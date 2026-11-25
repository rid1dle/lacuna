//! The log writer. The DNS path hands records to a bounded channel and never waits;
//! one OS thread (rusqlite is blocking) writes them in batches and runs the rollups,
//! so this thread owns the only write connection.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, RecvTimeoutError, SyncSender, TryRecvError};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use rusqlite::{params, Connection, Transaction};
use tracing::warn;

use super::{rollup, Store};
use crate::codes::Source;
use crate::dns::pipeline::{LogSink, QueryRecord};

/// Records the channel holds before `send` starts dropping (about 2 MB at most).
pub const CHANNEL_CAPACITY: usize = 8192;
const BATCH_MAX: usize = 2_000;
const BATCH_WINDOW: Duration = Duration::from_secs(1);
const ROLLUP_EVERY: Duration = Duration::from_secs(5 * 60);
const RETAIN_EVERY: Duration = Duration::from_secs(60 * 60);

/// The pipeline's log sink.
pub struct LogSender {
    tx: SyncSender<QueryRecord>,
    dropped: Arc<AtomicU64>,
}

impl LogSink for LogSender {
    fn send(&self, r: QueryRecord) {
        // Full means the disk is behind; DNS must not wait for it. Disconnected means the
        // writer thread is gone. Either way the record is lost and counted.
        if self.tx.try_send(r).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// The receiving end, run on its own thread by `spawn`; tests drive it by hand.
pub struct Writer {
    pub(super) store: Store,
    rx: Receiver<QueryRecord>,
    dropped: Arc<AtomicU64>,
    pending: Vec<QueryRecord>,
}

pub fn channel(store: Store, capacity: usize) -> (LogSender, Writer) {
    let (tx, rx) = sync_channel(capacity);
    let dropped = Arc::new(AtomicU64::new(0));
    let sender = LogSender {
        tx,
        dropped: Arc::clone(&dropped),
    };
    let writer = Writer {
        store,
        rx,
        dropped,
        pending: Vec::with_capacity(BATCH_MAX),
    };
    (sender, writer)
}

/// Starts the writer thread. It exits once every `LogSender` is dropped, after writing
/// what it already received.
pub fn spawn(store: Store, capacity: usize) -> LogSender {
    let (sender, writer) = channel(store, capacity);
    std::thread::Builder::new()
        .name("log-writer".into())
        .spawn(move || writer.run())
        .expect("spawning the log writer thread");
    sender
}

impl Writer {
    fn run(mut self) {
        let mut next_rollup = Instant::now();
        let mut next_retain = Instant::now();
        loop {
            let open = self.collect(BATCH_WINDOW);
            if let Err(e) = self.flush() {
                warn!("query log batch lost: {e:#}");
            }
            if !open {
                return;
            }
            let now = Instant::now();
            if now >= next_rollup {
                if let Err(e) = rollup::roll_up(&self.store, now_ms()) {
                    warn!("rollup failed: {e:#}");
                }
                next_rollup = now + ROLLUP_EVERY;
            }
            if now >= next_retain {
                if let Err(e) = rollup::retain(&self.store, now_ms()) {
                    warn!("retention failed: {e:#}");
                }
                next_retain = now + RETAIN_EVERY;
            }
        }
    }

    /// Gathers records into `pending` until `BATCH_MAX` or until `window` has passed.
    /// Returns false once every sender is gone.
    pub(super) fn collect(&mut self, window: Duration) -> bool {
        let deadline = Instant::now() + window;
        while self.pending.len() < BATCH_MAX {
            match self.rx.try_recv() {
                Ok(r) => {
                    self.pending.push(r);
                    continue;
                }
                Err(TryRecvError::Disconnected) => return false,
                Err(TryRecvError::Empty) => {}
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            match self.rx.recv_timeout(left) {
                Ok(r) => self.pending.push(r),
                Err(RecvTimeoutError::Timeout) => break,
                Err(RecvTimeoutError::Disconnected) => return false,
            }
        }
        true
    }

    /// Writes `pending` and the drop count in one transaction. A failed batch is added
    /// to the drop count, so the loss still shows in `counters`.
    pub(super) fn flush(&mut self) -> Result<()> {
        let dropped = self.dropped.swap(0, Ordering::Relaxed);
        if self.pending.is_empty() && dropped == 0 {
            return Ok(());
        }
        let n = self.pending.len() as u64;
        let result = write_batch(&mut self.store.conn, &self.pending, dropped);
        self.pending.clear();
        if result.is_err() {
            self.dropped.fetch_add(n + dropped, Ordering::Relaxed);
        }
        result
    }
}

fn write_batch(conn: &mut Connection, records: &[QueryRecord], dropped: u64) -> Result<()> {
    let tx = conn.transaction()?;
    insert_batch(&tx, records, Source::Sieve)?;
    add_counter(&tx, "log_dropped", dropped)?;
    add_counter(&tx, "queries_total", records.len() as u64 + dropped)?;
    tx.commit()?;
    Ok(())
}

fn add_counter(tx: &Transaction, name: &str, by: u64) -> Result<()> {
    // SQLite integers are i64; a u64 count past i64::MAX is not a real case.
    let by = i64::try_from(by).unwrap_or(i64::MAX);
    tx.execute(
        "INSERT INTO counter_values (name, value) VALUES (?1, ?2)
         ON CONFLICT (name) DO UPDATE SET value = value + excluded.value",
        params![name, by],
    )?;
    Ok(())
}

/// Inserts raw rows, interning domain names and rule texts and recording each client
/// as seen. Counters are the caller's business.
pub fn insert_batch(tx: &Transaction, records: &[QueryRecord], source: Source) -> Result<()> {
    let mut put_domain = tx.prepare("INSERT OR IGNORE INTO domain_names (name) VALUES (?1)")?;
    let mut get_domain = tx.prepare("SELECT id FROM domain_names WHERE name = ?1")?;
    let mut put_rule =
        tx.prepare("INSERT OR IGNORE INTO rule_texts (list_id, text) VALUES (?1, ?2)")?;
    let mut get_rule = tx.prepare("SELECT id FROM rule_texts WHERE list_id = ?1 AND text = ?2")?;
    let mut put_row = tx.prepare(
        "INSERT INTO raw_queries (ts, client, domain_id, qtype, rcode, outcome, reason, \
         rule_id, served_from, upstream, latency_us, answers, source) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
    )?;
    let mut put_client = tx.prepare(
        "INSERT INTO client_names (ip, first_seen, last_seen) VALUES (?1, ?2, ?3)
         ON CONFLICT (ip) DO UPDATE SET first_seen = min(first_seen, excluded.first_seen),
                                        last_seen = max(last_seen, excluded.last_seen)",
    )?;

    // Ids looked up in this batch only. The maps die with the batch, so memory stays
    // bounded however many names the log has seen; the database is the real index.
    let mut domains: HashMap<&str, i64> = HashMap::new();
    let mut rules: HashMap<(u32, &str), i64> = HashMap::new();
    let mut clients: HashMap<IpAddr, (i64, i64)> = HashMap::new();
    for r in records {
        let domain_id = match domains.get(r.name.as_str()) {
            Some(&id) => id,
            None => {
                put_domain.execute([&r.name])?;
                let id: i64 = get_domain.query_row([&r.name], |row| row.get(0))?;
                domains.insert(&r.name, id);
                id
            }
        };
        let rule_id = match (r.list_id, r.rule.as_deref()) {
            (Some(list), Some(text)) => Some(match rules.get(&(list, text)) {
                Some(&id) => id,
                None => {
                    put_rule.execute(params![list, text])?;
                    let id: i64 = get_rule.query_row(params![list, text], |row| row.get(0))?;
                    rules.insert((list, text), id);
                    id
                }
            }),
            _ => None,
        };
        let answers = r
            .answers
            .iter()
            .map(IpAddr::to_string)
            .collect::<Vec<_>>()
            .join(",");
        put_row.execute(params![
            r.ts_ms,
            r.client.to_string(),
            domain_id,
            r.qtype,
            r.rcode,
            r.outcome.code(),
            r.reason.code(),
            rule_id,
            r.served_from.code(),
            r.upstream,
            r.latency_us,
            answers,
            source.code(),
        ])?;
        let seen = clients.entry(r.client).or_insert((r.ts_ms, r.ts_ms));
        seen.0 = seen.0.min(r.ts_ms);
        seen.1 = seen.1.max(r.ts_ms);
    }
    for (ip, (first, last)) in clients {
        put_client.execute(params![ip.to_string(), first, last])?;
    }
    Ok(())
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::time::{Duration, Instant};

    use super::*;
    use crate::dns::pipeline::LogSink;
    use crate::store::testing::{record, TempDb};
    use crate::store::Store;

    fn memory() -> Store {
        Store::open(Path::new(":memory:")).unwrap()
    }

    fn counter(store: &Store, name: &str) -> i64 {
        store
            .conn
            .query_row("SELECT value FROM counters WHERE name = ?1", [name], |r| {
                r.get(0)
            })
            .unwrap()
    }

    fn count(store: &Store, table: &str) -> i64 {
        store
            .conn
            .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
            .unwrap()
    }

    #[test]
    fn full_channel_counts_drops() {
        let (tx, mut w) = channel(memory(), 2);
        for i in 0..5 {
            tx.send(record(i, "10.0.0.1", "a.example"));
        }
        assert!(w.collect(Duration::ZERO));
        w.flush().unwrap();
        assert_eq!(counter(&w.store, "log_dropped"), 3);
        assert_eq!(counter(&w.store, "queries_total"), 5);
        assert_eq!(count(&w.store, "raw_queries"), 2);

        // The drop count is flushed once, not again on the next batch.
        tx.send(record(9, "10.0.0.1", "a.example"));
        assert!(w.collect(Duration::ZERO));
        w.flush().unwrap();
        assert_eq!(counter(&w.store, "log_dropped"), 3);
        assert_eq!(counter(&w.store, "queries_total"), 6);
    }

    #[test]
    fn domains_are_interned() {
        let (tx, mut w) = channel(memory(), 200);
        for batch in 0..2 {
            for i in 0..50 {
                tx.send(record(batch * 50 + i, "10.0.0.1", "same.example"));
            }
            assert!(w.collect(Duration::ZERO));
            w.flush().unwrap();
        }
        assert_eq!(count(&w.store, "domain_names"), 1);
        assert_eq!(count(&w.store, "raw_queries"), 100);
    }

    #[test]
    fn rules_are_interned_per_list() {
        let (tx, mut w) = channel(memory(), 16);
        for (list, rule) in [(1, "||a.com^"), (1, "||a.com^"), (2, "||a.com^")] {
            let mut r = record(0, "10.0.0.1", "a.com");
            r.list_id = Some(list);
            r.rule = Some(rule.into());
            tx.send(r);
        }
        assert!(w.collect(Duration::ZERO));
        w.flush().unwrap();
        assert_eq!(count(&w.store, "rule_texts"), 2);
        let distinct: i64 = w
            .store
            .conn
            .query_row("SELECT count(DISTINCT rule_id) FROM raw_queries", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(distinct, 2);
    }

    #[test]
    fn clients_are_upserted_with_first_and_last_seen() {
        let (tx, mut w) = channel(memory(), 16);
        tx.send(record(200, "10.0.0.1", "a.example"));
        tx.send(record(100, "10.0.0.1", "a.example"));
        tx.send(record(150, "10.0.0.2", "a.example"));
        assert!(w.collect(Duration::ZERO));
        w.flush().unwrap();
        tx.send(record(500, "10.0.0.1", "a.example"));
        assert!(w.collect(Duration::ZERO));
        w.flush().unwrap();

        let mut stmt = w
            .store
            .conn
            .prepare(
                "SELECT client, device, origin, first_seen, last_seen FROM devices ORDER BY client",
            )
            .unwrap();
        let rows: Vec<(String, String, Option<String>, i64, i64)> = stmt
            .query_map([], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
            })
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(
            rows,
            vec![
                ("10.0.0.1".into(), "10.0.0.1".into(), None, 100, 500),
                ("10.0.0.2".into(), "10.0.0.2".into(), None, 150, 150),
            ]
        );
    }

    #[test]
    fn disconnected_channel_ends_collect() {
        let (tx, mut w) = channel(memory(), 4);
        tx.send(record(1, "10.0.0.1", "a.example"));
        drop(tx);
        assert!(!w.collect(Duration::from_secs(5)));
        assert_eq!(w.pending.len(), 1, "records sent before the drop are kept");
    }

    /// The real thread: a record sent through `spawn` reaches the file within the
    /// 1s batch window, seen from a second connection. The record is current: the
    /// thread runs retention at start, which would rightly delete an old one.
    #[test]
    fn spawned_writer_persists_records() {
        let db = TempDb::new("writer");
        let tx = spawn(Store::open(&db.0).unwrap(), 16);
        tx.send(record(now_ms(), "10.0.0.1", "a.example"));
        let reader = Store::open(&db.0).unwrap();
        let started = Instant::now();
        while count(&reader, "raw_queries") == 0 {
            assert!(
                started.elapsed() < Duration::from_secs(5),
                "record never written"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}
