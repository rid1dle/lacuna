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
use tracing::{info, warn};

use super::{rollup, Store, LOG_DROPPED, LOG_LATE, QUERIES_TOTAL};
use crate::codes::Source;
use crate::dns::pipeline::{LogSink, QueryRecord};
use crate::rules::RuleRef;

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
    /// The last write failed. Logged on the change only, not once a second.
    pub(super) failing: bool,
}

/// Lets `serve` wait for the writer thread to finish its last batch.
pub struct WriterHandle {
    // The thread holds the only sender and never sends: dropping it when the thread
    // ends (normally or by panic) is the signal.
    done: Receiver<()>,
}

impl WriterHandle {
    /// True once the thread has finished, false if `timeout` passed first.
    pub fn wait(&self, timeout: Duration) -> bool {
        !matches!(
            self.done.recv_timeout(timeout),
            Err(RecvTimeoutError::Timeout)
        )
    }
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
        failing: false,
    };
    (sender, writer)
}

/// Starts the writer thread. Once every `LogSender` is dropped, the thread writes every
/// record still in the channel and exits; the handle's `wait` sees that.
pub fn spawn(store: Store, capacity: usize) -> (LogSender, WriterHandle) {
    let (sender, writer) = channel(store, capacity);
    let (done_tx, done) = std::sync::mpsc::channel::<()>();
    std::thread::Builder::new()
        .name("log-writer".into())
        .spawn(move || {
            let _done = done_tx;
            writer.run();
        })
        .expect("spawning the log writer thread");
    (sender, WriterHandle { done })
}

impl Writer {
    fn run(mut self) {
        let mut next_rollup = Instant::now();
        let mut next_retain = Instant::now();
        loop {
            let open = self.collect(BATCH_WINDOW);
            // Errors are logged inside flush, on the change of state only.
            let _ = self.flush();
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
    /// to the drop count, so the loss still shows in `counters` once writes recover.
    pub(super) fn flush(&mut self) -> Result<()> {
        let dropped = self.dropped.swap(0, Ordering::Relaxed);
        if self.pending.is_empty() && dropped == 0 {
            return Ok(());
        }
        let n = self.pending.len() as u64;
        let result = write_batch(&mut self.store.conn, &self.pending, dropped);
        self.pending.clear();
        match &result {
            Ok(()) if self.failing => {
                info!("query log writes recovered");
                self.failing = false;
            }
            Ok(()) => {}
            Err(e) => {
                self.dropped.fetch_add(n + dropped, Ordering::Relaxed);
                if !self.failing {
                    warn!(
                        "query log writes failing, records are dropped until they recover: {e:#}"
                    );
                    self.failing = true;
                }
            }
        }
        result
    }
}

fn write_batch(conn: &mut Connection, records: &[QueryRecord], dropped: u64) -> Result<()> {
    let tx = conn.transaction()?;
    let late = insert_batch(&tx, records, Source::Lacuna)?;
    add_counter(&tx, LOG_DROPPED, dropped)?;
    add_counter(&tx, LOG_LATE, late)?;
    add_counter(&tx, QUERIES_TOTAL, records.len() as u64 + dropped)?;
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

/// Inserts raw rows, interning domain names (and rule texts, for a rule given as text)
/// and recording each client as seen. Rows behind the rollup marks are added to the
/// rollups here, so they count exactly once; returns how many there were. Counters are
/// the caller's business.
pub fn insert_batch(tx: &Transaction, records: &[QueryRecord], source: Source) -> Result<u64> {
    let before = insert_rows(tx, records, source)?;
    rollup::roll_late(tx, before)
}

/// What one imported batch did.
pub struct ImportedBatch {
    pub raw: u64,
    pub rolled_up_only: u64,
    /// From taking the write lock to committing: how long the live writer could wait.
    pub held: Duration,
}

/// Writes one batch of imported history in one transaction. Rows from `raw_from_ms` on
/// stay raw, and those behind the rollup marks are rolled up here as live late rows are,
/// but not added to `log_late`: they are history, not a writer falling behind. Older
/// rows only add to the rollups.
pub fn import_batch(
    store: &Store,
    records: &[QueryRecord],
    raw_from_ms: i64,
) -> Result<ImportedBatch> {
    // IMMEDIATE (the connection's default): waits, up to busy_timeout, while the live
    // writer holds the lock, instead of failing.
    let tx = store.conn.unchecked_transaction()?;
    let locked = Instant::now();
    let before = insert_rows(&tx, records, Source::Adguard)?;
    let rolled_up_only = rollup::roll_and_drop_old(&tx, before, raw_from_ms)?;
    rollup::roll_late(&tx, before)?;
    // Counted in the table, not derived from the batch length, so the import's
    // `lines == raw + rolled_up_only + skipped` check sees a row that went missing.
    let raw: i64 = tx.query_row(
        "SELECT count(*) FROM raw_queries WHERE rowid > ?1",
        [before],
        |r| r.get(0),
    )?;
    tx.commit()?;
    Ok(ImportedBatch {
        raw: u64::try_from(raw).unwrap_or(0),
        rolled_up_only,
        held: locked.elapsed(),
    })
}

/// Inserts the rows and returns the largest rowid before them.
fn insert_rows(tx: &Connection, records: &[QueryRecord], source: Source) -> Result<i64> {
    // New rows get rowids above the current maximum, which is how the late rollup
    // finds this batch's rows.
    let before: i64 = tx.query_row("SELECT coalesce(max(rowid), 0) FROM raw_queries", [], |r| {
        r.get(0)
    })?;
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
        // The pipeline builds both from one Option<(list, rule)>, so one without the
        // other cannot happen; such a record would be logged without its rule.
        debug_assert_eq!(
            r.list_id.is_some(),
            r.rule.is_some(),
            "list_id and rule differ"
        );
        let rule_id = match (r.list_id, &r.rule) {
            // Interned when the rule set was built; the row outlives that set.
            (Some(_), Some(RuleRef::Id(id))) => Some(i64::from(*id)),
            (Some(list), Some(RuleRef::Text(text))) => {
                let text: &str = text;
                Some(match rules.get(&(list, text)) {
                    Some(&id) => id,
                    None => {
                        put_rule.execute(params![list, text])?;
                        let id: i64 = get_rule.query_row(params![list, text], |row| row.get(0))?;
                        rules.insert((list, text), id);
                        id
                    }
                })
            }
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
    Ok(before)
}

pub fn now_ms() -> i64 {
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

    /// A list refresh holds the write lock for a moment. A DEFERRED transaction whose
    /// first statement is a read fails at once when it must upgrade ("database is
    /// locked", busy_timeout is not consulted); the log batch must wait instead.
    #[test]
    fn batch_waits_for_another_writer_instead_of_dropping() {
        let db = TempDb::new("busy");
        let (tx, mut w) = channel(Store::open(&db.0).unwrap(), 8);
        tx.send(record(1, "10.0.0.1", "a.example"));
        assert!(w.collect(Duration::ZERO));

        let (locked_tx, locked_rx) = std::sync::mpsc::channel();
        let path = db.0.clone();
        let other = std::thread::spawn(move || {
            let mut conn = rusqlite::Connection::open(path).unwrap();
            let t = conn
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                .unwrap();
            t.execute("INSERT INTO rule_texts (list_id, text) VALUES (1, 'x')", [])
                .unwrap();
            locked_tx.send(()).unwrap();
            std::thread::sleep(Duration::from_millis(300));
            t.commit().unwrap();
        });
        locked_rx.recv().unwrap();
        w.flush().unwrap();
        other.join().unwrap();
        assert_eq!(counter(&w.store, "log_dropped"), 0);
        assert_eq!(count(&w.store, "raw_queries"), 1);
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
                "SELECT client, device, origin, first_seen_ts, last_seen_ts FROM devices ORDER BY client",
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

    /// A batch that cannot be written is counted as dropped, so the loss shows up in
    /// `counters` once the disk recovers.
    #[test]
    fn failed_batch_counts_as_dropped() {
        let (tx, mut w) = channel(memory(), 16);
        for i in 0..3 {
            tx.send(record(i, "10.0.0.1", "a.example"));
        }
        assert!(w.collect(Duration::ZERO));
        w.store
            .conn
            .execute_batch("ALTER TABLE raw_queries RENAME TO raw_queries_away")
            .unwrap();
        assert!(w.flush().is_err());
        assert!(w.failing, "the failure is remembered, so it is logged once");
        w.store
            .conn
            .execute_batch("ALTER TABLE raw_queries_away RENAME TO raw_queries")
            .unwrap();
        w.flush().unwrap();
        assert!(!w.failing);
        assert_eq!(counter(&w.store, "log_dropped"), 3);
        assert_eq!(counter(&w.store, "queries_total"), 3);
        assert_eq!(count(&w.store, "raw_queries"), 0);
    }

    /// Dropping the last sender makes the thread write everything it holds and finish;
    /// `wait` sees that, so a shutdown loses nothing already sent.
    #[test]
    fn spawned_writer_drains_on_shutdown() {
        let db = TempDb::new("drain");
        let (tx, writer) = spawn(Store::open(&db.0).unwrap(), 4096);
        let now = now_ms();
        for i in 0..3000 {
            tx.send(record(now + i, "10.0.0.1", "a.example"));
        }
        drop(tx);
        assert!(writer.wait(Duration::from_secs(3)), "writer did not finish");
        let reader = Store::open(&db.0).unwrap();
        assert_eq!(count(&reader, "raw_queries"), 3000);
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
        let (tx, _writer) = spawn(Store::open(&db.0).unwrap(), 16);
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
