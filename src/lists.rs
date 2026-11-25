//! Filter lists: fetch by URL, keep the last good copy on disk, rebuild the live rule set.
//!
//! Bodies live in `lists_dir/<id>.txt` and are the only copy between refreshes: a refresh
//! writes a new body there only when it parses to at least one rule, and every rebuild
//! reads the files back, so a failed fetch or a 200 "<html>502</html>" never costs the
//! rules already in force.
//!
//! Database writes use a short-lived second connection rather than the writer thread's.
//! SQLite's WAL allows one writer at a time. Every write transaction on both connections
//! begins IMMEDIATE, so a contender waits up to busy_timeout (5s) instead of failing at
//! once, and each transaction here is at most `RULE_CHUNK` rows, so the query-log writer
//! waits only milliseconds.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::future::Future;
use std::io::Write as _;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, RecordType};
use rusqlite::{Connection, TransactionBehavior};
use tracing::{info, warn};

use crate::config::ListConfig;
use crate::dns::pipeline::Shared;
use crate::dns::upstream::{client_builder, Upstream, Upstreams};
use crate::rules::{parse_line, ListStats, Parsed, RuleSet};

const FETCH_TIMEOUT: Duration = Duration::from_secs(30);
/// A list bigger than this is refused: the largest real list is a few MB.
const MAX_BODY_BYTES: usize = 20 * 1024 * 1024;
/// Rule texts per transaction while saving a changed list.
const RULE_CHUNK: usize = 5_000;
/// First refresh after startup, then once a day.
pub const FIRST_REFRESH: Duration = Duration::from_secs(5);
pub const REFRESH_EVERY: Duration = Duration::from_secs(24 * 60 * 60);
/// After a refresh where something failed, try again sooner than a day.
pub const RETRY_AFTER: Duration = Duration::from_secs(60 * 60);

/// Gets one list body. A trait so the refresh logic is tested without a network.
pub trait Fetch: Send + Sync {
    fn fetch(&self, url: &str) -> impl Future<Output = Result<String, String>> + Send;
}

/// Fetches over HTTP(S). The list host has no fixed address and the machine's resolver
/// is sieve itself, so the host is resolved through sieve's own upstreams and pinned
/// into the client.
pub struct HttpFetcher<U: Upstream> {
    ups: Arc<Upstreams<U>>,
    max_bytes: usize,
}

impl<U: Upstream + 'static> HttpFetcher<U> {
    pub fn new(ups: Arc<Upstreams<U>>) -> Self {
        HttpFetcher {
            ups,
            max_bytes: MAX_BODY_BYTES,
        }
    }
}

impl<U: Upstream + 'static> Fetch for HttpFetcher<U> {
    async fn fetch(&self, url: &str) -> Result<String, String> {
        let parsed = reqwest::Url::parse(url).map_err(|e| format!("bad url: {e}"))?;
        let host = parsed.host_str().ok_or("url has no host")?;
        let mut builder = client_builder()
            .no_proxy()
            // Following a redirect would need resolving another host.
            .redirect(reqwest::redirect::Policy::none())
            .timeout(FETCH_TIMEOUT);
        // An IP literal needs no lookup (and lets tests use a loopback server). The port
        // in the override is ignored by reqwest; the URL's port is used.
        if host.trim_matches(['[', ']']).parse::<IpAddr>().is_err() {
            let ip = resolve_host(&self.ups, host).await?;
            builder = builder.resolve(host, SocketAddr::new(ip, 0));
        }
        let client = builder.build().map_err(|e| format!("http client: {e}"))?;

        let mut resp = client
            .get(parsed.clone())
            .send()
            .await
            .map_err(|e| format!("request failed: {}", error_chain(&e)))?;
        let status = resp.status();
        if status.is_redirection() {
            let to = resp
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("(no Location)");
            return Err(format!(
                "HTTP {} redirect to {to}, not followed",
                status.as_u16()
            ));
        }
        if !status.is_success() {
            return Err(format!("HTTP {}", status.as_u16()));
        }
        let cap = resp
            .content_length()
            .map_or(0, |n| n.min(self.max_bytes as u64) as usize);
        let mut body = Vec::with_capacity(cap);
        while let Some(chunk) = resp
            .chunk()
            .await
            .map_err(|e| format!("reading body: {}", error_chain(&e)))?
        {
            if body.len() + chunk.len() > self.max_bytes {
                return Err(format!("body larger than {} bytes", self.max_bytes));
            }
            body.extend_from_slice(&chunk);
        }
        String::from_utf8(body).map_err(|_| "body is not UTF-8".to_string())
    }
}

/// reqwest's top-level message is often just "error sending request"; the cause is below.
fn error_chain(e: &dyn std::error::Error) -> String {
    let mut text = e.to_string();
    let mut source = e.source();
    while let Some(s) = source {
        let _ = write!(text, ": {s}");
        source = s.source();
    }
    text
}

/// An A lookup through sieve's own upstreams (DoH race, then fallback).
async fn resolve_host<U: Upstream + 'static>(
    ups: &Upstreams<U>,
    host: &str,
) -> Result<IpAddr, String> {
    let name = Name::from_ascii(format!("{host}.")).map_err(|e| format!("{host}: {e}"))?;
    let mut q = Message::new(0, MessageType::Query, OpCode::Query);
    q.metadata.recursion_desired = true;
    q.add_query(Query::query(name, RecordType::A));
    let (answer, _, _) = ups
        .resolve(&q)
        .await
        .map_err(|e| format!("resolving {host}: {e}"))?;
    first_v4(&answer, host)
}

fn first_v4(answer: &Message, host: &str) -> Result<IpAddr, String> {
    if answer.metadata.response_code == ResponseCode::NXDomain {
        return Err(format!("{host}: NXDOMAIN"));
    }
    answer
        .answers
        .iter()
        .find_map(|r| match r.data {
            RData::A(A(v4)) => Some(IpAddr::V4(v4)),
            _ => None,
        })
        .ok_or_else(|| format!("{host}: no A record"))
}

#[derive(Debug)]
pub struct RefreshReport {
    /// One entry per enabled list, in config order: its stats after the rebuild, or why
    /// its fetch failed (the last good body stays in force).
    pub per_list: Vec<(u32, Result<ListStats, String>)>,
    /// False when nothing could be fetched, so the running set was left alone.
    pub swapped: bool,
}

impl RefreshReport {
    /// One line for the log.
    pub fn summary(&self) -> String {
        let parts: Vec<String> = self
            .per_list
            .iter()
            .map(|(id, r)| match r {
                Ok(s) => format!(
                    "list {id}: parsed {} skipped {}",
                    s.parsed,
                    s.skipped.values().sum::<usize>()
                ),
                Err(e) => format!("list {id}: error {e}"),
            })
            .collect();
        format!(
            "lists refreshed (swapped: {}): {}",
            self.swapped,
            parts.join("; ")
        )
    }
}

/// How long to wait before the next refresh: an hour when any list failed (the lists
/// are daily files, but a transient outage should not cost a day), else a day. A refresh
/// with no error and `swapped == false` found nothing new, which is also a success.
pub fn next_refresh_in(report: &RefreshReport) -> Duration {
    if report.per_list.iter().any(|(_, r)| r.is_err()) {
        RETRY_AFTER
    } else {
        REFRESH_EVERY
    }
}

/// What the manager builds from; replaced as a whole by `set_config`.
struct Conf {
    lists: Vec<ListConfig>,
    user_rules: Vec<String>,
}

pub struct Lists<F: Fetch> {
    conf: RwLock<Arc<Conf>>,
    dir: PathBuf,
    db: PathBuf,
    rules: Shared<RuleSet>,
    fetcher: F,
    /// One refresh at a time (the daily loop and a manual refresh may overlap), and no
    /// config change or rebuild from disk during one.
    refresh_lock: tokio::sync::Mutex<()>,
    /// Stats of the build behind the live set; None until one succeeds, which makes the
    /// next refresh rebuild.
    built: Mutex<Option<Vec<ListStats>>>,
}

impl<F: Fetch> Lists<F> {
    pub fn new(
        lists: Vec<ListConfig>,
        user_rules: Vec<String>,
        dir: PathBuf,
        db: PathBuf,
        rules: Shared<RuleSet>,
        fetcher: F,
    ) -> Self {
        Lists {
            conf: RwLock::new(Arc::new(Conf { lists, user_rules })),
            dir,
            db,
            rules,
            fetcher,
            refresh_lock: tokio::sync::Mutex::new(()),
            built: Mutex::new(None),
        }
    }

    /// Replaces the list configs and user rules (a config reload) and applies them at
    /// once: `list_meta` rows, then a rebuild from the bodies on disk. Waits for a
    /// refresh in flight, which would otherwise finish with the old config after this
    /// returns: saving a body fetched from a URL the reload moved away from, and swapping
    /// in a set built from the old user rules.
    pub async fn set_config(&self, lists: Vec<ListConfig>, user_rules: Vec<String>) -> Result<()> {
        let _one_at_a_time = self.refresh_lock.lock().await;
        *self.conf.write().unwrap_or_else(PoisonError::into_inner) =
            Arc::new(Conf { lists, user_rules });
        // A failed rebuild leaves this None, so the next refresh rebuilds.
        *self.built.lock().unwrap_or_else(PoisonError::into_inner) = None;
        self.sync_meta().await;
        let (set, stats) = self.rebuild().await?;
        self.swap(set, stats);
        Ok(())
    }

    /// The configured name of list `id`; list 0 is the user rules.
    pub fn list_name(&self, id: u32) -> Option<String> {
        if id == 0 {
            return Some("user rules".to_string());
        }
        let conf = self.conf();
        conf.lists
            .iter()
            .find(|l| l.id == id)
            .map(|l| l.name.clone())
    }

    fn conf(&self) -> Arc<Conf> {
        Arc::clone(&self.conf.read().unwrap_or_else(PoisonError::into_inner))
    }

    /// Makes `list_meta` hold a row for every configured list, so the views never show a
    /// NULL list name; existing rows keep their fetch history. Lists no longer configured
    /// are marked disabled (the row stays, for labels in old log rows). A list whose URL
    /// changed loses its last-good file: that body came from somewhere else.
    pub async fn sync_meta(&self) {
        let conf = self.conf();
        let rows: Vec<(u32, String, String, bool)> = conf
            .lists
            .iter()
            .map(|l| (l.id, l.name.clone(), l.url.clone(), l.enabled))
            .collect();
        let dir = self.dir.clone();
        self.db_run("list_meta upsert", move |conn| {
            let tx = conn.transaction()?;
            let known: Vec<(u32, Option<String>)> = tx
                .prepare("SELECT id, url FROM list_meta")?
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect::<rusqlite::Result<_>>()?;
            for (id, old_url) in &known {
                match rows.iter().find(|r| r.0 == *id) {
                    None => {
                        tx.execute("UPDATE list_meta SET enabled = 0 WHERE id = ?1", [id])?;
                    }
                    Some((_, _, url, _)) if old_url.as_deref().is_some_and(|u| u != url) => {
                        let _ = std::fs::remove_file(dir.join(format!("{id}.txt")));
                    }
                    Some(_) => {}
                }
            }
            for (id, name, url, enabled) in rows {
                tx.execute(
                    "INSERT INTO list_meta (id, name, url, enabled) VALUES (?1, ?2, ?3, ?4)
                     ON CONFLICT (id) DO UPDATE SET
                         name = excluded.name, url = excluded.url, enabled = excluded.enabled",
                    (id, name, url, enabled),
                )?;
            }
            tx.commit()
        })
        .await;
    }

    /// Builds the rule set from the bodies on disk. No network.
    pub async fn load_last_good(&self) -> Result<()> {
        let _one_at_a_time = self.refresh_lock.lock().await;
        let (set, stats) = self.rebuild().await?;
        info!(
            rules = set.rule_count(),
            lists = stats.len() - 1,
            "last good lists loaded"
        );
        self.swap(set, stats);
        Ok(())
    }

    /// Fetches every enabled list, saves the bodies that are good, rebuilds from disk and
    /// swaps the set in. Failures are per list and recorded in `list_meta.last_error`.
    /// When no body changed since the live build, the rebuild is skipped.
    pub async fn refresh(&self) -> RefreshReport {
        let _one_at_a_time = self.refresh_lock.lock().await;
        // The status updates below need their rows; this is a few tiny upserts.
        self.sync_meta().await;
        let conf = self.conf();

        let mut outcomes: Vec<(u32, Result<bool, String>)> = Vec::new();
        for list in conf.lists.iter().filter(|l| l.enabled) {
            let outcome = self.fetch_one(list).await;
            let (id, now) = (list.id, now_ms());
            let error = outcome.as_ref().err().cloned();
            self.db_run("list fetch status", move |conn| match error {
                None => conn.execute(
                    "UPDATE list_meta SET fetched_at = ?2, last_error = NULL WHERE id = ?1",
                    (id, now),
                ),
                Some(e) => conn.execute(
                    "UPDATE list_meta SET last_error = ?2 WHERE id = ?1",
                    (id, e),
                ),
            })
            .await;
            outcomes.push((id, outcome));
        }

        let all_failed = !outcomes.is_empty() && outcomes.iter().all(|(_, o)| o.is_err());
        let any_changed = outcomes.iter().any(|(_, o)| matches!(o, Ok(true)));
        let current = self
            .built
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        if all_failed || (!any_changed && current.is_some()) {
            // Nothing new to build from: the running set stays.
            let stats = current.unwrap_or_default();
            return RefreshReport {
                per_list: outcomes
                    .into_iter()
                    .map(|(id, o)| match o {
                        Err(e) => (id, Err(e)),
                        Ok(_) => match stats.iter().find(|s| s.list_id == id) {
                            Some(s) => (id, Ok(s.clone())),
                            None => (id, Err("not in the running set".to_string())),
                        },
                    })
                    .collect(),
                swapped: false,
            };
        }

        match self.rebuild().await {
            Ok((set, stats)) => {
                self.store_stats(&stats).await;
                let per_list = outcomes
                    .into_iter()
                    .map(|(id, o)| match o {
                        Err(e) => (id, Err(e)),
                        Ok(_) => match stats.iter().find(|s| s.list_id == id) {
                            Some(s) => (id, Ok(s.clone())),
                            None => (id, Err("missing from the rebuilt set".to_string())),
                        },
                    })
                    .collect();
                self.swap(set, stats);
                RefreshReport {
                    per_list,
                    swapped: true,
                }
            }
            Err(e) => {
                warn!("rule set rebuild failed, keeping the running set: {e:#}");
                let reason = format!("rebuild failed: {e:#}");
                // The fetch recorded success; the list is not in force, so say so.
                let failed: Vec<u32> = outcomes
                    .iter()
                    .filter(|(_, o)| o.is_ok())
                    .map(|(id, _)| *id)
                    .collect();
                let text = reason.clone();
                self.db_run("list rebuild status", move |conn| {
                    let tx = conn.transaction()?;
                    for id in failed {
                        tx.execute(
                            "UPDATE list_meta SET last_error = ?2 WHERE id = ?1",
                            (id, &text),
                        )?;
                    }
                    tx.commit()
                })
                .await;
                RefreshReport {
                    per_list: outcomes
                        .into_iter()
                        .map(|(id, o)| (id, Err(o.err().unwrap_or_else(|| reason.clone()))))
                        .collect(),
                    swapped: false,
                }
            }
        }
    }

    /// Fetches one list and saves it as the new last good body if it has any rules.
    /// Ok(true) when the saved body changed.
    async fn fetch_one(&self, list: &ListConfig) -> Result<bool, String> {
        let body = self.fetcher.fetch(&list.url).await?;
        let (dir, db, id) = (self.dir.clone(), self.db.clone(), list.id);
        // Parsing and file and database work are blocking; `body` is dropped inside.
        tokio::task::spawn_blocking(move || persist(&dir, &db, id, &body))
            .await
            .map_err(|e| format!("saving the list panicked: {e}"))?
    }

    /// User rules plus the last good body of every enabled list, bodies read from disk
    /// and dropped as soon as the set is built. A file with no rules in it (damaged, or
    /// an error page saved by an older build) is ignored with a warning.
    async fn rebuild(&self) -> Result<(RuleSet, Vec<ListStats>)> {
        let conf = self.conf();
        let dir = self.dir.clone();
        tokio::task::spawn_blocking(move || {
            let bodies: Vec<(u32, String)> = conf
                .lists
                .iter()
                .filter(|l| l.enabled)
                .filter_map(
                    |l| match std::fs::read_to_string(dir.join(format!("{}.txt", l.id))) {
                        Ok(body) if has_rules(&body) => Some((l.id, body)),
                        Ok(_) => {
                            warn!(list = l.id, "last good file has no rules, ignoring it");
                            None
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
                        Err(e) => {
                            warn!(list = l.id, "reading last good body: {e}");
                            None
                        }
                    },
                )
                .collect();
            let refs: Vec<(u32, &str)> = bodies.iter().map(|(id, b)| (*id, b.as_str())).collect();
            RuleSet::build(&conf.user_rules, &refs)
        })
        .await
        .context("rebuilding the rule set")
    }

    fn swap(&self, set: RuleSet, stats: Vec<ListStats>) {
        // Take the old set out under the lock but free it after: dropping a big set
        // would otherwise hold up every query waiting to read the lock.
        let old = {
            let mut guard = self.rules.write().unwrap_or_else(PoisonError::into_inner);
            std::mem::replace(&mut *guard, Arc::new(set))
        };
        *self.built.lock().unwrap_or_else(PoisonError::into_inner) = Some(stats);
        // Freed on a blocking thread so the async worker does not stall on it.
        drop(tokio::task::spawn_blocking(move || drop(old)));
    }

    async fn store_stats(&self, stats: &[ListStats]) {
        let rows: Vec<(u32, i64, String)> = stats
            .iter()
            .filter(|s| s.list_id != 0)
            .map(|s| (s.list_id, s.parsed as i64, skipped_json(&s.skipped)))
            .collect();
        self.db_run("list stats", move |conn| {
            let tx = conn.transaction()?;
            for (id, parsed, skipped) in rows {
                tx.execute(
                    "UPDATE list_meta SET parsed = ?2, skipped_json = ?3 WHERE id = ?1",
                    (id, parsed, skipped),
                )?;
            }
            tx.commit()
        })
        .await;
    }

    /// Runs `f` on a fresh connection off the async threads. The log is never a reason to
    /// fail a refresh, so an error is only a warning.
    async fn db_run<T: Send + 'static>(
        &self,
        what: &'static str,
        f: impl FnOnce(&mut Connection) -> rusqlite::Result<T> + Send + 'static,
    ) -> Option<T> {
        let path = self.db.clone();
        let result = tokio::task::spawn_blocking(move || {
            let mut conn = connect(&path)?;
            f(&mut conn)
        })
        .await;
        match result {
            Ok(Ok(v)) => Some(v),
            Ok(Err(e)) => {
                warn!("{what}: {e}");
                None
            }
            Err(e) => {
                warn!("{what}: {e}");
                None
            }
        }
    }
}

fn has_rules(body: &str) -> bool {
    body.lines()
        .any(|l| matches!(parse_line(l), Parsed::Rule(_)))
}

/// Saves `body` as list `id`'s last good copy. Err when it has no rules (an error page,
/// an empty file) or its rule texts cannot be saved (the file is then left alone, so the
/// next refresh tries again). Ok(true) when the saved body changed; rule_texts are
/// inserted only then.
fn persist(dir: &Path, db: &Path, id: u32, body: &str) -> Result<bool, String> {
    if !has_rules(body) {
        return Err(format!(
            "fetched body has no rules ({} bytes), keeping the previous list",
            body.len()
        ));
    }
    let path = dir.join(format!("{id}.txt"));
    let unchanged = std::fs::metadata(&path).is_ok_and(|m| m.len() == body.len() as u64)
        && std::fs::read(&path).is_ok_and(|old| old == body.as_bytes());
    if unchanged {
        return Ok(false);
    }
    connect(db)
        .and_then(|mut conn| insert_rule_texts(&mut conn, id, body))
        .map_err(|e| format!("saving rule texts: {e}"))?;
    std::fs::create_dir_all(dir).map_err(|e| format!("creating {}: {e}", dir.display()))?;
    // Write beside, flush to disk, then rename: a crash never leaves half a list.
    let tmp = dir.join(format!("{id}.txt.tmp"));
    std::fs::File::create(&tmp)
        .and_then(|mut f| f.write_all(body.as_bytes()).and_then(|()| f.sync_all()))
        .and_then(|()| std::fs::rename(&tmp, &path))
        .map_err(|e| format!("writing {}: {e}", path.display()))?;
    Ok(true)
}

fn connect(path: &Path) -> rusqlite::Result<Connection> {
    let mut conn = Connection::open(path)?;
    conn.busy_timeout(Duration::from_secs(5))?;
    // See Store::open: IMMEDIATE waits for the lock, a DEFERRED upgrade fails at once.
    conn.set_transaction_behavior(TransactionBehavior::Immediate);
    Ok(conn)
}

/// INSERT OR IGNORE of every rule's text, `RULE_CHUNK` per transaction.
fn insert_rule_texts(conn: &mut Connection, list_id: u32, body: &str) -> rusqlite::Result<()> {
    let mut chunk: Vec<String> = Vec::with_capacity(RULE_CHUNK);
    for line in body.lines() {
        if let Parsed::Rule(rule) = parse_line(line) {
            chunk.push(rule.text);
            if chunk.len() == RULE_CHUNK {
                insert_chunk(conn, list_id, &mut chunk)?;
            }
        }
    }
    insert_chunk(conn, list_id, &mut chunk)
}

fn insert_chunk(
    conn: &mut Connection,
    list_id: u32,
    chunk: &mut Vec<String>,
) -> rusqlite::Result<()> {
    let tx = conn.transaction()?;
    {
        let mut stmt =
            tx.prepare("INSERT OR IGNORE INTO rule_texts (list_id, text) VALUES (?1, ?2)")?;
        for text in chunk.drain(..) {
            stmt.execute((list_id, text))?;
        }
    }
    tx.commit()
}

/// `{"regex":3}`. Keys are `SkipReason` labels from a fixed vocabulary, escaped anyway.
fn skipped_json(skipped: &BTreeMap<String, usize>) -> String {
    let fields: Vec<String> = skipped
        .iter()
        .map(|(k, n)| format!("\"{}\":{n}", k.replace('\\', "\\\\").replace('"', "\\\"")))
        .collect();
    format!("{{{}}}", fields.join(","))
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as i64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::pipeline::shared;
    use crate::dns::pipeline::testing::{upstreams, State};
    use crate::rules::Verdict;
    use crate::store::testing::TempDb;
    use crate::store::Store;
    use rusqlite::OptionalExtension;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Mutex;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// A fetcher serving canned bodies by URL, changeable between refreshes.
    #[derive(Clone, Default)]
    struct FakeFetch {
        bodies: Arc<Mutex<HashMap<String, Result<String, String>>>>,
        /// Once set, every fetch signals `entered` and waits for a `release` permit.
        gate: Arc<Mutex<Option<Gate>>>,
    }

    #[derive(Clone)]
    struct Gate {
        entered: Arc<tokio::sync::Notify>,
        release: Arc<tokio::sync::Semaphore>,
    }

    impl FakeFetch {
        fn set(&self, url: &str, body: Result<&str, &str>) {
            let body = body.map(String::from).map_err(String::from);
            self.bodies.lock().unwrap().insert(url.to_string(), body);
        }

        fn gate(&self) -> Gate {
            let gate = Gate {
                entered: Arc::new(tokio::sync::Notify::new()),
                release: Arc::new(tokio::sync::Semaphore::new(0)),
            };
            *self.gate.lock().unwrap() = Some(gate.clone());
            gate
        }
    }

    impl Fetch for FakeFetch {
        async fn fetch(&self, url: &str) -> Result<String, String> {
            let gate = self.gate.lock().unwrap().clone();
            if let Some(g) = gate {
                // notify_one stores the signal if nobody is waiting yet.
                g.entered.notify_one();
                g.release.acquire().await.unwrap().forget();
            }
            let found = self.bodies.lock().unwrap().get(url).cloned();
            found.unwrap_or_else(|| Err("not served".into()))
        }
    }

    const URL1: &str = "https://lists.test/1.txt";
    const URL2: &str = "https://lists.test/2.txt";

    fn cfg(id: u32, name: &str, url: &str, enabled: bool) -> ListConfig {
        ListConfig {
            id,
            name: name.into(),
            url: url.into(),
            enabled,
        }
    }

    struct Rig {
        lists: Lists<FakeFetch>,
        fetch: FakeFetch,
        rules: Shared<RuleSet>,
        db: TempDb,
        dir: PathBuf,
    }

    fn rig(tag: &str) -> Rig {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let db = TempDb::new(tag);
        Store::open(&db.0).unwrap();
        let dir = std::env::temp_dir().join(format!(
            "sieve-lists-{tag}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let fetch = FakeFetch::default();
        let rules = shared(RuleSet::default());
        let lists = Lists::new(
            vec![cfg(1, "First", URL1, true), cfg(2, "Second", URL2, false)],
            vec!["||user-blocked.test^".to_string()],
            dir.clone(),
            db.0.clone(),
            Arc::clone(&rules),
            fetch.clone(),
        );
        Rig {
            lists,
            fetch,
            rules,
            db,
            dir,
        }
    }

    impl Drop for Rig {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    impl Rig {
        fn blocks(&self, name: &str) -> bool {
            let set = Arc::clone(&self.rules.read().unwrap());
            matches!(set.check(name), Verdict::Block { .. })
        }

        fn sql<T: rusqlite::types::FromSql>(&self, sql: &str) -> Option<T> {
            let conn = rusqlite::Connection::open(&self.db.0).unwrap();
            conn.query_row(sql, [], |r| r.get::<_, Option<T>>(0))
                .optional()
                .unwrap()
                .flatten()
        }
    }

    #[tokio::test]
    async fn refresh_swaps_and_saves_last_good() {
        let r = rig("swap");
        r.fetch
            .set(URL1, Ok("||adnet.com^\n||ads.net^\n! comment\n/re/\n"));
        assert!(!r.blocks("adnet.com"));

        let report = r.lists.refresh().await;
        assert!(report.swapped);
        assert_eq!(report.per_list.len(), 1, "the disabled list is not fetched");
        let (id, stats) = &report.per_list[0];
        assert_eq!(*id, 1);
        let stats = stats.as_ref().unwrap();
        assert_eq!((stats.parsed, stats.skipped["regex"]), (2, 1));

        assert!(r.blocks("adnet.com") && r.blocks("x.ads.net"));
        assert_eq!(
            std::fs::read_to_string(r.dir.join("1.txt")).unwrap(),
            "||adnet.com^\n||ads.net^\n! comment\n/re/\n"
        );
        assert_eq!(
            r.sql::<i64>("SELECT parsed FROM list_meta WHERE id = 1"),
            Some(2)
        );
        assert_eq!(
            r.sql::<String>("SELECT skipped_json FROM list_meta WHERE id = 1"),
            Some(r#"{"regex":1}"#.to_string())
        );
        assert!(r.sql::<i64>("SELECT fetched_at FROM list_meta WHERE id = 1") > Some(0));
        assert_eq!(
            r.sql::<String>("SELECT last_error FROM list_meta WHERE id = 1"),
            None
        );
        assert_eq!(
            r.sql::<i64>("SELECT count(*) FROM rule_texts WHERE list_id = 1"),
            Some(2)
        );

        // Same body again: nothing is written and nothing is rebuilt. Deleting a row first
        // proves the insert is skipped, not merely ignored as a duplicate.
        rusqlite::Connection::open(&r.db.0)
            .unwrap()
            .execute("DELETE FROM rule_texts WHERE text = '||ads.net^'", [])
            .unwrap();
        let again = r.lists.refresh().await;
        assert!(!again.swapped);
        let stats = again.per_list[0].1.as_ref().unwrap();
        assert_eq!(stats.parsed, 2);
        assert_eq!(
            r.sql::<i64>("SELECT count(*) FROM rule_texts WHERE list_id = 1"),
            Some(1)
        );
        assert!(r.blocks("adnet.com"));
    }

    #[tokio::test]
    async fn load_last_good_works_offline() {
        let r = rig("offline");
        std::fs::create_dir_all(&r.dir).unwrap();
        std::fs::write(r.dir.join("1.txt"), "||adnet.com^\n").unwrap();
        // The disabled list's file is ignored.
        std::fs::write(r.dir.join("2.txt"), "||disabled.com^\n").unwrap();

        r.lists.load_last_good().await.unwrap();
        assert!(r.blocks("adnet.com"));
        assert!(r.blocks("user-blocked.test"), "user rules are in the set");
        assert!(!r.blocks("disabled.com"));
    }

    #[tokio::test]
    async fn refresh_keeps_last_good_when_new_set_is_empty() {
        let r = rig("empty");
        r.fetch.set(URL1, Ok("||adnet.com^\n"));
        r.lists.refresh().await;
        let fetched_at = r.sql::<i64>("SELECT fetched_at FROM list_meta WHERE id = 1");

        r.fetch.set(URL1, Ok("<html>502</html>"));
        let report = r.lists.refresh().await;
        assert!(!report.swapped);
        assert!(report.per_list[0].1.is_err());
        assert!(r.blocks("adnet.com"), "the old rules stay");
        assert_eq!(
            std::fs::read_to_string(r.dir.join("1.txt")).unwrap(),
            "||adnet.com^\n"
        );
        let error = r.sql::<String>("SELECT last_error FROM list_meta WHERE id = 1");
        assert!(error.unwrap().contains("no rules"));
        assert_eq!(
            r.sql::<i64>("SELECT fetched_at FROM list_meta WHERE id = 1"),
            fetched_at
        );
    }

    #[tokio::test]
    async fn failed_fetch_records_last_error() {
        let r = rig("failed");
        r.fetch.set(URL1, Err("connection refused"));
        let report = r.lists.refresh().await;
        assert!(!report.swapped);
        assert_eq!(report.per_list[0].1, Err("connection refused".to_string()));
        assert_eq!(
            r.sql::<String>("SELECT last_error FROM list_meta WHERE id = 1"),
            Some("connection refused".to_string())
        );
        assert_eq!(
            r.sql::<i64>("SELECT fetched_at FROM list_meta WHERE id = 1"),
            None
        );
    }

    #[tokio::test]
    async fn one_failed_list_does_not_block_the_others() {
        let db = TempDb::new("two");
        Store::open(&db.0).unwrap();
        let dir = std::env::temp_dir().join(format!("sieve-lists-two-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let fetch = FakeFetch::default();
        fetch.set(URL1, Ok("||one.test^\n"));
        fetch.set(URL2, Err("HTTP 404"));
        let rules = shared(RuleSet::default());
        let lists = Lists::new(
            vec![cfg(1, "A", URL1, true), cfg(2, "B", URL2, true)],
            vec![],
            dir.clone(),
            db.0.clone(),
            Arc::clone(&rules),
            fetch,
        );
        let report = lists.refresh().await;
        assert!(report.swapped);
        assert!(report.per_list[0].1.is_ok() && report.per_list[1].1.is_err());
        let set = Arc::clone(&rules.read().unwrap());
        assert!(matches!(set.check("one.test"), Verdict::Block { .. }));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn an_empty_body_for_one_list_keeps_its_old_body_while_another_updates() {
        let db = TempDb::new("mixed");
        Store::open(&db.0).unwrap();
        let dir = std::env::temp_dir().join(format!("sieve-lists-mixed-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let fetch = FakeFetch::default();
        let rules = shared(RuleSet::default());
        let lists = Lists::new(
            vec![cfg(1, "A", URL1, true), cfg(2, "B", URL2, true)],
            vec![],
            dir.clone(),
            db.0.clone(),
            Arc::clone(&rules),
            fetch.clone(),
        );
        fetch.set(URL1, Ok("||old-one.test^\n"));
        fetch.set(URL2, Ok("||old-two.test^\n"));
        lists.refresh().await;

        fetch.set(URL1, Ok("<html>502</html>"));
        fetch.set(URL2, Ok("||new-two.test^\n"));
        let report = lists.refresh().await;
        assert!(report.swapped);
        assert!(report.per_list[0].1.is_err() && report.per_list[1].1.is_ok());
        let set = Arc::clone(&rules.read().unwrap());
        let blocked = |n: &str| matches!(set.check(n), Verdict::Block { .. });
        assert!(blocked("old-one.test"), "list 1 keeps its old body");
        assert!(blocked("new-two.test") && !blocked("old-two.test"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn meta_rows_exist_before_any_fetch() {
        let r = rig("meta");
        r.lists.sync_meta().await;
        assert_eq!(
            r.sql::<String>("SELECT name FROM list_meta WHERE id = 1"),
            Some("First".to_string())
        );
        assert_eq!(
            r.sql::<i64>("SELECT enabled FROM list_meta WHERE id = 2"),
            Some(0)
        );
        assert_eq!(
            r.sql::<String>("SELECT url FROM list_meta WHERE id = 2"),
            Some(URL2.to_string())
        );
        // A renamed list is updated, not duplicated.
        r.lists
            .set_config(
                vec![cfg(1, "Renamed", URL1, true), cfg(2, "Second", URL2, false)],
                vec![],
            )
            .await
            .unwrap();
        assert_eq!(r.sql::<i64>("SELECT count(*) FROM list_meta"), Some(2));
        assert_eq!(
            r.sql::<String>("SELECT name FROM list_meta WHERE id = 1"),
            Some("Renamed".to_string())
        );
    }

    #[tokio::test]
    async fn removed_lists_are_disabled_and_moved_urls_lose_their_file() {
        let r = rig("moved");
        r.fetch.set(URL1, Ok("||adnet.com^\n"));
        r.lists.refresh().await;
        assert!(r.dir.join("1.txt").exists());

        // List 2 leaves the config; list 1 now comes from another URL.
        r.lists
            .set_config(
                vec![cfg(1, "First", "https://other.test/1.txt", true)],
                vec![],
            )
            .await
            .unwrap();
        assert!(!r.dir.join("1.txt").exists());
        assert!(
            !r.blocks("adnet.com"),
            "the moved list's old body left the set"
        );
        assert_eq!(
            r.sql::<i64>("SELECT enabled FROM list_meta WHERE id = 2"),
            Some(0)
        );
        assert_eq!(
            r.sql::<String>("SELECT name FROM list_meta WHERE id = 2"),
            Some("Second".to_string())
        );
    }

    /// A reload while a refresh is fetching list 1 from the URL the reload moves it away
    /// from. The reload must wait: otherwise it removes the old file first, and the
    /// refresh then saves the old URL's body and swaps it in after the reload.
    #[tokio::test]
    async fn set_config_waits_for_an_in_flight_refresh() {
        let r = Arc::new(rig("race"));
        r.fetch.set(URL1, Ok("||old-url.test^\n"));
        let gate = r.fetch.gate();
        let refresh = tokio::spawn({
            let r = Arc::clone(&r);
            async move { r.lists.refresh().await }
        });
        gate.entered.notified().await;

        let reload = tokio::spawn({
            let r = Arc::clone(&r);
            async move {
                r.lists
                    .set_config(
                        vec![cfg(1, "First", "https://other.test/1.txt", true)],
                        vec![],
                    )
                    .await
                    .unwrap();
            }
        });
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(!reload.is_finished(), "the reload ran during the refresh");

        gate.release.add_permits(1);
        refresh.await.unwrap();
        reload.await.unwrap();
        assert!(!r.blocks("old-url.test"));
        assert!(!r.dir.join("1.txt").exists());
    }

    #[tokio::test]
    async fn config_change_applies_at_once_without_a_fetch() {
        let r = rig("reload");
        r.fetch.set(URL1, Ok("||adnet.com^\n"));
        r.lists.refresh().await;
        // Unreachable now: the rebuild must come from the body on disk.
        r.fetch.set(URL1, Err("offline"));
        r.lists
            .set_config(
                vec![cfg(1, "First", URL1, true)],
                vec!["||new-user.test^".to_string()],
            )
            .await
            .unwrap();
        assert!(r.blocks("new-user.test") && !r.blocks("user-blocked.test"));
        assert!(r.blocks("adnet.com"));
        assert_eq!(r.lists.list_name(1).as_deref(), Some("First"));
        assert_eq!(r.lists.list_name(0).as_deref(), Some("user rules"));
        assert_eq!(r.lists.list_name(9), None);
    }

    #[tokio::test]
    async fn rule_text_failure_leaves_the_last_good_file_alone() {
        let r = rig("textfail");
        let lists = Lists::new(
            vec![cfg(1, "First", URL1, true)],
            vec![],
            r.dir.clone(),
            r.dir.join("missing-dir/x.db"),
            shared(RuleSet::default()),
            r.fetch.clone(),
        );
        r.fetch.set(URL1, Ok("||adnet.com^\n"));
        let report = lists.refresh().await;
        assert!(report.per_list[0]
            .1
            .as_ref()
            .unwrap_err()
            .contains("rule texts"));
        assert!(!r.dir.join("1.txt").exists());
    }

    #[test]
    fn failures_retry_in_an_hour_successes_in_a_day() {
        let ok = (
            1,
            Ok(ListStats {
                list_id: 1,
                parsed: 1,
                skipped: BTreeMap::new(),
            }),
        );
        let bad = (2, Err("HTTP 502".to_string()));
        let report = |per_list, swapped| RefreshReport { per_list, swapped };
        assert_eq!(
            next_refresh_in(&report(vec![ok.clone()], true)),
            REFRESH_EVERY
        );
        // Nothing new (no rebuild) but no error: still a daily cadence.
        assert_eq!(
            next_refresh_in(&report(vec![ok.clone()], false)),
            REFRESH_EVERY
        );
        assert_eq!(
            next_refresh_in(&report(vec![ok, bad.clone()], true)),
            RETRY_AFTER
        );
        assert_eq!(next_refresh_in(&report(vec![bad], false)), RETRY_AFTER);
    }

    #[test]
    fn rule_texts_insert_in_chunks() {
        let db = TempDb::new("chunks");
        Store::open(&db.0).unwrap();
        let mut conn = connect(&db.0).unwrap();
        let body: String = (0..12_345).map(|i| format!("||d{i}.test^\n")).collect();
        insert_rule_texts(&mut conn, 1, &body).unwrap();
        insert_rule_texts(&mut conn, 1, &body).unwrap();
        let n: i64 = conn
            .query_row(
                "SELECT count(*) FROM rule_texts WHERE list_id = 1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 12_345);
    }

    // ---- the real fetcher, against a hand-rolled HTTP server on loopback ----

    /// Answers every connection with `response`, after reading the request head.
    async fn serve(response: Vec<u8>) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                let response = response.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    let mut head = Vec::new();
                    while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                        match sock.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => head.extend_from_slice(&buf[..n]),
                        }
                    }
                    let _ = sock.write_all(&response).await;
                });
            }
        });
        format!("http://{addr}/list.txt")
    }

    fn http(status: &str, extra: &str, body: &str) -> Vec<u8> {
        format!(
            "HTTP/1.1 {status}\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .into_bytes()
    }

    fn fetcher() -> HttpFetcher<crate::dns::pipeline::testing::Fake> {
        let state = Arc::new(State::default());
        HttpFetcher::new(Arc::new(upstreams(&state, Duration::from_millis(1))))
    }

    #[tokio::test]
    async fn http_fetch_returns_the_body() {
        let url = serve(http("200 OK", "", "||adnet.com^\n")).await;
        assert_eq!(
            fetcher().fetch(&url).await,
            Ok("||adnet.com^\n".to_string())
        );
    }

    #[tokio::test]
    async fn http_fetch_rejects_error_status() {
        let url = serve(http("502 Bad Gateway", "", "<html>502</html>")).await;
        let err = fetcher().fetch(&url).await.unwrap_err();
        assert!(err.contains("502"), "{err}");
    }

    #[tokio::test]
    async fn http_fetch_does_not_follow_redirects() {
        let url = serve(http(
            "301 Moved Permanently",
            "Location: https://elsewhere.test/x.txt\r\n",
            "",
        ))
        .await;
        let err = fetcher().fetch(&url).await.unwrap_err();
        assert!(
            err.contains("301") && err.contains("https://elsewhere.test/x.txt"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn http_fetch_stops_at_the_size_cap() {
        let url = serve(http("200 OK", "", &"a".repeat(5000))).await;
        let mut f = fetcher();
        f.max_bytes = 1000;
        let err = f.fetch(&url).await.unwrap_err();
        assert!(err.contains("larger than"), "{err}");
    }

    #[tokio::test]
    async fn host_names_resolve_through_sieves_upstreams() {
        let state = Arc::new(State::default());
        let ups = upstreams(&state, Duration::from_millis(1));
        let ip = resolve_host(&ups, "lists.example").await.unwrap();
        assert!(ip.is_ipv4());
        assert!(state.calls.load(Ordering::SeqCst) > 0);
    }

    #[test]
    fn answers_without_an_a_record_are_a_clear_error() {
        use hickory_proto::op::{MessageType, OpCode, ResponseCode};
        let mut m = Message::new(1, MessageType::Response, OpCode::Query);
        m.metadata.response_code = ResponseCode::NXDomain;
        assert_eq!(first_v4(&m, "x.test").unwrap_err(), "x.test: NXDOMAIN");
        m.metadata.response_code = ResponseCode::NoError;
        assert_eq!(first_v4(&m, "x.test").unwrap_err(), "x.test: no A record");
    }
}
