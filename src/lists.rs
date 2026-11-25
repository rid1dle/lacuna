//! Filter lists: fetch by URL, keep the last good copy on disk, rebuild the live rule set.
//!
//! Bodies live in `lists_dir/<id>.txt` and are the only copy between refreshes: a refresh
//! writes a new body there only when it parses to at least one rule, and every rebuild
//! reads the files back, so a failed fetch or a 200 "<html>502</html>" never costs the
//! rules already in force.
//!
//! Database writes use a short-lived second connection rather than the writer thread's.
//! SQLite's WAL allows one writer at a time (busy_timeout 5s), so each transaction here
//! is at most `RULE_CHUNK` rows: the query-log writer never waits more than a few ms.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, RecordType};
use rusqlite::Connection;
use tracing::{info, warn};

use crate::config::{ListConfig, UpstreamConfig};
use crate::dns::pipeline::Shared;
use crate::dns::upstream::{client_builder, Remote, Upstream, Upstreams};
use crate::rules::{parse_line, ListStats, Parsed, RuleSet};

const FETCH_TIMEOUT: Duration = Duration::from_secs(30);
/// A list bigger than this is refused: the largest real list is a few MB.
const MAX_BODY_BYTES: usize = 20 * 1024 * 1024;
/// Rule texts per transaction while saving a changed list.
const RULE_CHUNK: usize = 5_000;
/// First refresh after startup, then once a day.
pub const FIRST_REFRESH: Duration = Duration::from_secs(5);
pub const REFRESH_EVERY: Duration = Duration::from_secs(24 * 60 * 60);

/// Gets one list body. A trait so the refresh logic is tested without a network.
pub trait Fetch: Send + Sync {
    fn fetch(&self, url: &str) -> impl Future<Output = Result<String, String>> + Send;
}

/// Fetches over HTTP(S). The list host has no fixed address and the machine's resolver
/// is sieve itself, so the host is resolved through sieve's own upstreams and pinned
/// into the client.
pub struct HttpFetcher<U: Upstream> {
    ups: Upstreams<U>,
    max_bytes: usize,
}

impl<U: Upstream + 'static> HttpFetcher<U> {
    pub fn new(ups: Upstreams<U>) -> Self {
        HttpFetcher {
            ups,
            max_bytes: MAX_BODY_BYTES,
        }
    }
}

impl HttpFetcher<Remote> {
    pub fn from_config(cfg: &UpstreamConfig) -> Result<Self> {
        Ok(Self::new(Upstreams::from_config(cfg)?))
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
            return Err(format!("HTTP {} redirect to {to}, not followed", status.as_u16()));
        }
        if !status.is_success() {
            return Err(format!("HTTP {}", status.as_u16()));
        }
        let mut body = Vec::new();
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

pub struct Lists<F: Fetch> {
    lists: Vec<ListConfig>,
    user_rules: Vec<String>,
    dir: PathBuf,
    db: PathBuf,
    rules: Shared<RuleSet>,
    fetcher: F,
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
            lists,
            user_rules,
            dir,
            db,
            rules,
            fetcher,
        }
    }

    fn enabled(&self) -> impl Iterator<Item = &ListConfig> {
        self.lists.iter().filter(|l| l.enabled)
    }

    /// Makes `list_meta` hold a row for every configured list, so the views never show a
    /// NULL list name. Existing rows keep their fetch history.
    pub async fn sync_meta(&self) {
        let rows: Vec<(u32, String, String, bool)> = self
            .lists
            .iter()
            .map(|l| (l.id, l.name.clone(), l.url.clone(), l.enabled))
            .collect();
        self.db_run("list_meta upsert", move |conn| {
            let tx = conn.transaction()?;
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
        let (set, stats) = self.rebuild().await?;
        info!(
            rules = set.rule_count(),
            lists = stats.len() - 1,
            "last good lists loaded"
        );
        self.swap(set);
        Ok(())
    }

    /// Fetches every enabled list, saves the bodies that are good, rebuilds from disk and
    /// swaps the set in. Failures are per list and recorded in `list_meta.last_error`.
    pub async fn refresh(&self) -> RefreshReport {
        // The status updates below need their rows; this is a few tiny upserts.
        self.sync_meta().await;
        let mut outcomes: Vec<(u32, Result<(), String>)> = Vec::new();
        for list in self.enabled() {
            let outcome = self.fetch_one(list).await;
            let (id, now) = (list.id, now_ms());
            let error = outcome.as_ref().err().cloned();
            self.db_run("list fetch status", move |conn| match error {
                None => conn.execute(
                    "UPDATE list_meta SET fetched_at = ?2, last_error = NULL WHERE id = ?1",
                    (id, now),
                ),
                Some(e) => conn.execute("UPDATE list_meta SET last_error = ?2 WHERE id = ?1", (id, e)),
            })
            .await;
            outcomes.push((id, outcome));
        }

        let all_failed = !outcomes.is_empty() && outcomes.iter().all(|(_, o)| o.is_err());
        let built = if all_failed {
            Err(anyhow::anyhow!("every fetch failed"))
        } else {
            self.rebuild().await
        };
        match built {
            Ok((set, stats)) => {
                self.swap(set);
                self.store_stats(&stats).await;
                let per_list = outcomes
                    .into_iter()
                    .map(|(id, o)| match o {
                        Err(e) => (id, Err(e)),
                        Ok(()) => match stats.iter().find(|s| s.list_id == id) {
                            Some(s) => (id, Ok(s.clone())),
                            None => (id, Err("missing from the rebuilt set".to_string())),
                        },
                    })
                    .collect();
                RefreshReport {
                    per_list,
                    swapped: true,
                }
            }
            Err(e) => {
                if !all_failed {
                    warn!("rule set rebuild failed, keeping the running set: {e:#}");
                }
                let reason = format!("{e:#}");
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
    async fn fetch_one(&self, list: &ListConfig) -> Result<(), String> {
        let body = self.fetcher.fetch(&list.url).await?;
        let (dir, db, id) = (self.dir.clone(), self.db.clone(), list.id);
        // Parsing and file and database work are blocking; `body` is dropped inside.
        tokio::task::spawn_blocking(move || persist(&dir, &db, id, &body))
            .await
            .map_err(|e| format!("saving the list panicked: {e}"))?
    }

    /// User rules plus the last good body of every enabled list, bodies read from disk
    /// and dropped as soon as the set is built.
    async fn rebuild(&self) -> Result<(RuleSet, Vec<ListStats>)> {
        let ids: Vec<u32> = self.enabled().map(|l| l.id).collect();
        let (dir, user) = (self.dir.clone(), self.user_rules.clone());
        tokio::task::spawn_blocking(move || {
            let bodies: Vec<(u32, String)> = ids
                .into_iter()
                .filter_map(|id| {
                    match std::fs::read_to_string(dir.join(format!("{id}.txt"))) {
                        Ok(body) => Some((id, body)),
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
                        Err(e) => {
                            warn!(list = id, "reading last good body: {e}");
                            None
                        }
                    }
                })
                .collect();
            let refs: Vec<(u32, &str)> = bodies.iter().map(|(id, b)| (*id, b.as_str())).collect();
            RuleSet::build(&user, &refs)
        })
        .await
        .context("rebuilding the rule set")
    }

    fn swap(&self, set: RuleSet) {
        // The lock is held only for this assignment; readers clone the inner Arc.
        *self.rules.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(set);
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

/// Saves `body` as list `id`'s last good copy. Err when it has no rules (an error page,
/// an empty file). rule_texts are inserted only when the body differs from the saved one.
fn persist(dir: &Path, db: &Path, id: u32, body: &str) -> Result<(), String> {
    if !body.lines().any(|l| matches!(parse_line(l), Parsed::Rule(_))) {
        return Err(format!(
            "fetched body has no rules ({} bytes), keeping the previous list",
            body.len()
        ));
    }
    let path = dir.join(format!("{id}.txt"));
    let unchanged = std::fs::metadata(&path).is_ok_and(|m| m.len() == body.len() as u64)
        && std::fs::read(&path).is_ok_and(|old| old == body.as_bytes());
    if unchanged {
        return Ok(());
    }
    // The rows go in before the file lands, so a crash in between retries next refresh.
    match connect(db).and_then(|mut conn| insert_rule_texts(&mut conn, id, body)) {
        Ok(()) => {}
        Err(e) => warn!(list = id, "saving rule texts: {e}"),
    }
    std::fs::create_dir_all(dir).map_err(|e| format!("creating {}: {e}", dir.display()))?;
    // Write beside, then rename: a crash mid-write never leaves half a list.
    let tmp = dir.join(format!("{id}.txt.tmp"));
    std::fs::write(&tmp, body)
        .and_then(|()| std::fs::rename(&tmp, &path))
        .map_err(|e| format!("writing {}: {e}", path.display()))
}

fn connect(path: &Path) -> rusqlite::Result<Connection> {
    let conn = Connection::open(path)?;
    conn.busy_timeout(Duration::from_secs(5))?;
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

fn insert_chunk(conn: &mut Connection, list_id: u32, chunk: &mut Vec<String>) -> rusqlite::Result<()> {
    let tx = conn.transaction()?;
    {
        let mut stmt = tx.prepare("INSERT OR IGNORE INTO rule_texts (list_id, text) VALUES (?1, ?2)")?;
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
    use std::sync::Mutex;
    use crate::dns::pipeline::shared;
    use crate::dns::pipeline::testing::{upstreams, State};
    use crate::rules::Verdict;
    use crate::store::testing::TempDb;
    use crate::store::Store;
    use rusqlite::OptionalExtension;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicU32, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// A fetcher serving canned bodies by URL, changeable between refreshes.
    #[derive(Clone, Default)]
    struct FakeFetch(Arc<Mutex<HashMap<String, Result<String, String>>>>);

    impl FakeFetch {
        fn set(&self, url: &str, body: Result<&str, &str>) {
            let body = body.map(String::from).map_err(String::from);
            self.0.lock().unwrap().insert(url.to_string(), body);
        }
    }

    impl Fetch for FakeFetch {
        async fn fetch(&self, url: &str) -> Result<String, String> {
            let found = self.0.lock().unwrap().get(url).cloned();
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
            vec![
                cfg(1, "First", URL1, true),
                cfg(2, "Second", URL2, false),
            ],
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
        r.fetch.set(URL1, Ok("||adnet.com^\n||ads.net^\n! comment\n/re/\n"));
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

        // Same body again: nothing new is written.
        let again = r.lists.refresh().await;
        assert!(again.swapped);
        assert_eq!(
            r.sql::<i64>("SELECT count(*) FROM rule_texts WHERE list_id = 1"),
            Some(2)
        );
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
        r.lists.sync_meta().await;
        assert_eq!(r.sql::<i64>("SELECT count(*) FROM list_meta"), Some(2));
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
            .query_row("SELECT count(*) FROM rule_texts WHERE list_id = 1", [], |r| {
                r.get(0)
            })
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
        HttpFetcher::new(upstreams(&state, Duration::from_millis(1)))
    }

    #[tokio::test]
    async fn http_fetch_returns_the_body() {
        let url = serve(http("200 OK", "", "||adnet.com^\n")).await;
        assert_eq!(fetcher().fetch(&url).await, Ok("||adnet.com^\n".to_string()));
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
        assert!(err.contains("301") && err.contains("https://elsewhere.test/x.txt"), "{err}");
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
        assert_eq!(state.calls.load(Ordering::SeqCst) > 0, true);
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
