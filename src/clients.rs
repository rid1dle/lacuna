//! Device names for the query log, kept in `client_names` (the database is the only cache).
//!
//! Names are resolved off the DNS hot path. Config names are written at startup and on
//! reload and always win. A background pass every `PASS_EVERY` asks the router for the
//! PTR record of clients that have no name yet, or whose PTR name is over a day old.
//!
//! IPv6 askers mostly use temporary addresses that change daily and have no PTR name.
//! They are named after the IPv4 device with the same hardware address, read from the
//! host's neighbour table (origin 'neigh'), refreshed at every pass.
//! Probe (2026-11-26): a container on the server's Wi-Fi asking the wired address over
//! IPv6 showed up in the host table as
//!   fd4a:f14c:7097::5eed dev enp2s0 lladdr b0:7d:64:16:00:76
//!   192.168.0.99 dev enp2s0 lladdr b0:7d:64:16:00:76
//!
//! Probe (2026-11-25, from a rust:1-alpine container on the host network, via
//! `lacuna ask <ip>.0.168.192.in-addr.arpa PTR --server 192.168.0.1:53`): the router
//! answers PTR for LAN clients.
//!   100.0.168.192.in-addr.arpa. 0 IN PTR MacBookPro.lan.
//!   196.0.168.192.in-addr.arpa. 0 IN PTR MacBookAir.lan.
//!   175.0.168.192.in-addr.arpa. 0 IN PTR iPhone.lan.
//! Hence the `.lan` suffix stripping below.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::Write as _;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, RecordType};
use rusqlite::{params, Connection, TransactionBehavior};
use tracing::{debug, warn};

use crate::dns::upstream::{UdpUpstream, Upstream};

pub const PASS_EVERY: Duration = Duration::from_secs(10 * 60);
/// First pass shortly after start, so names show up soon after a restart.
pub const FIRST_PASS: Duration = Duration::from_secs(10);
const PTR_TIMEOUT: Duration = Duration::from_secs(1);
const BATCH: i64 = 50;
const RETRY_AFTER_MS: i64 = 24 * 60 * 60 * 1000;

/// A short-lived write connection. Like `lists::connect`: IMMEDIATE transactions wait
/// for the lock (up to busy_timeout) instead of failing when the log writer holds it.
fn connect(path: &Path) -> rusqlite::Result<Connection> {
    let mut conn = Connection::open(path)?;
    conn.busy_timeout(Duration::from_secs(5))?;
    conn.set_transaction_behavior(TransactionBehavior::Immediate);
    Ok(conn)
}

pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

/// Writes config names (origin 'config'), which always win, and removes the config name
/// of any client no longer listed so a PTR name can take over. One transaction; called
/// at startup and by the config reload.
pub fn apply_config_names(db: &Path, devices: &BTreeMap<IpAddr, String>) -> Result<()> {
    let mut conn = connect(db).context("opening the database for device names")?;
    let tx = conn.transaction()?;
    let now = now_ms();
    {
        let mut put = tx.prepare(
            "INSERT INTO client_names (ip, name, origin, first_seen, last_seen)
             VALUES (?1, ?2, 'config', ?3, ?3)
             ON CONFLICT (ip) DO UPDATE SET name = excluded.name, origin = 'config'",
        )?;
        for (ip, name) in devices {
            put.execute(params![ip.to_string(), name, now])?;
        }
        let mut stale = Vec::new();
        {
            let mut q = tx.prepare("SELECT ip FROM client_names WHERE origin = 'config'")?;
            for ip in q.query_map([], |r| r.get::<_, String>(0))? {
                stale.push(ip?);
            }
        }
        let keep: BTreeSet<String> = devices.keys().map(IpAddr::to_string).collect();
        // named_at back to NULL makes the client due for a PTR lookup at the next pass.
        let mut clear = tx.prepare(
            "UPDATE client_names SET name = NULL, origin = NULL, named_at = NULL WHERE ip = ?1",
        )?;
        for ip in stale.iter().filter(|ip| !keep.contains(*ip)) {
            clear.execute([ip])?;
        }
    }
    tx.commit()?;
    Ok(())
}

/// The naming pass. Holds no per-client state in memory.
pub struct Devices<U: Upstream> {
    db: PathBuf,
    router: U,
    /// The neighbour table file (`dns.neighbors`), if configured.
    neighbors: Option<PathBuf>,
}

impl Devices<UdpUpstream> {
    pub fn new(db: PathBuf, router: IpAddr, neighbors: Option<PathBuf>) -> Self {
        Devices {
            db,
            router: UdpUpstream::with_timeout(SocketAddr::new(router, 53), PTR_TIMEOUT),
            neighbors,
        }
    }
}

impl<U: Upstream> Devices<U> {
    #[cfg(test)]
    fn with_upstream(db: PathBuf, router: U, neighbors: Option<PathBuf>) -> Self {
        Devices {
            db,
            router,
            neighbors,
        }
    }

    /// Looks up up to `BATCH` clients that are due and records the results in one
    /// transaction. Due means: not a config or neighbour name, and never asked or asked
    /// over a day ago. Then names IPv6 askers through the neighbour table, so a device
    /// first seen in this pass on both addresses is named on both at once.
    /// Returns how many clients were asked over PTR.
    pub async fn pass(&self, now: i64) -> Result<usize> {
        let asked = self.ptr_pass(now).await?;
        if let Some(file) = &self.neighbors {
            let (db, file) = (self.db.clone(), file.clone());
            tokio::task::spawn_blocking(move || name_by_neighbors(&db, &file, now)).await??;
        }
        Ok(asked)
    }

    async fn ptr_pass(&self, now: i64) -> Result<usize> {
        let db = self.db.clone();
        let due = tokio::task::spawn_blocking(move || due_clients(&db, now)).await??;
        let mut found: Vec<(String, Lookup)> = Vec::with_capacity(due.len());
        for ip in &due {
            let Ok(addr) = ip.parse::<IpAddr>() else {
                continue;
            };
            let outcome = match self.router.query(&ptr_query(addr)).await {
                Ok(answer) => Lookup::Answer(name_from_answer(addr, &answer)),
                // A timeout says nothing about the name: keep what is stored, retry tomorrow.
                Err(e) => {
                    debug!(%ip, "ptr lookup failed: {e:#}");
                    Lookup::Failed
                }
            };
            found.push((ip.clone(), outcome));
        }
        let db = self.db.clone();
        let n = found.len();
        tokio::task::spawn_blocking(move || record(&db, &found, now)).await??;
        Ok(n)
    }

    /// Runs `pass` forever.
    /// Config names first, then the PTR loop, in one background task so the PTR pass
    /// never runs before the config names it must not overwrite. Writing the names can
    /// wait up to busy_timeout for the log writer's lock, so it runs on a blocking thread:
    /// DNS is already listening and must not wait with it.
    pub fn start(self, names: BTreeMap<IpAddr, String>) -> tokio::task::JoinHandle<()>
    where
        U: 'static,
    {
        tokio::spawn(async move {
            let db = self.db.clone();
            match tokio::task::spawn_blocking(move || apply_config_names(&db, &names)).await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => warn!("device names from config not applied: {e:#}"),
                Err(e) => warn!("device names from config not applied: {e}"),
            }
            self.run().await;
        })
    }

    async fn run(self) {
        tokio::time::sleep(FIRST_PASS).await;
        loop {
            if let Err(e) = self.pass(now_ms()).await {
                warn!("device name pass failed: {e:#}");
            }
            tokio::time::sleep(PASS_EVERY).await;
        }
    }
}

fn due_clients(db: &Path, now: i64) -> Result<Vec<String>> {
    let conn = connect(db)?;
    let mut q = conn.prepare(
        "SELECT ip FROM client_names
         WHERE coalesce(origin, '') NOT IN ('config', 'neigh')
           AND (named_at IS NULL OR named_at < ?1)
         ORDER BY coalesce(named_at, 0) LIMIT ?2",
    )?;
    let rows = q.query_map(params![now - RETRY_AFTER_MS, BATCH], |r| r.get(0))?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

/// What one PTR lookup showed.
enum Lookup {
    /// The router answered: a usable name, or None for an answer that names nothing.
    Answer(Option<String>),
    /// No usable reply (timeout, transport error).
    Failed,
}

fn record(db: &Path, found: &[(String, Lookup)], now: i64) -> Result<()> {
    let mut conn = connect(db)?;
    let tx = conn.transaction()?;
    {
        // The origin test again: a config reload may have named the client while its
        // lookup was in flight, and config and neighbour names win over PTR.
        let mut put = tx.prepare(
            "UPDATE client_names
             SET name = ?2, origin = CASE WHEN ?2 IS NULL THEN NULL ELSE 'ptr' END, named_at = ?3
             WHERE ip = ?1 AND coalesce(origin, '') NOT IN ('config', 'neigh')",
        )?;
        let mut touch = tx.prepare(
            "UPDATE client_names SET named_at = ?2
             WHERE ip = ?1 AND coalesce(origin, '') NOT IN ('config', 'neigh')",
        )?;
        for (ip, outcome) in found {
            match outcome {
                Lookup::Answer(name) => put.execute(params![ip, name, now])?,
                Lookup::Failed => touch.execute(params![ip, now])?,
            };
        }
    }
    tx.commit()?;
    Ok(())
}

/// Hardware address by IP, from `ip neigh show` text:
/// `fd4a::5eed dev enp2s0 lladdr b0:7d:64:16:00:76 STALE`. Entries without a hardware
/// address (FAILED, INCOMPLETE) are left out.
fn parse_neighbors(text: &str) -> HashMap<IpAddr, String> {
    let mut out = HashMap::new();
    for line in text.lines() {
        let mut words = line.split_whitespace();
        let Some(Ok(ip)) = words.next().map(str::parse::<IpAddr>) else {
            continue;
        };
        if let Some(mac) = words.skip_while(|w| *w != "lladdr").nth(1) {
            out.insert(ip.to_canonical(), mac.to_ascii_lowercase());
        }
    }
    out
}

/// Names every IPv6 asker whose hardware address also carries an IPv4 address with a
/// name, using that name (origin 'neigh'). With several such IPv4 addresses, the one seen
/// most recently wins. Re-run every pass, so renaming the IPv4 device carries over. An
/// asker missing from the table keeps the name it has. Returns how many rows changed.
fn name_by_neighbors(db: &Path, file: &Path, now: i64) -> Result<usize> {
    let text = match std::fs::read_to_string(file) {
        Ok(t) => t,
        // The sidecar writes it within seconds of starting; until then there is nothing to do.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(e) => {
            return Err(e)
                .with_context(|| format!("reading the neighbour table {}", file.display()))
        }
    };
    let table = parse_neighbors(&text);
    let mut v4_by_mac: HashMap<&str, Vec<String>> = HashMap::new();
    for (ip, mac) in &table {
        if ip.is_ipv4() {
            v4_by_mac.entry(mac).or_default().push(ip.to_string());
        }
    }

    let mut conn = connect(db)?;
    let tx = conn.transaction()?;
    let mut changed = 0;
    {
        // IPv6 text always holds a colon and IPv4 text never does.
        let mut askers = tx.prepare(
            "SELECT ip, name FROM client_names
             WHERE instr(ip, ':') > 0 AND coalesce(origin, '') <> 'config'",
        )?;
        let mut sibling = tx.prepare(
            "SELECT name, last_seen FROM client_names WHERE ip = ?1 AND name IS NOT NULL",
        )?;
        let mut put = tx.prepare(
            "UPDATE client_names SET name = ?2, origin = 'neigh', named_at = ?3
             WHERE ip = ?1 AND coalesce(origin, '') <> 'config'",
        )?;
        let rows: Vec<(String, Option<String>)> = askers
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<rusqlite::Result<_>>()?;
        for (ip, current) in rows {
            let Some(mac) = ip.parse::<IpAddr>().ok().and_then(|a| table.get(&a)) else {
                continue;
            };
            let mut best: Option<(i64, String)> = None;
            for v4 in v4_by_mac.get(mac.as_str()).into_iter().flatten() {
                let found =
                    sibling.query_row([v4], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)));
                match found {
                    Ok((name, seen)) if best.as_ref().map_or(true, |(b, _)| seen > *b) => {
                        best = Some((seen, name));
                    }
                    Ok(_) | Err(rusqlite::Error::QueryReturnedNoRows) => {}
                    Err(e) => return Err(e.into()),
                }
            }
            if let Some((_, name)) = best {
                if current.as_deref() != Some(name.as_str()) {
                    changed += put.execute(params![ip, name, now])?;
                }
            }
        }
    }
    tx.commit()?;
    Ok(changed)
}

/// The reverse-lookup name: `192.168.0.100` is `100.0.168.192.in-addr.arpa.`; IPv6 uses
/// its 32 nibbles in reverse under `ip6.arpa.`.
fn reverse_name(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, c, d] = v4.octets();
            format!("{d}.{c}.{b}.{a}.in-addr.arpa.")
        }
        IpAddr::V6(v6) => {
            let mut s = String::with_capacity(73);
            for byte in v6.octets().iter().rev() {
                let _ = write!(s, "{:x}.{:x}.", byte & 0xf, byte >> 4);
            }
            s.push_str("ip6.arpa.");
            s
        }
    }
}

fn ptr_query(ip: IpAddr) -> Message {
    let mut q = Message::new(0, MessageType::Query, OpCode::Query);
    q.metadata.recursion_desired = true;
    // reverse_name only emits valid labels, so a parse failure cannot happen; an empty
    // query would simply get no answer.
    if let Ok(name) = Name::from_ascii(reverse_name(ip)) {
        q.add_query(Query::query(name, RecordType::PTR));
    }
    q
}

/// The device name in a PTR answer, or None when it says nothing useful.
fn name_from_answer(ip: IpAddr, answer: &Message) -> Option<String> {
    if answer.metadata.response_code != ResponseCode::NoError {
        return None;
    }
    let target = answer.answers.iter().find_map(|r| match &r.data {
        RData::PTR(ptr) => Some(ptr.0.to_ascii()),
        _ => None,
    })?;
    clean_name(ip, &target)
}

/// `mi-phone.lan.` becomes `mi-phone`. A name that is the IP's own reverse name or its
/// text counts as none, as does one left empty.
fn clean_name(ip: IpAddr, raw: &str) -> Option<String> {
    let trimmed = raw.trim().trim_end_matches('.');
    if trimmed.eq_ignore_ascii_case(reverse_name(ip).trim_end_matches('.'))
        || trimmed == ip.to_string()
    {
        return None;
    }
    let mut name = trimmed;
    for suffix in [".lan", ".local", ".home"] {
        if name.len() > suffix.len() && name.to_ascii_lowercase().ends_with(suffix) {
            name = &name[..name.len() - suffix.len()];
            break;
        }
    }
    // The name ends up in the log and the API: printable ASCII only (this also rejects
    // the backslash escapes `Name::to_ascii` writes for odd bytes), one DNS label long.
    let printable = name.bytes().all(|b| (0x21..=0x7e).contains(&b)) && !name.contains('\\');
    (printable && !name.is_empty() && name.len() <= 63 && !name.starts_with('.')).then(|| name.to_string())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use hickory_proto::rr::rdata::PTR;
    use hickory_proto::rr::Record;
    use tokio::net::UdpSocket;

    use super::*;
    use crate::store::testing::TempDb;
    use crate::store::Store;

    const T0: i64 = 1_000_000_000_000;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// A store with the given clients seen, returning the temp db to keep it alive.
    fn db_with(tag: &str, clients: &[&str]) -> TempDb {
        let db = TempDb::new(tag);
        let store = Store::open(&db.0).unwrap();
        drop(store);
        let conn = connect(&db.0).unwrap();
        for c in clients {
            conn.execute(
                "INSERT INTO client_names (ip, first_seen, last_seen) VALUES (?1, 1, 1)",
                [c],
            )
            .unwrap();
        }
        db
    }

    fn row(db: &TempDb, ip: &str) -> (Option<String>, Option<String>, Option<i64>) {
        connect(&db.0)
            .unwrap()
            .query_row(
                "SELECT name, origin, named_at FROM client_names WHERE ip = ?1",
                [ip],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap()
    }

    /// A fake router answering every PTR with `target` (None: NXDOMAIN), counting packets.
    async fn fake_router(target: Option<&'static str>) -> (SocketAddr, Arc<AtomicUsize>) {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        let count = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&count);
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            while let Ok((n, from)) = sock.recv_from(&mut buf).await {
                let Ok(q) = Message::from_vec(&buf[..n]) else {
                    continue;
                };
                seen.fetch_add(1, Ordering::SeqCst);
                let mut r = Message::response(q.metadata.id, q.metadata.op_code);
                r.queries = q.queries.clone();
                match target {
                    Some(t) => r.answers.push(Record::from_rdata(
                        q.queries[0].name().clone(),
                        0,
                        RData::PTR(PTR(Name::from_ascii(t).unwrap())),
                    )),
                    None => r.metadata.response_code = ResponseCode::NXDomain,
                }
                let _ = sock.send_to(&r.to_vec().unwrap(), from).await;
            }
        });
        (addr, count)
    }

    fn devices(db: &TempDb, addr: SocketAddr) -> Devices<UdpUpstream> {
        Devices::with_upstream(
            db.0.clone(),
            UdpUpstream::with_timeout(addr, Duration::from_millis(300)),
            None,
        )
    }

    /// `devices` with a neighbour table file holding `table`.
    fn devices_with_table(db: &TempDb, addr: SocketAddr, table: &str) -> Devices<UdpUpstream> {
        let file = db.0.with_extension("neigh");
        std::fs::write(&file, table).unwrap();
        Devices::with_upstream(
            db.0.clone(),
            UdpUpstream::with_timeout(addr, Duration::from_millis(300)),
            Some(file),
        )
    }

    fn seen(db: &TempDb, ip: &str, last_seen: i64) {
        connect(&db.0)
            .unwrap()
            .execute(
                "UPDATE client_names SET last_seen = ?2 WHERE ip = ?1",
                params![ip, last_seen],
            )
            .unwrap();
    }

    fn cfg(pairs: &[(&str, &str)]) -> BTreeMap<IpAddr, String> {
        pairs.iter().map(|(i, n)| (ip(i), n.to_string())).collect()
    }

    /// The DNS listener is up before names are written, so a database locked by the log
    /// writer (busy_timeout 5 s) must not hold up the caller.
    #[tokio::test]
    async fn start_does_not_wait_for_a_locked_database() {
        let db = db_with("startlock", &[]);
        let mut holder = connect(&db.0).unwrap();
        // IMMEDIATE (the connection's default) takes the write lock at once.
        let lock = holder.transaction().unwrap();
        let (addr, _) = fake_router(None).await;
        let begun = std::time::Instant::now();
        let task = devices(&db, addr).start(cfg(&[("192.168.0.9", "tv")]));
        assert!(
            begun.elapsed() < Duration::from_secs(1),
            "start waited {:?} for the lock",
            begun.elapsed()
        );
        drop(lock);
        let named = || {
            connect(&db.0)
                .unwrap()
                .query_row(
                    "SELECT count(*) FROM client_names WHERE ip = '192.168.0.9' AND name = 'tv'",
                    [],
                    |r| r.get::<_, i64>(0),
                )
                .unwrap()
                == 1
        };
        let mut waited = 0;
        while !named() {
            assert!(waited < 500, "config names never written once the lock was free");
            tokio::time::sleep(Duration::from_millis(10)).await;
            waited += 1;
        }
        task.abort();
    }

    #[tokio::test]
    async fn config_name_wins_and_survives_a_ptr_pass() {
        let db = db_with("cfgwins", &["192.168.0.5"]);
        apply_config_names(&db.0, &cfg(&[("192.168.0.5", "tv")])).unwrap();
        let (addr, count) = fake_router(Some("other.lan.")).await;
        let n = devices(&db, addr).pass(T0).await.unwrap();
        assert_eq!(n, 0);
        assert_eq!(count.load(Ordering::SeqCst), 0);
        assert_eq!(
            row(&db, "192.168.0.5"),
            (Some("tv".into()), Some("config".into()), None)
        );
    }

    #[tokio::test]
    async fn ptr_name_used_when_no_config() {
        let db = db_with("ptrname", &["192.168.0.6"]);
        let (addr, _) = fake_router(Some("mi-phone.lan.")).await;
        devices(&db, addr).pass(T0).await.unwrap();
        assert_eq!(
            row(&db, "192.168.0.6"),
            (Some("mi-phone".into()), Some("ptr".into()), Some(T0))
        );
    }

    #[tokio::test]
    async fn no_answer_means_null_name_but_named_at_set() {
        let db = db_with("noans", &["192.168.0.7"]);
        let (addr, _) = fake_router(None).await;
        devices(&db, addr).pass(T0).await.unwrap();
        assert_eq!(row(&db, "192.168.0.7"), (None, None, Some(T0)));
    }

    #[tokio::test]
    async fn a_timeout_leaves_name_null_and_sets_named_at() {
        let db = db_with("timeout", &["192.168.0.8"]);
        // A bound socket that never replies.
        let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        devices(&db, silent.local_addr().unwrap())
            .pass(T0)
            .await
            .unwrap();
        assert_eq!(row(&db, "192.168.0.8"), (None, None, Some(T0)));
    }

    #[tokio::test]
    async fn a_timeout_keeps_an_existing_ptr_name() {
        let db = db_with("keep", &["192.168.0.13"]);
        let (addr, _) = fake_router(Some("pc.lan.")).await;
        devices(&db, addr).pass(T0).await.unwrap();
        let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let later = T0 + RETRY_AFTER_MS + 1;
        devices(&db, silent.local_addr().unwrap())
            .pass(later)
            .await
            .unwrap();
        assert_eq!(
            row(&db, "192.168.0.13"),
            (Some("pc".into()), Some("ptr".into()), Some(later))
        );
    }

    #[tokio::test]
    async fn a_name_within_24h_is_not_requeried() {
        let db = db_with("cached", &["192.168.0.9"]);
        let (addr, count) = fake_router(Some("pc.lan.")).await;
        let d = devices(&db, addr);
        d.pass(T0).await.unwrap();
        assert_eq!(count.load(Ordering::SeqCst), 1);
        d.pass(T0 + RETRY_AFTER_MS - 1).await.unwrap();
        assert_eq!(count.load(Ordering::SeqCst), 1);
        d.pass(T0 + RETRY_AFTER_MS + 1).await.unwrap();
        assert_eq!(count.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn removing_an_ip_from_config_clears_its_config_name() {
        let db = db_with("removed", &["192.168.0.10", "192.168.0.11"]);
        apply_config_names(
            &db.0,
            &cfg(&[("192.168.0.10", "a"), ("192.168.0.11", "b")]),
        )
        .unwrap();
        apply_config_names(&db.0, &cfg(&[("192.168.0.11", "b")])).unwrap();
        assert_eq!(row(&db, "192.168.0.10"), (None, None, None));
        assert_eq!(row(&db, "192.168.0.11").0.as_deref(), Some("b"));
        // PTR can take over now.
        let (addr, _) = fake_router(Some("late.lan.")).await;
        devices(&db, addr).pass(T0).await.unwrap();
        assert_eq!(row(&db, "192.168.0.10").0.as_deref(), Some("late"));
        assert_eq!(row(&db, "192.168.0.11").0.as_deref(), Some("b"));
    }

    #[test]
    fn config_name_creates_a_row_for_an_unseen_client() {
        let db = db_with("unseen", &[]);
        apply_config_names(&db.0, &cfg(&[("192.168.0.12", "printer")])).unwrap();
        assert_eq!(row(&db, "192.168.0.12").0.as_deref(), Some("printer"));
    }

    #[test]
    fn name_cleaning_table() {
        let a = ip("192.168.0.100");
        let cases = [
            ("mi-phone.lan.", Some("mi-phone")),
            ("MacBookPro.local.", Some("MacBookPro")),
            ("tv.home", Some("tv")),
            ("Host.LAN.", Some("Host")),
            ("plain.", Some("plain")),
            ("box.example.com.", Some("box.example.com")),
            ("lan.", Some("lan")),
            ("100.0.168.192.in-addr.arpa.", None),
            ("192.168.0.100", None),
            ("192.168.0.100.", None),
            (".", None),
            (".lan.", None),
            ("a\\.b.lan.", None),
            ("caf\u{e9}.lan.", None),
            ("with space.lan.", None),
            ("", None),
        ];
        let long = format!("{}.lan.", "a".repeat(64));
        assert_eq!(clean_name(a, &long), None);
        let max = format!("{}.lan.", "a".repeat(63));
        assert_eq!(clean_name(a, &max), Some("a".repeat(63)));
        for (raw, want) in cases {
            assert_eq!(clean_name(a, raw).as_deref(), want, "{raw:?}");
        }
    }

    /// As busybox `ip neigh show` printed it on the host (2026-11-26), plus the entry
    /// kinds that carry no hardware address.
    const TABLE: &str = "\
192.168.0.99 dev enp2s0 lladdr B0:7D:64:16:00:76 used 0/0/0 probes 1 STALE
fd4a:f14c:7097::5eed dev enp2s0 lladdr b0:7d:64:16:00:76 used 0/0/0 probes 1 REACHABLE
fd4a:f14c:7097::1 dev enp2s0 lladdr dc:ea:e7:e7:51:02 router STALE
192.168.0.42 dev enp2s0  FAILED
fd4a:f14c:7097::dead dev enp2s0 INCOMPLETE
not-an-ip dev enp2s0 lladdr 00:00:00:00:00:01 STALE
";

    #[test]
    fn neighbour_table_parses() {
        let t = parse_neighbors(TABLE);
        assert_eq!(t.len(), 3, "{t:?}");
        assert_eq!(t[&ip("192.168.0.99")], "b0:7d:64:16:00:76");
        assert_eq!(t[&ip("fd4a:f14c:7097::5eed")], "b0:7d:64:16:00:76");
        assert_eq!(t[&ip("fd4a:f14c:7097::1")], "dc:ea:e7:e7:51:02");
    }

    #[tokio::test]
    async fn ipv6_asker_takes_its_ipv4_devices_name() {
        let db = db_with(
            "neigh",
            &["192.168.0.99", "fd4a:f14c:7097::5eed", "fd4a:f14c:7097::77"],
        );
        apply_config_names(&db.0, &cfg(&[("192.168.0.99", "MacBookAir")])).unwrap();
        let (addr, _) = fake_router(None).await;
        let d = devices_with_table(&db, addr, TABLE);
        d.pass(T0).await.unwrap();
        assert_eq!(
            row(&db, "fd4a:f14c:7097::5eed"),
            (Some("MacBookAir".into()), Some("neigh".into()), Some(T0))
        );
        // Not in the table: no name, and PTR found none either.
        assert_eq!(row(&db, "fd4a:f14c:7097::77").0, None);

        // A rename of the IPv4 device carries over at the next pass.
        apply_config_names(&db.0, &cfg(&[("192.168.0.99", "Mac")])).unwrap();
        d.pass(T0 + 1).await.unwrap();
        assert_eq!(row(&db, "fd4a:f14c:7097::5eed").0.as_deref(), Some("Mac"));

        // A day later the router has a PTR name for everything; the neighbour name stays.
        let (addr, count) = fake_router(Some("other.lan.")).await;
        let later = T0 + 2 * RETRY_AFTER_MS;
        devices_with_table(&db, addr, TABLE)
            .pass(later)
            .await
            .unwrap();
        assert_eq!(
            row(&db, "fd4a:f14c:7097::5eed"),
            (Some("Mac".into()), Some("neigh".into()), Some(T0 + 1))
        );
        // Only the unnamed IPv6 asker was due for PTR (the IPv4 one has a config name).
        assert_eq!(count.load(Ordering::SeqCst), 1);
        assert_eq!(row(&db, "fd4a:f14c:7097::77").0.as_deref(), Some("other"));
    }

    #[tokio::test]
    async fn neighbour_naming_prefers_the_latest_ipv4_and_never_overrides_config() {
        let table = "\
192.168.0.20 dev enp2s0 lladdr aa:aa:aa:aa:aa:01 STALE
192.168.0.21 dev enp2s0 lladdr aa:aa:aa:aa:aa:01 REACHABLE
fd00::20 dev enp2s0 lladdr aa:aa:aa:aa:aa:01 REACHABLE
fd00::30 dev enp2s0 lladdr aa:aa:aa:aa:aa:01 REACHABLE
";
        let db = db_with(
            "neighpick",
            &["192.168.0.20", "192.168.0.21", "fd00::20", "fd00::30"],
        );
        apply_config_names(
            &db.0,
            &cfg(&[
                ("192.168.0.20", "old lease"),
                ("192.168.0.21", "phone"),
                ("fd00::30", "pinned"),
            ]),
        )
        .unwrap();
        seen(&db, "192.168.0.20", 5);
        seen(&db, "192.168.0.21", 9);
        let (addr, _) = fake_router(None).await;
        devices_with_table(&db, addr, table).pass(T0).await.unwrap();
        assert_eq!(row(&db, "fd00::20").0.as_deref(), Some("phone"));
        assert_eq!(
            row(&db, "fd00::30"),
            (Some("pinned".into()), Some("config".into()), None)
        );
    }

    #[tokio::test]
    async fn missing_neighbour_table_is_not_an_error() {
        let db = db_with("neighmissing", &["fd00::1"]);
        let (addr, _) = fake_router(None).await;
        let d = Devices::with_upstream(
            db.0.clone(),
            UdpUpstream::with_timeout(addr, Duration::from_millis(300)),
            Some(db.0.with_extension("absent")),
        );
        d.pass(T0).await.unwrap();
    }

    #[test]
    fn reverse_names() {
        assert_eq!(reverse_name(ip("192.168.0.100")), "100.0.168.192.in-addr.arpa.");
        assert_eq!(
            reverse_name(ip("2001:db8::1")),
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa."
        );
    }
}
