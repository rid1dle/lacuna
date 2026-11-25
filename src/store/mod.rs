//! The SQLite query log: schema, migration and the one write connection.
//!
//! Tables (schema.sql) are internal; the views (views.sql) are the public contract
//! (schemaVersion 1) that Sonder's dashboards query with their own SQL.

pub mod rollup;
pub mod writer;

use std::fmt::Write as _;
use std::path::Path;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior};

use crate::codes::{Outcome, Reason, ServedFrom, Source};

/// The schema version this build creates and understands.
const SCHEMA_VERSION: i64 = 1;
const TABLES_SQL: &str = include_str!("schema.sql");
const VIEWS_TEMPLATE: &str = include_str!("views.sql");

/// Counter names in `counter_values`. Each exists from the first open, at 0.
pub const LOG_DROPPED: &str = "log_dropped";
pub const LOG_LATE: &str = "log_late";
pub const QUERIES_TOTAL: &str = "queries_total";
const COUNTERS: &[&str] = &[LOG_DROPPED, LOG_LATE, QUERIES_TOTAL];

pub const HOUR_MS: i64 = 3_600_000;
pub const DAY_MS: i64 = 86_400_000;
/// Asia/Kolkata is UTC+05:30 all year (no DST), so a house day is a fixed offset from UTC.
pub const IST_OFFSET_MS: i64 = 19_800_000;

/// The list id of the user rules from config.toml.
const USER_LIST_ID: u32 = 0;

/// Response codes the views name (RFC 1035 and 2136 mnemonics); others show as `RCODE<n>`.
const RCODE_LABELS: &[(u16, &str)] = &[
    (0, "NOERROR"),
    (1, "FORMERR"),
    (2, "SERVFAIL"),
    (3, "NXDOMAIN"),
    (4, "NOTIMP"),
    (5, "REFUSED"),
];

/// Record types the views name; any other shows as `TYPE<n>`, the RFC 3597 spelling.
const TYPE_LABELS: &[(u16, &str)] = &[
    (1, "A"),
    (2, "NS"),
    (5, "CNAME"),
    (6, "SOA"),
    (12, "PTR"),
    (15, "MX"),
    (16, "TXT"),
    (28, "AAAA"),
    (33, "SRV"),
    (64, "SVCB"),
    (65, "HTTPS"),
    (255, "ANY"),
];

/// How long rows are kept, in days.
#[derive(Debug, Clone, Copy)]
pub struct Retention {
    pub raw_days: u32,
    pub rollup_days: u32,
}

impl Default for Retention {
    /// The deploy config's values.
    fn default() -> Self {
        Retention {
            raw_days: 30,
            rollup_days: 365,
        }
    }
}

/// The write connection. Exactly one exists per process; it lives on the writer thread.
pub struct Store {
    conn: Connection,
    pub retention: Retention,
}

impl Store {
    /// Opens (creating if needed) and migrates the database at `path`.
    pub fn open(path: &Path) -> Result<Store> {
        let mut conn =
            Connection::open(path).with_context(|| format!("opening {}", path.display()))?;
        conn.busy_timeout(Duration::from_secs(5))?;
        // WAL lets the API's read-only connections read while this one writes. A
        // filesystem without shared memory support silently stays in rollback mode,
        // where readers would block the writer, so the answer is checked.
        let mode: String = conn.query_row("PRAGMA journal_mode = WAL", [], |r| r.get(0))?;
        if mode != "wal" && mode != "memory" {
            bail!(
                "{}: journal_mode is {mode}, WAL is required",
                path.display()
            );
        }
        // NORMAL in WAL mode cannot corrupt the file; a power cut may lose the last
        // batches, which is fine for a query log. cache_size is negative KiB: 4 MB.
        conn.execute_batch(
            "PRAGMA synchronous = NORMAL; PRAGMA cache_size = -4096; PRAGMA foreign_keys = OFF;",
        )?;
        migrate(&mut conn).with_context(|| format!("migrating {}", path.display()))?;
        Ok(Store {
            conn,
            retention: Retention::default(),
        })
    }
}

/// No `meta` table: a new database, so create the tables. Version 1: keep them. Anything
/// else is refused rather than written to. Then, on every open, the views are rebuilt
/// from this build's enums and every counter is made to exist.
fn migrate(conn: &mut Connection) -> Result<()> {
    // IMMEDIATE takes the write lock before reading the version, so two processes
    // opening a new file cannot both create the schema.
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let has_meta: i64 = tx.query_row(
        "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'meta'",
        [],
        |r| r.get(0),
    )?;
    if has_meta == 0 {
        tx.execute_batch(TABLES_SQL)?;
    } else {
        let version: Option<i64> = tx
            .query_row(
                "SELECT value FROM meta WHERE key = 'schema_version'",
                [],
                |r| r.get(0),
            )
            .optional()?;
        match version {
            Some(SCHEMA_VERSION) => {}
            Some(v) if v > SCHEMA_VERSION => bail!(
                "schema_version {v} is newer than this sieve understands ({SCHEMA_VERSION}); \
                 refusing to start rather than write to it"
            ),
            other => bail!("not a sieve database: meta.schema_version is {other:?}"),
        }
    }

    let views: Vec<String> = tx
        .prepare("SELECT name FROM sqlite_master WHERE type = 'view'")?
        .query_map([], |r| r.get(0))?
        .collect::<Result<_, _>>()?;
    for view in views {
        tx.execute_batch(&format!("DROP VIEW \"{}\"", view.replace('"', "\"\"")))?;
    }
    tx.execute_batch(&views_sql())?;
    for name in COUNTERS {
        tx.execute(
            "INSERT OR IGNORE INTO counter_values (name, value) VALUES (?1, 0)",
            [name],
        )?;
    }
    tx.commit()?;
    Ok(())
}

/// views.sql with its placeholders filled in from the Rust enums and constants.
fn views_sql() -> String {
    let list_name =
        format!("CASE WHEN r.list_id = {USER_LIST_ID} THEN 'user rules' ELSE l.name END");
    let codes = |column: &str, arms: Vec<(u8, &'static str)>| case_sql(column, arms, "NULL");
    VIEWS_TEMPLATE
        .replace("{type_label}", &type_label_sql("qtype"))
        .replace(
            "{rcode_label}",
            &case_sql("rcode", RCODE_LABELS.iter().copied(), "'RCODE' || rcode"),
        )
        .replace(
            "{outcome_label}",
            &codes(
                "outcome",
                Outcome::ALL.iter().map(|v| (v.code(), v.label())).collect(),
            ),
        )
        .replace(
            "{reason_label}",
            &codes(
                "reason",
                Reason::ALL.iter().map(|v| (v.code(), v.label())).collect(),
            ),
        )
        .replace(
            "{served_from_label}",
            &codes(
                "served_from",
                ServedFrom::ALL
                    .iter()
                    .map(|v| (v.code(), v.label()))
                    .collect(),
            ),
        )
        .replace(
            "{source_label}",
            &codes(
                "source",
                Source::ALL.iter().map(|v| (v.code(), v.label())).collect(),
            ),
        )
        .replace("{list_name}", &list_name)
        .replace("{ist_offset_ms}", &IST_OFFSET_MS.to_string())
}

fn type_label_sql(column: &str) -> String {
    case_sql(
        column,
        TYPE_LABELS.iter().copied(),
        &format!("'TYPE' || {column}"),
    )
}

/// `CASE column WHEN code THEN 'label' ... ELSE otherwise END`. Labels are our own
/// constants, but quotes are doubled anyway so a label can never break the SQL.
fn case_sql<C: std::fmt::Display>(
    column: &str,
    arms: impl IntoIterator<Item = (C, &'static str)>,
    otherwise: &str,
) -> String {
    let mut sql = format!("CASE {column}");
    for (code, label) in arms {
        let _ = write!(sql, " WHEN {code} THEN '{}'", label.replace('\'', "''"));
    }
    let _ = write!(sql, " ELSE {otherwise} END");
    sql
}

#[cfg(test)]
pub(crate) mod testing {
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};

    use crate::codes::{Outcome, Reason, ServedFrom};
    use crate::dns::pipeline::QueryRecord;

    /// A database file in the temp dir, removed (with its WAL files) on drop.
    pub struct TempDb(pub PathBuf);

    impl TempDb {
        pub fn new(tag: &str) -> TempDb {
            static NEXT: AtomicU32 = AtomicU32::new(0);
            let n = NEXT.fetch_add(1, Ordering::Relaxed);
            let name = format!("sieve-test-{tag}-{}-{n}.db", std::process::id());
            let db = TempDb(std::env::temp_dir().join(name));
            db.remove();
            db
        }

        fn remove(&self) {
            for suffix in ["", "-wal", "-shm"] {
                let mut p = self.0.clone().into_os_string();
                p.push(suffix);
                let _ = std::fs::remove_file(p);
            }
        }
    }

    impl Drop for TempDb {
        fn drop(&mut self) {
            self.remove();
        }
    }

    /// A plain allowed A query answered from cache.
    pub fn record(ts_ms: i64, client: &str, name: &str) -> QueryRecord {
        QueryRecord {
            ts_ms,
            client: client.parse().expect("test ip"),
            name: name.to_string(),
            qtype: 1,
            rcode: 0,
            outcome: Outcome::Allowed,
            reason: Reason::None,
            list_id: None,
            rule: None,
            served_from: ServedFrom::Cache,
            upstream: None,
            latency_us: 1000,
            answers: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::time::Duration;

    use hickory_proto::rr::RecordType;

    use super::testing::{record, TempDb};
    use super::writer;
    use super::*;
    use crate::codes::{Outcome, Reason, ServedFrom, Source};
    use crate::dns::pipeline::LogSink;

    fn memory() -> Store {
        Store::open(Path::new(":memory:")).unwrap()
    }

    #[test]
    fn views_expose_labels() {
        let (tx, mut w) = writer::channel(memory(), 16);
        let mut r = record(1_795_546_800_123, "192.168.0.50", "ads.example.com");
        r.qtype = 28;
        r.outcome = Outcome::Blocked;
        r.reason = Reason::Rule;
        r.served_from = ServedFrom::Upstream;
        r.list_id = Some(0);
        r.rule = Some("||ads.example.com^".into());
        r.upstream = Some("https://dns10.quad9.net/dns-query".into());
        r.latency_us = 1500;
        r.answers = vec!["0.0.0.0".parse().unwrap(), "::".parse().unwrap()];
        tx.send(r);
        assert!(w.collect(Duration::ZERO));
        w.flush().unwrap();

        let conn = &w.store.conn;
        let labels: (String, String, String) = conn
            .query_row("SELECT outcome, served_from, type FROM queries", [], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })
            .unwrap();
        assert_eq!(labels, ("blocked".into(), "upstream".into(), "AAAA".into()));

        type Row = (i64, String, String, String, String, String, String, String);
        let row: Row = conn
            .query_row(
                "SELECT ts, time, client, device, domain, reason, rule, list FROM queries",
                [],
                |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                        r.get(6)?,
                        r.get(7)?,
                    ))
                },
            )
            .unwrap();
        assert_eq!(
            row,
            (
                1_795_546_800_123,
                "2026-11-24T19:00:00.123Z".into(),
                "192.168.0.50".into(),
                "192.168.0.50".into(),
                "ads.example.com".into(),
                "rule".into(),
                "||ads.example.com^".into(),
                "user rules".into(),
            )
        );
        let rest: (String, f64, String, String) = conn
            .query_row(
                "SELECT upstream, latency_ms, answers, source FROM queries",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap();
        assert_eq!(
            rest,
            (
                "https://dns10.quad9.net/dns-query".into(),
                1.5,
                "0.0.0.0,::".into(),
                "sieve".into()
            )
        );
    }

    #[test]
    fn every_code_label_round_trips_through_views() {
        assert_labels_round_trip(&mut memory());
    }

    /// Views are rebuilt from this build's enums on every open, so a database created
    /// by an older build (or a damaged view) gets the current labels.
    #[test]
    fn views_are_rebuilt_on_open() {
        let db = TempDb::new("views");
        Store::open(&db.0)
            .unwrap()
            .conn
            .execute_batch(
                "DROP VIEW queries;
                 CREATE VIEW queries AS SELECT ts, 'stale' AS outcome, 'stale' AS reason,
                     'stale' AS served_from, 'stale' AS source FROM raw_queries;",
            )
            .unwrap();
        assert_labels_round_trip(&mut Store::open(&db.0).unwrap());
    }

    /// The column lists are the frozen v1 contract; changing one is a schemaVersion bump.
    #[test]
    fn view_columns_are_the_contract() {
        let store = memory();
        let contract: &[(&str, &[&str])] = &[
            (
                "queries",
                &[
                    "ts",
                    "time",
                    "client",
                    "device",
                    "domain",
                    "type",
                    "rcode",
                    "outcome",
                    "reason",
                    "rule",
                    "list_id",
                    "list",
                    "served_from",
                    "upstream",
                    "latency_ms",
                    "answers",
                    "source",
                ],
            ),
            (
                "hourly",
                &[
                    "hour_ts",
                    "client",
                    "device",
                    "outcome",
                    "n",
                    "avg_latency_ms",
                ],
            ),
            (
                "daily",
                &[
                    "day", "day_ts", "client", "device", "domain", "outcome", "rule", "list_id",
                    "list", "n",
                ],
            ),
            (
                "devices",
                &[
                    "client",
                    "device",
                    "origin",
                    "first_seen_ts",
                    "last_seen_ts",
                ],
            ),
            (
                "lists",
                &[
                    "id",
                    "name",
                    "url",
                    "enabled",
                    "parsed",
                    "skipped_json",
                    "fetched_ts",
                    "last_error",
                ],
            ),
            ("rules", &["id", "list_id", "list", "text"]),
            ("counters", &["name", "value"]),
        ];
        for &(view, columns) in contract {
            let stmt = store
                .conn
                .prepare(&format!("SELECT * FROM {view}"))
                .unwrap();
            assert_eq!(stmt.column_names().collect::<Vec<_>>(), columns, "{view}");
        }
        let views: i64 = store
            .conn
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type = 'view'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(views, contract.len() as i64);
    }

    /// The documented range filters must reach an index on the base table, never a scan.
    #[test]
    fn range_filters_use_indexes() {
        let store = memory();
        for sql in [
            "SELECT * FROM queries WHERE ts >= 1",
            "SELECT * FROM queries WHERE client = '10.0.0.1' AND ts >= 1",
            "SELECT * FROM hourly WHERE hour_ts >= 1",
            "SELECT * FROM daily WHERE day_ts >= 1",
        ] {
            let mut stmt = store
                .conn
                .prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
                .unwrap();
            let plan: Vec<String> = stmt
                .query_map([], |r| r.get(3))
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap();
            assert!(
                !plan.iter().any(|step| step.starts_with("SCAN")),
                "{sql}: {plan:?}"
            );
        }
    }

    #[test]
    fn rcode_labels() {
        let mut store = memory();
        let codes = [0u16, 1, 2, 3, 4, 5, 99];
        let records: Vec<_> = codes
            .iter()
            .enumerate()
            .map(|(i, &rcode)| {
                let mut r = record(i as i64, "10.0.0.1", "a.example");
                r.rcode = rcode;
                r
            })
            .collect();
        let tx = store.conn.transaction().unwrap();
        writer::insert_batch(&tx, &records, Source::Sieve).unwrap();
        tx.commit().unwrap();
        let mut stmt = store
            .conn
            .prepare("SELECT rcode FROM queries ORDER BY ts")
            .unwrap();
        let got: Vec<String> = stmt
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(
            got,
            ["NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED", "RCODE99"]
        );
    }

    /// Every enum label comes back through the views; a variant added to codes.rs but
    /// missing from the views would read as NULL here.
    fn assert_labels_round_trip(store: &mut Store) {
        let n = [
            Outcome::ALL.len(),
            Reason::ALL.len(),
            ServedFrom::ALL.len(),
            Source::ALL.len(),
        ]
        .into_iter()
        .max()
        .unwrap();
        for (i, &source) in Source::ALL.iter().enumerate() {
            let records: Vec<_> = (0..n)
                .map(|j| {
                    let mut r = record((i * n + j) as i64, "10.0.0.1", "a.example");
                    r.outcome = Outcome::ALL[j % Outcome::ALL.len()];
                    r.reason = Reason::ALL[j % Reason::ALL.len()];
                    r.served_from = ServedFrom::ALL[j % ServedFrom::ALL.len()];
                    r
                })
                .collect();
            let tx = store.conn.transaction().unwrap();
            writer::insert_batch(&tx, &records, source).unwrap();
            tx.commit().unwrap();
        }
        let mut stmt = store
            .conn
            .prepare("SELECT outcome, reason, served_from, source FROM queries ORDER BY ts")
            .unwrap();
        type Labels = (
            Option<String>,
            Option<String>,
            Option<String>,
            Option<String>,
        );
        let rows: Vec<Labels> = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(rows.len(), n * Source::ALL.len());
        for (k, row) in rows.iter().enumerate() {
            let (i, j) = (k / n, k % n);
            let want = (
                Some(Outcome::ALL[j % Outcome::ALL.len()].label().to_string()),
                Some(Reason::ALL[j % Reason::ALL.len()].label().to_string()),
                Some(
                    ServedFrom::ALL[j % ServedFrom::ALL.len()]
                        .label()
                        .to_string(),
                ),
                Some(Source::ALL[i].label().to_string()),
            );
            assert_eq!(*row, want, "row {k}");
        }
        // hourly and daily carry outcome labels too.
        rollup::run(store, 3 * DAY_MS).unwrap();
        for view in ["hourly", "daily"] {
            let mut stmt = store
                .conn
                .prepare(&format!(
                    "SELECT DISTINCT outcome FROM {view} ORDER BY outcome"
                ))
                .unwrap();
            let got: Vec<Option<String>> = stmt
                .query_map([], |r| r.get(0))
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap();
            let mut want: Vec<Option<String>> = Outcome::ALL
                .iter()
                .map(|o| Some(o.label().to_string()))
                .collect();
            want.sort();
            assert_eq!(got, want, "{view}");
        }
    }

    #[test]
    fn type_labels_match_hickory() {
        for &(code, label) in TYPE_LABELS {
            assert_eq!(RecordType::from(code).to_string(), label, "type {code}");
        }
        let store = memory();
        let label = |code: u16| -> String {
            store
                .conn
                .query_row(
                    &format!("SELECT {}", type_label_sql(&code.to_string())),
                    [],
                    |r| r.get(0),
                )
                .unwrap()
        };
        assert_eq!(label(28), "AAAA");
        assert_eq!(label(65), "HTTPS");
        assert_eq!(label(999), "TYPE999");
    }

    #[test]
    fn schema_has_no_unfilled_placeholders() {
        assert!(!views_sql().contains('{'), "placeholder left in views");
        assert!(!TABLES_SQL.contains('{'), "tables take no placeholders");
    }

    /// Day length and the IST offset come from the Rust constants, never typed into SQL.
    #[test]
    fn templates_have_no_time_literals() {
        for (file, text) in [("schema.sql", TABLES_SQL), ("views.sql", VIEWS_TEMPLATE)] {
            for literal in ["86400", "19800", "3600"] {
                assert!(!text.contains(literal), "{file} contains {literal}");
            }
        }
    }

    #[test]
    fn migration_is_idempotent_and_refuses_newer() {
        let db = TempDb::new("migrate");
        {
            let store = Store::open(&db.0).unwrap();
            let mode: String = store
                .conn
                .query_row("PRAGMA journal_mode", [], |r| r.get(0))
                .unwrap();
            assert_eq!(mode, "wal");
            let cache: i64 = store
                .conn
                .query_row("PRAGMA cache_size", [], |r| r.get(0))
                .unwrap();
            assert_eq!(cache, -4096);
            store
                .conn
                .execute("INSERT INTO domain_names(name) VALUES ('kept.example')", [])
                .unwrap();
        }
        {
            let store = Store::open(&db.0).unwrap();
            let n: i64 = store
                .conn
                .query_row("SELECT count(*) FROM domain_names", [], |r| r.get(0))
                .unwrap();
            assert_eq!(n, 1, "reopening must not recreate the schema");
            let version: i64 = store
                .conn
                .query_row(
                    "SELECT value FROM meta WHERE key = 'schema_version'",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(version, 1);
            store
                .conn
                .execute("UPDATE meta SET value = 2 WHERE key = 'schema_version'", [])
                .unwrap();
        }
        let err = Store::open(&db.0)
            .err()
            .expect("newer schema must be refused");
        assert!(format!("{err:#}").contains("newer"), "{err:#}");
    }

    #[test]
    fn counters_view_starts_at_zero() {
        let store = memory();
        let mut stmt = store
            .conn
            .prepare("SELECT name, value FROM counters ORDER BY name")
            .unwrap();
        let rows: Vec<(String, i64)> = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(
            rows,
            vec![
                ("log_dropped".into(), 0),
                ("log_late".into(), 0),
                ("queries_total".into(), 0)
            ]
        );
    }

    #[test]
    fn rules_and_lists_views_name_the_list() {
        let store = memory();
        store
            .conn
            .execute_batch(
                "INSERT INTO list_meta(id, name, url, enabled) VALUES (1, 'AdGuard DNS filter', 'https://x', 1);
                 INSERT INTO rule_texts(list_id, text) VALUES (1, '||a.com^'), (0, '||b.com^'), (9, '||c.com^');",
            )
            .unwrap();
        let mut stmt = store
            .conn
            .prepare("SELECT list_id, list, text FROM rules ORDER BY id")
            .unwrap();
        let rows: Vec<(i64, Option<String>, String)> = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(
            rows,
            vec![
                (1, Some("AdGuard DNS filter".into()), "||a.com^".into()),
                (0, Some("user rules".into()), "||b.com^".into()),
                (9, None, "||c.com^".into()),
            ]
        );
        let name: String = store
            .conn
            .query_row("SELECT name FROM lists WHERE id = 1", [], |r| r.get(0))
            .unwrap();
        assert_eq!(name, "AdGuard DNS filter");
    }
}
