//! Hourly and daily rollups, and retention. Called from the writer thread, which owns
//! the only write connection.
//!
//! Rollups read raw rows not yet rolled up: `meta.rolled_hourly_until` and
//! `meta.rolled_daily_until` hold the end (exclusive, unix ms) of what has been counted.

use anyhow::Result;
use rusqlite::{params, Connection, OptionalExtension};

use super::{Store, DAY_MS, HOUR_MS, IST_OFFSET_MS};

/// A row's `ts` is when its query started; it reaches the table after the answer (up to
/// a few seconds) plus up to 1s in the writer's batch. Only hours and days that ended
/// this long ago are rolled up, so a late row never lands behind the mark.
const SETTLE_MS: i64 = 60_000;
/// Rows per DELETE. Each chunk commits on its own, so retention never holds the write
/// lock for long.
const DELETE_CHUNK: usize = 10_000;

const ROLLED_HOURLY: &str = "rolled_hourly_until";
const ROLLED_DAILY: &str = "rolled_daily_until";

/// Rollups, then retention. The writer thread calls the two on their own schedules.
#[allow(dead_code)] // Task 13's history import runs both after loading rows.
pub fn run(store: &Store, now_ms: i64) -> Result<()> {
    roll_up(store, now_ms)?;
    retain(store, now_ms)
}

/// Counts every closed hour and every closed IST day not counted yet, in one transaction.
pub fn roll_up(store: &Store, now_ms: i64) -> Result<()> {
    let settled = now_ms - SETTLE_MS;
    // `unchecked_transaction` works through `&Connection`; nothing else uses this
    // connection meanwhile, since only the writer thread holds it. It begins IMMEDIATE
    // (the connection's default, see `Store::open`) so it waits for a list refresh.
    let tx = store.conn.unchecked_transaction()?;

    let from = meta(&tx, ROLLED_HOURLY)?.unwrap_or(0);
    let to = settled - settled.rem_euclid(HOUR_MS);
    if to > from {
        roll_hourly(&tx, IN_RANGE, from, to)?;
        set_meta(&tx, ROLLED_HOURLY, to)?;
    }
    let from = meta(&tx, ROLLED_DAILY)?.unwrap_or(0);
    let to = ist_day_start(settled);
    if to > from {
        roll_daily(&tx, IN_RANGE, from, to)?;
        set_meta(&tx, ROLLED_DAILY, to)?;
    }
    tx.commit()?;
    Ok(())
}

/// Adds rows inserted after `after_rowid` whose `ts` is behind a mark to that rollup,
/// since the scheduled rollup starts at the mark and would never see them. Runs in the
/// inserting transaction. Returns how many rows were behind either mark.
pub(super) fn roll_late(conn: &Connection, after_rowid: i64) -> Result<u64> {
    // No mark yet means nothing was rolled up, so nothing can be late.
    let hourly = meta(conn, ROLLED_HOURLY)?.unwrap_or(0);
    let daily = meta(conn, ROLLED_DAILY)?.unwrap_or(0);
    let late: i64 = conn.query_row(
        "SELECT count(*) FROM raw_queries WHERE rowid > ?1 AND ts < ?2",
        params![after_rowid, hourly.max(daily)],
        |r| r.get(0),
    )?;
    if late > 0 {
        roll_hourly(conn, LATE, after_rowid, hourly)?;
        roll_daily(conn, LATE, after_rowid, daily)?;
    }
    Ok(u64::try_from(late).unwrap_or(0))
}

/// Raw rows a rollup reads: a `ts` range (the scheduled rollup, through the ts index),
/// or rows after a rowid that are behind a mark (late rows).
const IN_RANGE: &str = "ts >= ?1 AND ts < ?2";
const LATE: &str = "rowid > ?1 AND ts < ?2";

/// Upserts, so counts already in the rollups (late rows, the AdGuard import) add up.
fn roll_hourly(conn: &Connection, rows: &str, a: i64, b: i64) -> Result<()> {
    conn.execute(
        &format!(
            "INSERT INTO hourly_counts (hour_ms, client, outcome, n, latency_us_sum)
             SELECT ts - ts % ?3, client, outcome, count(*), sum(latency_us)
             FROM raw_queries WHERE {rows}
             GROUP BY 1, 2, 3
             ON CONFLICT (hour_ms, client, outcome) DO UPDATE SET
                 n = n + excluded.n,
                 latency_us_sum = latency_us_sum + excluded.latency_us_sum"
        ),
        params![a, b, HOUR_MS],
    )?;
    Ok(())
}

/// `day_ts` is the IST midnight before `ts`: whole days are counted from 1970-01-01
/// 00:00 IST, then shifted back to UTC milliseconds.
fn roll_daily(conn: &Connection, rows: &str, a: i64, b: i64) -> Result<()> {
    conn.execute(
        &format!(
            "INSERT INTO daily_counts (day_ts, client, domain_id, outcome, rule_id, n)
             SELECT (ts + ?3) / ?4 * ?4 - ?3, client, domain_id, outcome,
                    coalesce(rule_id, 0), count(*)
             FROM raw_queries WHERE {rows}
             GROUP BY 1, 2, 3, 4, 5
             ON CONFLICT (day_ts, client, domain_id, outcome, rule_id) DO UPDATE SET
                 n = n + excluded.n"
        ),
        params![a, b, IST_OFFSET_MS, DAY_MS],
    )?;
    Ok(())
}

/// Deletes raw rows older than `raw_days` (only those already rolled up) and rollups
/// older than `rollup_days`.
pub fn retain(store: &Store, now_ms: i64) -> Result<()> {
    let conn = &store.conn;
    let keep = store.retention;
    let rolled = meta(conn, ROLLED_HOURLY)?
        .unwrap_or(0)
        .min(meta(conn, ROLLED_DAILY)?.unwrap_or(0));
    let raw_cutoff = (now_ms - i64::from(keep.raw_days) * DAY_MS).min(rolled);
    delete_chunked(
        conn,
        "DELETE FROM raw_queries WHERE rowid IN \
         (SELECT rowid FROM raw_queries WHERE ts < ?1 LIMIT ?2)",
        raw_cutoff,
    )?;
    let rollup_cutoff = now_ms - i64::from(keep.rollup_days) * DAY_MS;
    delete_chunked(
        conn,
        "DELETE FROM hourly_counts WHERE rowid IN \
         (SELECT rowid FROM hourly_counts WHERE hour_ms < ?1 LIMIT ?2)",
        rollup_cutoff,
    )?;
    delete_chunked(
        conn,
        "DELETE FROM daily_counts WHERE rowid IN \
         (SELECT rowid FROM daily_counts WHERE day_ts < ?1 LIMIT ?2)",
        ist_day_start(rollup_cutoff),
    )?;
    Ok(())
}

/// The IST midnight (unix ms) that starts the house day containing `ms`.
fn ist_day_start(ms: i64) -> i64 {
    (ms + IST_OFFSET_MS).div_euclid(DAY_MS) * DAY_MS - IST_OFFSET_MS
}

/// Runs a `DELETE ... LIMIT ?2` until it deletes fewer than a full chunk. Outside a
/// transaction, so every chunk commits and releases the lock.
fn delete_chunked(conn: &Connection, sql: &str, cutoff: i64) -> Result<()> {
    let mut stmt = conn.prepare(sql)?;
    while stmt.execute(params![cutoff, DELETE_CHUNK as i64])? == DELETE_CHUNK {}
    Ok(())
}

fn meta(conn: &Connection, key: &str) -> Result<Option<i64>> {
    Ok(conn
        .query_row("SELECT value FROM meta WHERE key = ?1", [key], |r| r.get(0))
        .optional()?)
}

fn set_meta(conn: &Connection, key: &str, value: i64) -> Result<()> {
    conn.execute(
        "INSERT INTO meta (key, value) VALUES (?1, ?2)
         ON CONFLICT (key) DO UPDATE SET value = excluded.value",
        params![key, value],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;
    use crate::codes::{Outcome, Source};
    use crate::dns::pipeline::{LogSink, QueryRecord};
    use crate::store::testing::record;
    use crate::store::{writer, Store, DAY_MS, HOUR_MS};

    /// 2026-11-24T19:00:00Z, which is 2026-11-25 00:30 in IST.
    const T19: i64 = 1_795_546_800_000;
    const T1930: i64 = 1_795_548_600_000;
    const T2015: i64 = 1_795_551_300_000;
    /// 2026-11-25T19:00:00Z: the IST day 2026-11-25 has closed.
    const NEXT_DAY: i64 = 1_795_633_200_000;
    /// 2026-11-24T18:30:00Z, IST midnight starting 2026-11-25.
    const IST_MIDNIGHT: i64 = 1_795_545_000_000;

    fn store_with(records: &[QueryRecord]) -> Store {
        let mut store = Store::open(Path::new(":memory:")).unwrap();
        let tx = store.conn.transaction().unwrap();
        writer::insert_batch(&tx, records, Source::Lacuna).unwrap();
        tx.commit().unwrap();
        store
    }

    fn rows<T: rusqlite::types::FromSql>(store: &Store, sql: &str) -> Vec<Vec<T>> {
        let mut stmt = store.conn.prepare(sql).unwrap();
        let cols = stmt.column_count();
        stmt.query_map([], |r| (0..cols).map(|i| r.get(i)).collect())
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    }

    fn three_records() -> Vec<QueryRecord> {
        let mut a = record(T19, "10.0.0.1", "x.example");
        a.latency_us = 1000;
        let mut b = record(T1930, "10.0.0.1", "x.example");
        b.latency_us = 3000;
        let mut c = record(T2015, "10.0.0.1", "y.example");
        c.latency_us = 500;
        vec![a, b, c]
    }

    #[test]
    fn rollup_builds_hourly_and_daily() {
        let store = store_with(&three_records());
        run(&store, NEXT_DAY).unwrap();
        // Running again must not count anything twice.
        run(&store, NEXT_DAY + 10 * 60_000).unwrap();

        let hourly: Vec<Vec<rusqlite::types::Value>> = rows(
            &store,
            "SELECT hour_ts, client, device, outcome, n, avg_latency_ms FROM hourly ORDER BY hour_ts",
        );
        use rusqlite::types::Value::{Integer as I, Real as R, Text as S};
        assert_eq!(
            hourly,
            vec![
                vec![
                    I(T19),
                    S("10.0.0.1".into()),
                    S("10.0.0.1".into()),
                    S("allowed".into()),
                    I(2),
                    R(2.0)
                ],
                vec![
                    I(T19 + 3_600_000),
                    S("10.0.0.1".into()),
                    S("10.0.0.1".into()),
                    S("allowed".into()),
                    I(1),
                    R(0.5)
                ],
            ]
        );

        let daily: Vec<Vec<rusqlite::types::Value>> = rows(
            &store,
            "SELECT day, day_ts, client, device, domain, outcome, rule, list, n FROM daily ORDER BY domain",
        );
        use rusqlite::types::Value::Null as N;
        let day = |domain: &str, n| {
            vec![
                S("2026-11-25".into()),
                I(IST_MIDNIGHT),
                S("10.0.0.1".into()),
                S("10.0.0.1".into()),
                S(domain.into()),
                S("allowed".into()),
                N,
                N,
                I(n),
            ]
        };
        assert_eq!(daily, vec![day("x.example", 2), day("y.example", 1)]);
    }

    #[test]
    fn open_hour_and_open_day_wait() {
        let store = store_with(&three_records());
        // 20:30Z: the 19:00 hour is closed, the 20:00 hour and the IST day are not.
        run(&store, T19 + 90 * 60_000).unwrap();
        let hourly: Vec<Vec<i64>> = rows(&store, "SELECT hour_ts, n FROM hourly");
        assert_eq!(hourly, vec![vec![T19, 2]]);
        let daily: Vec<Vec<i64>> = rows(&store, "SELECT n FROM daily");
        assert!(daily.is_empty());

        run(&store, NEXT_DAY).unwrap();
        let hourly: Vec<Vec<i64>> = rows(&store, "SELECT hour_ts, n FROM hourly ORDER BY hour_ts");
        assert_eq!(hourly, vec![vec![T19, 2], vec![T19 + 3_600_000, 1]]);
    }

    #[test]
    fn daily_keeps_blocking_rule_and_list() {
        let mut r = record(T19, "10.0.0.1", "ads.example");
        r.outcome = Outcome::Blocked;
        r.list_id = Some(0);
        r.rule = Some("||ads.example^".into());
        let store = store_with(&[r.clone(), r]);
        run(&store, NEXT_DAY).unwrap();
        let daily: Vec<Vec<String>> = rows(
            &store,
            "SELECT outcome, rule, list, CAST(n AS TEXT) FROM daily",
        );
        assert_eq!(
            daily,
            vec![vec![
                "blocked".to_string(),
                "||ads.example^".into(),
                "user rules".into(),
                "2".into()
            ]]
        );
    }

    /// A row that arrives behind the rollup marks is counted in the same batch, exactly
    /// once, and survives retention of its raw row.
    #[test]
    fn late_rows_are_rolled_up_once() {
        let store = store_with(&three_records());
        run(&store, NEXT_DAY).unwrap();

        let (tx, mut w) = writer::channel(store, 4);
        tx.send(record(T19 + 5 * 60_000, "10.0.0.1", "x.example"));
        tx.send(record(NEXT_DAY, "10.0.0.1", "x.example"));
        assert!(w.collect(std::time::Duration::ZERO));
        w.flush().unwrap();
        let store = &w.store;

        let late: Vec<Vec<i64>> = rows(store, "SELECT value FROM counters WHERE name = 'log_late'");
        assert_eq!(late, vec![vec![1]]);
        let t19: Vec<Vec<i64>> = rows(
            store,
            &format!("SELECT n FROM hourly WHERE hour_ts = {T19}"),
        );
        assert_eq!(t19, vec![vec![3]]);
        let x: Vec<Vec<i64>> = rows(store, "SELECT n FROM daily WHERE domain = 'x.example'");
        assert_eq!(x, vec![vec![3]]);

        // The scheduled rollup picks up the on-time row only.
        run(store, NEXT_DAY + 2 * HOUR_MS).unwrap();
        let totals = |store: &Store| -> Vec<Vec<i64>> {
            rows(
                store,
                &format!(
                    "SELECT (SELECT sum(n) FROM hourly), (SELECT sum(n) FROM daily), \
                     (SELECT n FROM hourly WHERE hour_ts = {T19})"
                ),
            )
        };
        assert_eq!(totals(store), vec![vec![5, 4, 3]]);

        retain(store, NEXT_DAY + 31 * DAY_MS).unwrap();
        let raw: Vec<Vec<i64>> = rows(store, "SELECT count(*) FROM raw_queries");
        assert_eq!(
            raw,
            vec![vec![1]],
            "only the row in the open IST day is kept"
        );
        assert_eq!(totals(store), vec![vec![5, 4, 3]]);
    }

    #[test]
    fn retention_keeps_rollups() {
        let now = NEXT_DAY;
        let old = now - 31 * DAY_MS;
        let fresh = now - DAY_MS;
        let store = store_with(&[
            record(old, "10.0.0.1", "old.example"),
            record(fresh, "10.0.0.1", "fresh.example"),
        ]);
        run(&store, now).unwrap();

        let raw: Vec<Vec<String>> = rows(&store, "SELECT domain FROM queries");
        assert_eq!(raw, vec![vec!["fresh.example".to_string()]]);
        let daily: Vec<Vec<String>> = rows(&store, "SELECT domain FROM daily ORDER BY domain");
        assert_eq!(
            daily,
            vec![
                vec!["fresh.example".to_string()],
                vec!["old.example".into()]
            ]
        );
        let hourly: Vec<Vec<i64>> = rows(&store, "SELECT count(*) FROM hourly");
        assert_eq!(hourly, vec![vec![2]]);

        // Rollups older than rollup_days go too.
        run(&store, now + 400 * DAY_MS).unwrap();
        let left: Vec<Vec<i64>> = rows(
            &store,
            "SELECT (SELECT count(*) FROM hourly) + (SELECT count(*) FROM daily)",
        );
        assert_eq!(left, vec![vec![0]]);
    }

    #[test]
    fn retention_never_deletes_rows_not_rolled_up() {
        let now = NEXT_DAY;
        let store = store_with(&[record(now - 31 * DAY_MS, "10.0.0.1", "old.example")]);
        retain(&store, now).unwrap();
        let raw: Vec<Vec<i64>> = rows(&store, "SELECT count(*) FROM raw_queries");
        assert_eq!(raw, vec![vec![1]]);
    }

    #[test]
    fn retention_deletes_in_chunks() {
        let now = NEXT_DAY;
        let old: Vec<_> = (0..(DELETE_CHUNK as i64 * 2 + 7))
            .map(|i| record(now - 40 * DAY_MS + i, "10.0.0.1", "old.example"))
            .collect();
        let store = store_with(&old);
        run(&store, now).unwrap();
        let raw: Vec<Vec<i64>> = rows(&store, "SELECT count(*) FROM raw_queries");
        assert_eq!(raw, vec![vec![0]]);
    }
}
