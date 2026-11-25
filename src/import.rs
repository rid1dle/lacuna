//! Imports AdGuard Home's query log (querylog.json, one JSON object per line) so the
//! dashboards start with its history.
//!
//! Rows inside the raw window become raw rows with `source = adguard`; older rows only
//! add to the hourly and daily rollups. The file is read line by line and written in
//! batches, so memory stays flat on a log of any size, and each batch holds the write
//! lock briefly because a live `serve` may be writing to the same database.

use std::collections::BTreeMap;
use std::fmt;
use std::io::BufRead;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, ensure, Context, Result};
use hickory_proto::op::Message;
use hickory_proto::rr::RecordType;
use serde::de::IgnoredAny;
use serde::Deserialize;

use crate::codes::{Outcome, Reason, ServedFrom};
use crate::dns::pipeline::{addresses, QueryRecord};
use crate::rules::RuleRef;
use crate::store::{rollup, writer, Store, DAY_MS, HOUR_MS};

/// Rows per transaction.
pub const BATCH_ROWS: usize = 10_000;
/// The least time between one batch's commit and the next batch taking the lock.
/// SQLite's busy handler sleeps at most 100 ms between tries, so a live writer waiting
/// on the lock always gets a try inside this gap and is never starved into its timeout.
const YIELD: Duration = Duration::from_millis(100);

/// AdGuard Home's `filtering.Reason` values (internal/filtering/reason.go, numbered from
/// iota). Only these four occur in the house log; any other is skipped and counted.
const AG_NOT_FILTERED: i64 = 0;
const AG_ALLOW_LIST: i64 = 1;
const AG_BLOCK_LIST: i64 = 3;
const AG_REWRITTEN: i64 = 9;

#[derive(Debug, Default)]
pub struct ImportReport {
    pub lines: u64,
    pub raw: u64,
    pub rolled_up_only: u64,
    /// Lines not imported, by reason.
    pub skipped: BTreeMap<String, u64>,
    /// Imported rows whose answer could not be decoded: kept with no addresses and a
    /// NULL rcode (unknown).
    pub answer_undecodable: u64,
    /// The longest any one batch held the write lock.
    pub slowest_batch: Duration,
    /// Rows from this time (unix ms) on stay raw; older ones only add to the rollups.
    pub raw_from_ms: i64,
}

impl fmt::Display for ImportReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "raw from        unix ms {} (older rows only add to the rollups)",
            self.raw_from_ms
        )?;
        writeln!(f, "lines           {}", self.lines)?;
        writeln!(f, "raw             {}", self.raw)?;
        writeln!(f, "rolled up only  {}", self.rolled_up_only)?;
        for (reason, n) in &self.skipped {
            writeln!(f, "skipped         {n} {reason}")?;
        }
        writeln!(
            f,
            "undecodable     {} (imported without answers)",
            self.answer_undecodable
        )?;
        write!(f, "slowest batch   {} ms", self.slowest_batch.as_millis())
    }
}

/// Why a line was not imported; the label is its key in `ImportReport::skipped`.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Skip {
    BadJson,
    BadTime,
    BadClient,
    UnknownQtype,
    /// A `Result.Reason` this import does not map.
    UnmappedReason(i64),
    /// Blocked or allowed by a rule, but the line names none.
    NoRule,
    ListIdOutOfRange,
}

impl Skip {
    fn label(self) -> String {
        match self {
            Skip::BadJson => "bad_json".into(),
            Skip::BadTime => "bad_time".into(),
            Skip::BadClient => "bad_client".into(),
            Skip::UnknownQtype => "unknown_qtype".into(),
            Skip::UnmappedReason(n) => format!("unmapped_reason_{n}"),
            Skip::NoRule => "no_rule".into(),
            Skip::ListIdOutOfRange => "list_id_out_of_range".into(),
        }
    }
}

/// One line of querylog.json. Fields this import does not use (QC, CP, AD, IPList,
/// IsFiltered) are ignored.
#[derive(Deserialize)]
struct Line {
    #[serde(rename = "T")]
    time: String,
    #[serde(rename = "QH")]
    host: String,
    #[serde(rename = "QT")]
    qtype: String,
    #[serde(rename = "IP")]
    client: String,
    #[serde(rename = "Upstream", default)]
    upstream: String,
    /// The response sent, as a base64 DNS wire message.
    #[serde(rename = "Answer", default)]
    answer: String,
    /// The upstream's response, present when AdGuard blocked after resolving.
    #[serde(rename = "OrigAnswer")]
    orig_answer: Option<IgnoredAny>,
    #[serde(rename = "Cached", default)]
    cached: bool,
    #[serde(rename = "Result", default)]
    result: AgResult,
    /// Nanoseconds.
    #[serde(rename = "Elapsed")]
    elapsed: u64,
}

#[derive(Deserialize, Default)]
struct AgResult {
    #[serde(rename = "Reason", default)]
    reason: i64,
    #[serde(rename = "Rules", default)]
    rules: Vec<AgRule>,
}

#[derive(Deserialize)]
struct AgRule {
    #[serde(rename = "Text")]
    text: String,
    #[serde(rename = "FilterListID")]
    list_id: i64,
}

/// Imports `input` into `store`. Refuses a database that already had an import, since
/// the same queries would be counted twice (`Store::forget_adguard_import` clears that).
pub fn import_adguard(
    input: impl BufRead,
    store: &Store,
    now_ms: i64,
    raw_days: u32,
) -> Result<ImportReport> {
    import_in_batches(input, store, now_ms, raw_days, BATCH_ROWS)
}

fn import_in_batches(
    mut input: impl BufRead,
    store: &Store,
    now_ms: i64,
    raw_days: u32,
    batch_rows: usize,
) -> Result<ImportReport> {
    if let Some(at) = store.claim_adguard_import(now_ms)? {
        bail!(
            "an AdGuard import already ran into this database (started at unix ms {at}); \
             --force imports again and counts every query it already imported twice"
        );
    }
    // Closes the hours and days before now first. Every imported raw row is then behind
    // the marks and rolled up inside its own batch, rather than all at once later in one
    // long transaction.
    rollup::roll_up(store, now_ms)?;
    let raw_from = now_ms - i64::from(raw_days) * DAY_MS;

    let mut report = ImportReport {
        raw_from_ms: raw_from,
        ..ImportReport::default()
    };
    let mut batch = Vec::with_capacity(batch_rows);
    let mut buf = Vec::new();
    let mut last_commit = None;
    loop {
        buf.clear();
        if input
            .read_until(b'\n', &mut buf)
            .context("reading the log")?
            == 0
        {
            break;
        }
        report.lines += 1;
        match parse_line(&buf) {
            Ok((record, decoded)) => {
                report.answer_undecodable += u64::from(!decoded);
                batch.push(record);
            }
            Err(skip) => *report.skipped.entry(skip.label()).or_default() += 1,
        }
        if batch.len() >= batch_rows {
            write(store, &mut batch, raw_from, &mut report, &mut last_commit)?;
        }
    }
    write(store, &mut batch, raw_from, &mut report, &mut last_commit)?;
    // Rolls up what closed during the import. No retention here: pruning is serve's,
    // on its own schedule and with the deployed config's retention.
    rollup::roll_up(store, now_ms)?;

    let skipped: u64 = report.skipped.values().sum();
    ensure!(
        report.lines == report.raw + report.rolled_up_only + skipped,
        "import report does not add up: {report:?}"
    );
    Ok(report)
}

fn write(
    store: &Store,
    batch: &mut Vec<QueryRecord>,
    raw_from: i64,
    report: &mut ImportReport,
    last_commit: &mut Option<Instant>,
) -> Result<()> {
    if batch.is_empty() {
        return Ok(());
    }
    if let Some(at) = *last_commit {
        std::thread::sleep(YIELD.saturating_sub(at.elapsed()));
    }
    let done = writer::import_batch(store, batch, raw_from)?;
    *last_commit = Some(Instant::now());
    report.raw += done.raw;
    report.rolled_up_only += done.rolled_up_only;
    report.slowest_batch = report.slowest_batch.max(done.held);
    batch.clear();
    Ok(())
}

/// One line to a record, and whether its answer decoded.
fn parse_line(bytes: &[u8]) -> Result<(QueryRecord, bool), Skip> {
    let line: Line = serde_json::from_slice(bytes).map_err(|_| Skip::BadJson)?;
    let ts_ms = parse_time_ms(&line.time).ok_or(Skip::BadTime)?;
    let client = IpAddr::from_str(&line.client).map_err(|_| Skip::BadClient)?;
    let qtype = qtype_code(&line.qtype).ok_or(Skip::UnknownQtype)?;

    let answered = if line.cached {
        ServedFrom::Cache
    } else {
        ServedFrom::Upstream
    };
    // Mapped as lacuna's own pipeline logs the same decision: a block or rewrite is
    // answered locally, and an allow rule is named.
    let (outcome, reason, rule, served_from) = match line.result.reason {
        AG_NOT_FILTERED => (Outcome::Allowed, Reason::None, None, answered),
        AG_ALLOW_LIST => (
            Outcome::Allowed,
            Reason::Rule,
            Some(first_rule(&line.result)?),
            answered,
        ),
        AG_BLOCK_LIST => {
            // OrigAnswer means the name passed and a name in the upstream's answer (a
            // CNAME target) matched: lacuna's cname reason.
            let reason = if line.orig_answer.is_some() {
                Reason::Cname
            } else {
                Reason::Rule
            };
            let rule = first_rule(&line.result)?;
            (Outcome::Blocked, reason, Some(rule), ServedFrom::Local)
        }
        AG_REWRITTEN => (Outcome::Rewritten, Reason::None, None, ServedFrom::Local),
        other => return Err(Skip::UnmappedReason(other)),
    };

    let decoded = decode_answer(&line.answer);
    let decoded_ok = decoded.is_some();
    let (rcode, answers) = match decoded {
        Some((rcode, answers)) => (Some(rcode), answers),
        None => (None, Vec::new()),
    };
    let (list_id, rule) = rule.unzip();
    let record = QueryRecord {
        ts_ms,
        client,
        name: line.host.trim_end_matches('.').to_ascii_lowercase(),
        qtype,
        rcode,
        outcome,
        reason,
        list_id,
        rule,
        served_from,
        // AdGuard also names an upstream on cache hits (the one that filled the cache)
        // and on blocks found in a cached answer. In lacuna the column is the upstream
        // asked for this query, so it is kept only when one was.
        upstream: Some(line.upstream)
            .filter(|u| served_from == ServedFrom::Upstream && !u.is_empty()),
        latency_us: u32::try_from(line.elapsed / 1000).unwrap_or(u32::MAX),
        answers,
    };
    Ok((record, decoded_ok))
}

/// AdGuard's history names rules by text; the writer interns them.
fn first_rule(result: &AgResult) -> Result<(u32, RuleRef), Skip> {
    let rule = result.rules.first().ok_or(Skip::NoRule)?;
    let list = u32::try_from(rule.list_id).map_err(|_| Skip::ListIdOutOfRange)?;
    Ok((list, RuleRef::Text(Arc::from(rule.text.as_str()))))
}

/// The rcode and A/AAAA addresses of a base64 DNS response; `None` if it is not one.
fn decode_answer(b64: &str) -> Option<(u16, Vec<IpAddr>)> {
    let wire = data_encoding::BASE64.decode(b64.as_bytes()).ok()?;
    let msg = Message::from_vec(&wire).ok()?;
    Some((u16::from(msg.metadata.response_code), addresses(&msg)))
}

/// A type mnemonic, or `TYPE<n>` (RFC 3597) for a type without one, to its number.
fn qtype_code(qt: &str) -> Option<u16> {
    match qt.strip_prefix("TYPE") {
        Some(n) => n.parse().ok(),
        None => RecordType::from_str(qt).ok().map(u16::from),
    }
}

/// RFC 3339 (`2026-09-09T05:54:28.96330461+05:30`) to unix milliseconds. Digits past
/// the millisecond are dropped, never rounded into the next one.
fn parse_time_ms(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    let num = |from: usize, len: usize| -> Option<i64> {
        let digits = b.get(from..from + len)?;
        digits.iter().try_fold(0i64, |n, &c| {
            c.is_ascii_digit().then(|| n * 10 + i64::from(c - b'0'))
        })
    };
    let sep = |at: usize, c: u8| b.get(at) == Some(&c);
    if !(sep(4, b'-') && sep(7, b'-') && sep(10, b'T') && sep(13, b':') && sep(16, b':')) {
        return None;
    }
    let (year, month, day) = (num(0, 4)?, num(5, 2)?, num(8, 2)?);
    let (hour, minute, second) = (num(11, 2)?, num(14, 2)?, num(17, 2)?);
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 || minute > 59 {
        return None;
    }
    // 60 is a leap second; unix time folds it into the next second.
    if second > 60 {
        return None;
    }

    let mut at = 19;
    let mut millis = 0;
    if sep(at, b'.') {
        at += 1;
        let start = at;
        while b.get(at).is_some_and(u8::is_ascii_digit) {
            if at - start < 3 {
                millis = millis * 10 + i64::from(b[at] - b'0');
            }
            at += 1;
        }
        match at - start {
            0 => return None,
            1 => millis *= 100,
            2 => millis *= 10,
            _ => {}
        }
    }
    let offset_ms = match b.get(at)? {
        b'Z' if at + 1 == b.len() => 0,
        &c @ (b'+' | b'-') if at + 6 == b.len() && sep(at + 3, b':') => {
            let (h, m) = (num(at + 1, 2)?, num(at + 4, 2)?);
            let ms = h * HOUR_MS + m * 60_000;
            if c == b'-' {
                -ms
            } else {
                ms
            }
        }
        _ => return None,
    };
    let days = days_from_civil(year, month, day);
    Some(days * DAY_MS + hour * HOUR_MS + minute * 60_000 + second * 1000 + millis - offset_ms)
}

/// Days from 1970-01-01 to a proleptic Gregorian date (Howard Hinnant's
/// `days_from_civil`): years are counted from March so the leap day falls last.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * ((month + 9) % 12) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    use rusqlite::types::FromSql;

    use super::*;
    use crate::store::testing::{record, TempDb};
    use crate::store::{rollup, DAY_MS, HOUR_MS};

    /// 2026-11-25 00:00 IST. With 30 raw days the cut is 2026-10-26 00:00 IST.
    const NOW: i64 = 1_795_545_000_000;
    const CUT: i64 = 1_792_953_000_000;
    const RAW_DAYS: u32 = 30;
    /// Ten hand-written lines: three older than the cut, one cut short (bad JSON), one
    /// with an answer that is not base64.
    const SAMPLE: &str = include_str!("../tests/fixtures/adguard_querylog_sample.json");

    fn memory() -> Store {
        Store::open(Path::new(":memory:")).unwrap()
    }

    fn sample(store: &Store) -> ImportReport {
        import_adguard(SAMPLE.as_bytes(), store, NOW, RAW_DAYS).unwrap()
    }

    fn one<T: FromSql>(store: &Store, sql: &str) -> T {
        store.conn().query_row(sql, [], |r| r.get(0)).unwrap()
    }

    #[test]
    fn imports_blocked_row_with_rule() {
        let store = memory();
        sample(&store);
        type Row = (String, String, String, i64, String, String, String, f64);
        let row: Row = store
            .conn()
            .query_row(
                "SELECT outcome, reason, rule, list_id, served_from, answers, source, latency_ms
                 FROM queries WHERE domain = 'slackb.com'",
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
                "blocked".into(),
                "rule".into(),
                "||slackb.com^".into(),
                1,
                "local".into(),
                "0.0.0.0".into(),
                "adguard".into(),
                0.31,
            )
        );
        // The same rule blocked an old row too; it is stored once.
        let rules: i64 = one(
            &store,
            "SELECT count(*) FROM rules WHERE list_id = 1 AND text = '||slackb.com^'",
        );
        assert_eq!(rules, 1);
    }

    /// The other Result shapes the real log has: an allowlist rule, a legacy rewrite,
    /// a block found in the upstream answer (OrigAnswer is kept), and plain answers.
    #[test]
    fn maps_every_result_shape() {
        let store = memory();
        sample(&store);
        type Row = (
            String,
            String,
            String,
            Option<String>,
            Option<String>,
            String,
        );
        let mut stmt = store
            .conn()
            .prepare(
                "SELECT domain, outcome, reason, rule, upstream, served_from
                 FROM queries WHERE domain <> 'slackb.com' ORDER BY ts",
            )
            .unwrap();
        let rows: Vec<Row> = stmt
            .query_map([], |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                ))
            })
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        let up = || Some("https://dns.example/dns-query".to_string());
        let s = |v: &str| v.to_string();
        assert_eq!(
            rows,
            vec![
                // AdGuard names an upstream on cache hits and on blocks found in a
                // cached answer; lacuna names one only when it was asked.
                (
                    s("www.example.org"),
                    s("allowed"),
                    s("none"),
                    None,
                    None,
                    s("cache")
                ),
                (
                    s("allowed.example"),
                    s("allowed"),
                    s("rule"),
                    Some(s("@@||allowed.example^")),
                    up(),
                    s("upstream")
                ),
                (
                    s("nas.home.example"),
                    s("rewritten"),
                    s("none"),
                    None,
                    None,
                    s("local")
                ),
                (
                    s("tracker.example"),
                    s("blocked"),
                    s("cname"),
                    Some(s("||cdn.tracker.example^")),
                    None,
                    s("local")
                ),
                (
                    s("nx.example"),
                    s("allowed"),
                    s("none"),
                    None,
                    up(),
                    s("upstream")
                ),
            ]
        );
        let v6: (String, String, String) = store
            .conn()
            .query_row(
                "SELECT client, type, answers FROM queries WHERE domain = 'www.example.org'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(v6, (s("fd00::9"), s("AAAA"), s("2001:db8::2")));
        let rewrite: String = one(
            &store,
            "SELECT answers FROM queries WHERE domain = 'nas.home.example'",
        );
        assert_eq!(rewrite, "192.0.2.53");
    }

    #[test]
    fn old_rows_go_to_rollups_only() {
        let store = memory();
        let report = sample(&store);
        assert_eq!(report.rolled_up_only, 3);
        let raw_old: i64 = one(
            &store,
            &format!("SELECT count(*) FROM raw_queries WHERE ts < {CUT}"),
        );
        assert_eq!(raw_old, 0);
        // "Old.Example." is stored as old.example.
        let old: i64 = one(
            &store,
            "SELECT sum(n) FROM daily WHERE domain = 'old.example'",
        );
        assert_eq!(old, 2);
        let blocked: (i64, String, i64) = store
            .conn()
            .query_row(
                &format!(
                    "SELECT n, rule, list_id FROM daily
                     WHERE domain = 'slackb.com' AND day_ts < {CUT}"
                ),
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(blocked, (1, "||slackb.com^".into(), 1));
        let hourly: i64 = one(
            &store,
            &format!("SELECT sum(n) FROM hourly WHERE hour_ts < {CUT}"),
        );
        assert_eq!(hourly, 3);
        // 12 ms upstream answer plus a 90 us cached one, in different hours.
        let latency: f64 = one(
            &store,
            &format!("SELECT max(avg_latency_ms) FROM hourly WHERE hour_ts < {CUT}"),
        );
        assert_eq!(latency, 12.0);
    }

    #[test]
    fn bad_json_line_is_counted_not_fatal() {
        let store = memory();
        let report = sample(&store);
        assert_eq!(
            report.skipped,
            BTreeMap::from([("bad_json".to_string(), 1)])
        );
        // The line after it was imported.
        let nx: i64 = one(
            &store,
            "SELECT count(*) FROM queries WHERE domain = 'nx.example'",
        );
        assert_eq!(nx, 1);

        // Bytes that are not UTF-8 are a bad line too, not an I/O error.
        let store = memory();
        let mut input = b"\xff\xfe\n".to_vec();
        input.extend_from_slice(SAMPLE.lines().next().unwrap().as_bytes());
        let report = import_adguard(&input[..], &store, NOW, RAW_DAYS).unwrap();
        assert_eq!((report.lines, report.rolled_up_only), (2, 1));
        assert_eq!(report.skipped.get("bad_json"), Some(&1));
    }

    #[test]
    fn report_adds_up() {
        let store = memory();
        let report = sample(&store);
        assert_eq!(
            (
                report.lines,
                report.raw,
                report.rolled_up_only,
                report.answer_undecodable
            ),
            (10, 6, 3, 1)
        );
        assert_eq!(
            report.lines,
            report.raw + report.rolled_up_only + report.skipped.values().sum::<u64>()
        );
        // The undecodable answer: imported, with no addresses and no rcode (unknown,
        // not NOERROR).
        let row: (String, String, String, Option<String>) = store
            .conn()
            .query_row(
                "SELECT type, answers, outcome, rcode FROM queries WHERE domain = 'nx.example'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap();
        assert_eq!(row, ("HTTPS".into(), "".into(), "allowed".into(), None));
        let raw: i64 = one(&store, "SELECT count(*) FROM raw_queries");
        assert_eq!(raw, 6);
    }

    /// Pruning is serve's job, with the deployed retention; the import's own raw_days
    /// only decides which rows stay raw, and the report says where that cut fell.
    #[test]
    fn import_does_not_prune() {
        let mut store = memory();
        let old = record(NOW - 40 * DAY_MS, "10.9.0.9", "kept.example");
        store.insert_for_test(&[old]);
        let report = sample(&store);
        let kept: i64 = one(
            &store,
            "SELECT count(*) FROM queries WHERE domain = 'kept.example'",
        );
        assert_eq!(kept, 1, "a raw row older than the window is left to serve");
        assert_eq!(report.raw_from_ms, CUT);
        assert!(report.to_string().contains(&CUT.to_string()), "{report}");
    }

    #[test]
    fn second_import_refused() {
        let store = memory();
        sample(&store);
        let err = import_adguard(SAMPLE.as_bytes(), &store, NOW + 1, RAW_DAYS)
            .expect_err("a second import must be refused");
        assert!(format!("{err:#}").contains("already"), "{err:#}");
        let raw: i64 = one(&store, "SELECT count(*) FROM raw_queries");
        assert_eq!(raw, 6, "the refused import wrote nothing");

        // --force clears the mark; the rows are then counted again, as asked.
        store.forget_adguard_import().unwrap();
        sample(&store);
        let raw: i64 = one(&store, "SELECT count(*) FROM raw_queries");
        assert_eq!(raw, 12);
    }

    fn line(ts_ms: i64, client: &str) -> String {
        // An ISO time in UTC; AdGuard writes +05:30, which parse_time_ms handles too.
        let secs = ts_ms.div_euclid(1000);
        let days = secs.div_euclid(86_400);
        let (y, m, d) = civil(days);
        let s = secs.rem_euclid(86_400);
        format!(
            r#"{{"T":"{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{:03}Z","QH":"r.example","QT":"A","QC":"IN","CP":"","Answer":"","IP":"{client}","Result":{{}},"Elapsed":1000}}"#,
            s / 3600,
            s / 60 % 60,
            s % 60,
            ts_ms.rem_euclid(1000)
        )
    }

    /// Days since 1970-01-01 to (year, month, day), the inverse of days_from_civil.
    fn civil(z: i64) -> (i64, i64, i64) {
        let z = z + 719_468;
        let era = z.div_euclid(146_097);
        let doe = z - era * 146_097;
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let d = doy - (153 * mp + 2) / 5 + 1;
        let m = if mp < 10 { mp + 3 } else { mp - 9 };
        (yoe + era * 400 + i64::from(m <= 2), m, d)
    }

    /// Ruling 1: every imported line is counted exactly once in hourly and in daily,
    /// whichever way it got there: straight into the rollups (older than the cut), as a
    /// raw row behind the marks (rolled up in its batch), or as a raw row ahead of them
    /// (rolled up by the scheduled rollup). None of it is live traffic, so the live
    /// counters stay at zero.
    #[test]
    fn rollups_count_every_line_once() {
        let store = memory();
        // 2026-11-25 10:30 IST: today's 00:00-10:00 hours are closed, the IST day is not.
        let now = NOW + 10 * HOUR_MS + 30 * 60_000;
        let cut = now - i64::from(RAW_DAYS) * DAY_MS;
        let mut times = vec![cut - 2 * DAY_MS, cut - DAY_MS, cut - HOUR_MS, cut - 1];
        times.extend([cut, cut + 1, now - 5 * DAY_MS, now - 5 * DAY_MS + 7]);
        times.extend([NOW + 2 * HOUR_MS, NOW + 2 * HOUR_MS + 1]);
        times.extend([now - 10_000, now - 5_000]);
        let input: String = times
            .iter()
            .enumerate()
            .map(|(i, &t)| line(t, &format!("10.9.0.{}", i % 3)) + "\n")
            .collect();
        let report = import_in_batches(input.as_bytes(), &store, now, RAW_DAYS, 3).unwrap();
        assert_eq!(
            (report.lines, report.rolled_up_only, report.raw),
            (12, 4, 8)
        );

        let sums = |store: &Store| -> (i64, i64) {
            store
                .conn()
                .query_row(
                    "SELECT (SELECT sum(n) FROM hourly_counts), (SELECT sum(n) FROM daily_counts)",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .unwrap()
        };
        // Still open: the current hour's two rows, and today's four for daily.
        assert_eq!(sums(&store), (10, 8));

        rollup::roll_up(&store, now + 2 * DAY_MS).unwrap();
        let totals: (i64, i64, i64, i64) = store
            .conn()
            .query_row(
                "SELECT (SELECT sum(n) FROM hourly_counts), (SELECT sum(n) FROM daily_counts),
                        (SELECT value FROM counters WHERE name = 'log_late'),
                        (SELECT value FROM counters WHERE name = 'queries_total')",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap();
        assert_eq!(totals, (12, 12, 0, 0));
    }

    /// The import shares the file with a live writer that commits far more often than
    /// the real one (every 1 s at most). Each side waits for the lock instead of failing,
    /// and each leaves gaps the other gets in through, so neither errors.
    #[test]
    fn import_and_live_writer_share_the_database() {
        let db = TempDb::new("import-busy");
        let store = Store::open(&db.0).unwrap();
        let done = Arc::new(AtomicBool::new(false));
        let path = db.0.clone();
        let flag = Arc::clone(&done);
        let other = std::thread::spawn(move || -> rusqlite::Result<u32> {
            let mut conn = rusqlite::Connection::open(path)?;
            conn.busy_timeout(Duration::from_secs(5))?;
            let mut commits = 0;
            while !flag.load(Ordering::Relaxed) {
                let t = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
                t.execute(
                    "INSERT INTO rule_texts (list_id, text) VALUES (9, ?1)",
                    [commits.to_string()],
                )?;
                std::thread::sleep(Duration::from_millis(20));
                t.commit()?;
                commits += 1;
                std::thread::sleep(Duration::from_millis(30));
            }
            Ok(commits)
        });
        std::thread::sleep(Duration::from_millis(50));
        let input: String = (0..40)
            .map(|i| line(NOW - HOUR_MS + i, "10.9.0.1") + "\n")
            .collect();
        let report = import_in_batches(input.as_bytes(), &store, NOW, RAW_DAYS, 5).unwrap();
        done.store(true, Ordering::Relaxed);
        let commits = other.join().unwrap().unwrap();
        assert_eq!(report.raw, 40);
        assert!(commits > 0);
        let n: i64 = one(&store, "SELECT count(*) FROM rule_texts WHERE list_id = 9");
        assert_eq!(n, i64::from(commits));
    }

    #[test]
    fn times_are_rfc3339_to_unix_ms() {
        for (text, ms) in [
            // AdGuard's own spelling: nanoseconds and the house offset.
            ("2026-09-09T05:54:28.96330461+05:30", 1_788_913_468_963),
            ("2026-09-09T00:24:28.963Z", 1_788_913_468_963),
            ("2024-02-29T23:59:59.5-01:00", 1_709_254_799_500),
            ("2026-11-24T18:30:00Z", 1_795_545_000_000),
            ("1969-12-31T23:59:59.999Z", -1),
        ] {
            assert_eq!(parse_time_ms(text), Some(ms), "{text}");
        }
        for bad in [
            "",
            "2026-13-01T00:00:00Z",
            "2026-09-09 05:54:28Z",
            "2026-09-09T05:54:28+0530",
            "2026-09-09T05:54:28.+05:30",
            "2026-09-09T05:54:28",
            "2026-09-09T05:54:28Zjunk",
            "2026-09-09T24:00:00Z",
        ] {
            assert_eq!(parse_time_ms(bad), None, "{bad:?}");
        }
    }

    /// Every QT the real log has, including the RFC 3597 spelling for a type without a
    /// mnemonic.
    #[test]
    fn qtypes_from_the_real_log() {
        let names = [
            "A", "AAAA", "CNAME", "HINFO", "HTTPS", "MX", "NAPTR", "NS", "PTR", "SOA", "SRV",
            "SVCB", "TXT", "TYPE11",
        ];
        let codes: Vec<Option<u16>> = names.iter().map(|n| qtype_code(n)).collect();
        let want = [1, 28, 5, 13, 65, 15, 35, 2, 12, 6, 33, 64, 16, 11].map(Some);
        assert_eq!(codes, want);
        assert_eq!(qtype_code("BOGUS"), None);
    }
}
