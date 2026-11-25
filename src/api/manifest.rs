//! The manifest: what Sonder needs to show lacuna's data without knowing lacuna. The public
//! views with their columns, the variables, the default dashboards (SQL panels written
//! against the views only) and the actions.
//!
//! Every panel's SQL is a standalone query a user may clone and edit. In this source
//! the range prelude shared by several panels is a macro, but the text shipped is whole.
//!
//! Time ranges are exact, half open `[:from, :to)`. Up to 24 hours, panels read the raw
//! `queries` view. Longer ranges read the `hourly` or `daily` rollup only for whole
//! buckets inside the range that are rolled up (`[lo, hi)`), and raw rows for the
//! partial bucket at the start and everything from `hi` on. `hi` is capped at the
//! rollup's edge, `max(hour_ts) + 1 hour` (or `max(day_ts) + 1 day`); every raw row
//! after it is still in the log, since rollups lag by at most a day and raw rows are
//! kept 30 days. Only when raw rows no longer reach back to `:from` (past raw
//! retention) is the leading bucket taken whole from the rollup, an overcount of at
//! most one bucket. Each part is one index range: `lo` and `hi` are constant
//! subqueries, so the `ts`, `hour_ts` and `day_ts` indexes bound every scan.

use serde::Serialize;

/// Bumped when a view changes in a way that breaks SQL written against the old one.
pub const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Manifest {
    pub name: &'static str,
    pub version: &'static str,
    pub schema_version: u32,
    /// Queries lacuna runs at once (`api.max_concurrent`); more wait, then get 429.
    pub max_concurrent: usize,
    pub schema: Vec<View>,
    pub variables: Vec<Variable>,
    pub dashboards: Vec<Dashboard>,
    pub actions: Vec<Action>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct View {
    pub name: &'static str,
    pub kind: &'static str,
    pub description: &'static str,
    pub columns: Vec<ViewColumn>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ViewColumn {
    pub name: &'static str,
    /// "integer", "real" or "text".
    pub r#type: &'static str,
    pub description: &'static str,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Variable {
    pub id: &'static str,
    pub label: &'static str,
    pub r#type: &'static str,
    /// Rows of `value` and `label` to choose from; absent means free text.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options_sql: Option<&'static str>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Dashboard {
    pub id: &'static str,
    pub title: &'static str,
    /// The variable ids this dashboard shows pickers for.
    pub variables: Vec<&'static str>,
    pub panels: Vec<Panel>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Panel {
    pub id: &'static str,
    pub title: &'static str,
    /// "stat", "timeseries", "bar", "table" or "log".
    pub kind: &'static str,
    pub sql: &'static str,
    pub layout: Layout,
    pub options: Options,
}

/// A place on a 12-column grid; `h` is in rows of the consumer's choosing.
#[derive(Debug, Serialize)]
pub struct Layout {
    pub x: u32,
    pub y: u32,
    pub w: u32,
    pub h: u32,
}

/// Which result columns play which role in the drawing.
#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Options {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub y: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub series: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_seconds: Option<u32>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Action {
    pub id: &'static str,
    pub label: &'static str,
    pub params: Vec<ActionParam>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ActionParam {
    pub id: &'static str,
    pub label: &'static str,
    /// "int" or "text".
    pub r#type: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max: Option<i64>,
}

/// Bounds of the pause action's `minutes`: one minute to one day.
pub const PAUSE_MINUTES: (i64, i64) = (1, 1440);

/// The actions, by the id in their URL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionId {
    Pause,
    Resume,
    RefreshLists,
    ReloadConfig,
    TestDomain,
}

impl ActionId {
    pub const ALL: [ActionId; 5] = [
        ActionId::Pause,
        ActionId::Resume,
        ActionId::RefreshLists,
        ActionId::ReloadConfig,
        ActionId::TestDomain,
    ];

    pub fn id(self) -> &'static str {
        match self {
            ActionId::Pause => "pause",
            ActionId::Resume => "resume",
            ActionId::RefreshLists => "refresh_lists",
            ActionId::ReloadConfig => "reload_config",
            ActionId::TestDomain => "test_domain",
        }
    }

    pub fn from_id(id: &str) -> Option<ActionId> {
        ActionId::ALL.into_iter().find(|a| a.id() == id)
    }
}

pub fn manifest(max_concurrent: usize) -> Manifest {
    Manifest {
        name: "lacuna",
        version: env!("CARGO_PKG_VERSION"),
        schema_version: SCHEMA_VERSION,
        max_concurrent,
        schema: schema(),
        variables: vec![
            Variable {
                id: "client",
                label: "Device",
                r#type: "text",
                options_sql: Some(
                    "SELECT client AS value, device AS label FROM devices ORDER BY label",
                ),
            },
            Variable {
                id: "domain",
                label: "Domain",
                r#type: "text",
                options_sql: None,
            },
        ],
        dashboards: dashboards(),
        actions: vec![
            Action {
                id: ActionId::Pause.id(),
                label: "Pause blocking",
                params: vec![ActionParam {
                    id: "minutes",
                    label: "Minutes",
                    r#type: "int",
                    min: Some(PAUSE_MINUTES.0),
                    max: Some(PAUSE_MINUTES.1),
                }],
            },
            Action {
                id: ActionId::Resume.id(),
                label: "Resume blocking",
                params: vec![],
            },
            Action {
                id: ActionId::RefreshLists.id(),
                label: "Refresh filter lists",
                params: vec![],
            },
            Action {
                id: ActionId::ReloadConfig.id(),
                label: "Reload config",
                params: vec![],
            },
            Action {
                id: ActionId::TestDomain.id(),
                label: "Test a domain",
                params: vec![ActionParam {
                    id: "name",
                    label: "Domain",
                    r#type: "text",
                    min: None,
                    max: None,
                }],
            },
        ],
    }
}

const fn col(name: &'static str, r#type: &'static str, description: &'static str) -> ViewColumn {
    ViewColumn {
        name,
        r#type,
        description,
    }
}

fn schema() -> Vec<View> {
    vec![
        View {
            name: "queries",
            kind: "view",
            description: "Every query handled, kept 30 days. Bound it by ts, \
                          or by client with ts, which are indexed.",
            columns: vec![
                col("ts", "integer", "When the query arrived, unix ms UTC"),
                col("time", "text", "ts as ISO 8601 UTC text"),
                col("client", "text", "Client IP address"),
                col(
                    "device",
                    "text",
                    "Device name, or the IP when none is known",
                ),
                col(
                    "domain",
                    "text",
                    "Name asked for, lowercase, no trailing dot",
                ),
                col(
                    "type",
                    "text",
                    "Record type: A, AAAA, HTTPS, ... or TYPE<n>",
                ),
                col(
                    "rcode",
                    "text",
                    "Response code: NOERROR, NXDOMAIN, ... or RCODE<n>; NULL when unknown",
                ),
                col("outcome", "text", "allowed, blocked, rewritten or refused"),
                col(
                    "reason",
                    "text",
                    "none, rule, cname, refused_name or any_query",
                ),
                col("rule", "text", "Text of the rule that decided, if any"),
                col(
                    "list_id",
                    "integer",
                    "List of that rule; 0 is the user rules",
                ),
                col("list", "text", "Name of that list"),
                col(
                    "served_from",
                    "text",
                    "cache, stale_cache, upstream, fallback or local",
                ),
                col(
                    "upstream",
                    "text",
                    "Upstream that answered, if one was asked",
                ),
                col("latency_ms", "real", "Time to answer, milliseconds"),
                col("answers", "text", "A/AAAA addresses sent, comma separated"),
                col("source", "text", "lacuna, or adguard for imported history"),
            ],
        },
        View {
            name: "hourly",
            kind: "view",
            description: "Query counts per hour, client and outcome, kept a year. \
                          Bound it by hour_ts (indexed).",
            columns: vec![
                col("hour_ts", "integer", "Start of the hour, unix ms UTC"),
                col("client", "text", "Client IP address"),
                col(
                    "device",
                    "text",
                    "Device name, or the IP when none is known",
                ),
                col("outcome", "text", "allowed, blocked, rewritten or refused"),
                col("n", "integer", "Queries"),
                col(
                    "avg_latency_ms",
                    "real",
                    "Average time to answer, milliseconds",
                ),
            ],
        },
        View {
            name: "daily",
            kind: "view",
            description: "Query counts per IST day, client, domain, outcome and rule, \
                          kept a year. Bound it by day_ts (indexed).",
            columns: vec![
                col("day", "text", "The IST day, YYYY-MM-DD"),
                col(
                    "day_ts",
                    "integer",
                    "IST midnight starting the day, unix ms UTC",
                ),
                col("client", "text", "Client IP address"),
                col(
                    "device",
                    "text",
                    "Device name, or the IP when none is known",
                ),
                col("domain", "text", "Name asked for"),
                col("outcome", "text", "allowed, blocked, rewritten or refused"),
                col("rule", "text", "Text of the rule that decided, if any"),
                col(
                    "list_id",
                    "integer",
                    "List of that rule; 0 is the user rules",
                ),
                col("list", "text", "Name of that list"),
                col("n", "integer", "Queries"),
            ],
        },
        View {
            name: "devices",
            kind: "view",
            description: "Every client seen, with its name.",
            columns: vec![
                col("client", "text", "Client IP address"),
                col(
                    "device",
                    "text",
                    "Device name, or the IP when none is known",
                ),
                col(
                    "origin",
                    "text",
                    "Where the name came from: config or ptr; null if none",
                ),
                col("first_seen_ts", "integer", "First query, unix ms UTC"),
                col("last_seen_ts", "integer", "Latest query, unix ms UTC"),
            ],
        },
        View {
            name: "lists",
            kind: "view",
            description: "Filter lists from the config, with their last fetch.",
            columns: vec![
                col("id", "integer", "List id from the config"),
                col("name", "text", "List name"),
                col("url", "text", "Where it is fetched from"),
                col("enabled", "integer", "1 when enabled"),
                col("parsed", "integer", "Rules in force from it"),
                col(
                    "skipped_json",
                    "text",
                    "Lines skipped, by reason, as a JSON object",
                ),
                col(
                    "fetched_ts",
                    "integer",
                    "Last successful fetch, unix ms UTC",
                ),
                col(
                    "last_error",
                    "text",
                    "Error of the last fetch, if it failed",
                ),
            ],
        },
        View {
            name: "rules",
            kind: "view",
            description: "Rule texts of every list that has been loaded, and user rules \
                          that have decided a query.",
            columns: vec![
                col("id", "integer", "Rule id"),
                col("list_id", "integer", "List id; 0 is the user rules"),
                col("list", "text", "List name"),
                col("text", "text", "The rule as written"),
            ],
        },
        View {
            name: "counters",
            kind: "view",
            description: "Running totals since the log was created: queries_total, \
                          log_dropped (records lost before the log), log_late.",
            columns: vec![
                col("name", "text", "Counter name"),
                col("value", "integer", "Count"),
            ],
        },
    ]
}

const fn at(x: u32, y: u32, w: u32, h: u32) -> Layout {
    Layout { x, y, w, h }
}

fn timeseries(x: &'static str, y: &'static str, series: Option<&'static str>) -> Options {
    Options {
        x: Some(x),
        y: Some(y),
        series,
        ..Options::default()
    }
}

fn bar(label: &'static str, y: &'static str, series: Option<&'static str>) -> Options {
    Options {
        label: Some(label),
        y: Some(y),
        series,
        ..Options::default()
    }
}

fn stat(y: &'static str) -> Options {
    Options {
        y: Some(y),
        ..Options::default()
    }
}

fn dashboards() -> Vec<Dashboard> {
    vec![
        Dashboard {
            id: "overview",
            title: "Overview",
            variables: vec!["client"],
            panels: vec![
                Panel {
                    id: "queries_over_time",
                    title: "Queries over time",
                    kind: "timeseries",
                    sql: QUERIES_OVER_TIME,
                    layout: at(0, 0, 12, 8),
                    options: timeseries("ts", "n", Some("outcome")),
                },
                Panel {
                    id: "blocked_pct",
                    title: "Blocked %",
                    kind: "stat",
                    sql: BLOCKED_PCT,
                    layout: at(0, 8, 4, 4),
                    options: stat("blocked_pct"),
                },
                Panel {
                    id: "cache_hit_rate",
                    title: "Cache hit % (last 7 days at most)",
                    kind: "stat",
                    sql: CACHE_HIT_RATE,
                    layout: at(4, 8, 4, 4),
                    options: stat("cache_hit_pct"),
                },
                Panel {
                    id: "log_dropped",
                    title: "Log records dropped (all time)",
                    kind: "stat",
                    sql: LOG_DROPPED,
                    layout: at(8, 8, 4, 4),
                    options: stat("dropped"),
                },
                Panel {
                    id: "upstream_latency",
                    title: "Upstream latency, ms (last 7 days at most)",
                    kind: "timeseries",
                    sql: UPSTREAM_LATENCY,
                    layout: at(0, 12, 12, 8),
                    options: timeseries("ts", "avg_ms", None),
                },
            ],
        },
        Dashboard {
            id: "devices",
            title: "Devices",
            variables: vec!["client"],
            panels: vec![
                Panel {
                    id: "by_device",
                    title: "Queries by device",
                    kind: "bar",
                    sql: BY_DEVICE,
                    layout: at(0, 0, 6, 10),
                    options: bar("device", "n", Some("outcome")),
                },
                Panel {
                    id: "device_top_domains",
                    title: "Top domains",
                    kind: "bar",
                    sql: TOP_DOMAINS,
                    layout: at(6, 0, 6, 10),
                    options: bar("domain", "n", None),
                },
                Panel {
                    id: "device_timeline",
                    title: "Queries over time by device",
                    kind: "timeseries",
                    sql: DEVICE_TIMELINE,
                    layout: at(0, 10, 12, 8),
                    options: timeseries("ts", "n", Some("device")),
                },
            ],
        },
        Dashboard {
            id: "domains",
            title: "Domains",
            variables: vec!["client", "domain"],
            panels: vec![
                Panel {
                    id: "top_domains",
                    title: "Top domains",
                    kind: "bar",
                    sql: TOP_DOMAINS,
                    layout: at(0, 0, 6, 10),
                    options: bar("domain", "n", None),
                },
                Panel {
                    id: "top_blocked",
                    title: "Top blocked domains",
                    kind: "bar",
                    sql: TOP_BLOCKED,
                    layout: at(6, 0, 6, 10),
                    options: bar("domain", "n", None),
                },
                Panel {
                    id: "domain_lookups",
                    title: "Lookups of the domain (last 30 days at most)",
                    kind: "table",
                    sql: DOMAIN_LOOKUPS,
                    layout: at(0, 10, 12, 10),
                    options: Options::default(),
                },
            ],
        },
        Dashboard {
            id: "rules",
            title: "Rules",
            variables: vec!["client"],
            panels: vec![
                Panel {
                    id: "lists_table",
                    title: "Filter lists",
                    kind: "table",
                    sql: LISTS_TABLE,
                    layout: at(0, 0, 12, 5),
                    options: Options::default(),
                },
                Panel {
                    id: "top_rules",
                    title: "Top rules",
                    kind: "bar",
                    sql: TOP_RULES,
                    layout: at(0, 5, 6, 10),
                    options: bar("rule", "n", None),
                },
                Panel {
                    id: "never_hit",
                    title: "Rules with no hits in the range (first 500)",
                    kind: "table",
                    sql: NEVER_HIT,
                    layout: at(6, 5, 6, 10),
                    options: Options::default(),
                },
            ],
        },
        Dashboard {
            id: "live",
            title: "Live",
            variables: vec!["client"],
            panels: vec![Panel {
                id: "recent",
                title: "Recent queries",
                kind: "log",
                sql: RECENT,
                layout: at(0, 0, 12, 16),
                options: Options {
                    refresh_seconds: Some(5),
                    ..Options::default()
                },
            }],
        },
    ]
}

macro_rules! hourly_edges {
    () => {
        "\
-- [lo, hi): whole hours read from the hourly rollup. Raw rows cover [:from, lo) and
-- [hi, :to). Up to 24 hours everything is raw. Past raw retention, lo is the hour
-- holding :from, counted whole.
WITH lo AS (
  SELECT CASE
    WHEN :to - :from <= 86400000 THEN :to
    WHEN :from < (SELECT coalesce(min(ts), :to) FROM queries)
      THEN :from - :from % 3600000
    ELSE :from + 3599999 - (:from + 3599999) % 3600000
  END AS ts
),
hi AS (
  SELECT max((SELECT ts FROM lo), min(:to - :to % 3600000,
    (SELECT coalesce(max(hour_ts) + 3600000, 0) FROM hourly))) AS ts
)
"
    };
}

macro_rules! daily_edges {
    () => {
        "\
-- [lo, hi): whole IST days read from the daily rollup. Raw rows cover [:from, lo) and
-- [hi, :to). Up to 24 hours everything is raw. Past raw retention, lo is the day
-- holding :from, counted whole.
WITH lo AS (
  SELECT CASE
    WHEN :to - :from <= 86400000 THEN :to
    WHEN :from < (SELECT coalesce(min(ts), :to) FROM queries)
      THEN :from - (:from + 19800000) % 86400000
    ELSE :from + 86399999 - (:from + 86399999 + 19800000) % 86400000
  END AS ts
),
hi AS (
  SELECT max((SELECT ts FROM lo), min(:to - (:to + 19800000) % 86400000,
    (SELECT coalesce(max(day_ts) + 86400000, 0) FROM daily))) AS ts
)
"
    };
}

/// The three parts of a range for the hourly view: `$cols` from the rollup, `$raw`
/// (the same columns) from raw rows at either end, each with `$filter` added.
macro_rules! hourly_parts {
    ($cols:literal, $raw:literal, $filter:literal) => {
        concat!(
            "  SELECT ",
            $cols,
            "\n  FROM hourly\n",
            "  WHERE hour_ts >= (SELECT ts FROM lo) AND hour_ts < (SELECT ts FROM hi)\n",
            $filter,
            "  UNION ALL\n",
            "  SELECT ",
            $raw,
            "\n  FROM queries\n",
            "  WHERE ts >= :from AND ts < (SELECT ts FROM lo)\n",
            $filter,
            "  UNION ALL\n",
            "  SELECT ",
            $raw,
            "\n  FROM queries\n",
            "  WHERE ts >= (SELECT ts FROM hi) AND ts < :to\n",
            $filter,
        )
    };
}

macro_rules! daily_parts {
    ($cols:literal, $raw:literal, $filter:literal) => {
        concat!(
            "  SELECT ",
            $cols,
            "\n  FROM daily\n",
            "  WHERE day_ts >= (SELECT ts FROM lo) AND day_ts < (SELECT ts FROM hi)\n",
            $filter,
            "  UNION ALL\n",
            "  SELECT ",
            $raw,
            "\n  FROM queries\n",
            "  WHERE ts >= :from AND ts < (SELECT ts FROM lo)\n",
            $filter,
            "  UNION ALL\n",
            "  SELECT ",
            $raw,
            "\n  FROM queries\n",
            "  WHERE ts >= (SELECT ts FROM hi) AND ts < :to\n",
            $filter,
        )
    };
}

// Buckets: 5 minutes up to 24 hours, hours up to 7 days, IST days beyond.
const QUERIES_OVER_TIME: &str = concat!(
    hourly_edges!(),
    "\
SELECT
  CASE
    WHEN :to - :from <= 86400000 THEN t - t % 300000
    WHEN :to - :from <= 604800000 THEN t - t % 3600000
    ELSE t - (t + 19800000) % 86400000
  END AS ts,
  outcome,
  sum(n) AS n
FROM (
",
    hourly_parts!(
        "hour_ts AS t, outcome, n",
        "ts AS t, outcome, 1 AS n",
        "    AND (:client IS NULL OR client = :client)\n"
    ),
    ")
GROUP BY 1, 2
ORDER BY 1, 2"
);

const BLOCKED_PCT: &str = concat!(
    hourly_edges!(),
    "\
SELECT
  round(100.0 * sum(CASE WHEN outcome = 'blocked' THEN n ELSE 0 END)
        / nullif(sum(n), 0), 1) AS blocked_pct,
  coalesce(sum(n), 0) AS queries
FROM (
",
    hourly_parts!(
        "outcome, n",
        "outcome, 1 AS n",
        "    AND (:client IS NULL OR client = :client)\n"
    ),
    ")"
);

// Of the answers not made locally, the share served from the cache.
const CACHE_HIT_RATE: &str = "\
-- Raw rows only, so at most the last 7 days of the range: a month of raw rows is too
-- slow to scan while DNS is busy.
SELECT
  round(100.0 * sum(served_from IN ('cache', 'stale_cache'))
        / nullif(sum(served_from IN ('cache', 'stale_cache', 'upstream', 'fallback')), 0),
        1) AS cache_hit_pct
FROM queries
WHERE ts >= max(:from, :to - 604800000) AND ts < :to
  AND (:client IS NULL OR client = :client)";

// Not tied to the time range or a device: the counter runs since the log was created.
const LOG_DROPPED: &str = "\
SELECT value AS dropped
FROM counters
WHERE name = 'log_dropped'";

const UPSTREAM_LATENCY: &str = "\
-- Raw rows only, so at most the last 7 days of the range: a month of raw rows is too
-- slow to scan while DNS is busy.
SELECT
  CASE
    WHEN :to - :from <= 86400000 THEN ts - ts % 300000
    WHEN :to - :from <= 604800000 THEN ts - ts % 3600000
    ELSE ts - (ts + 19800000) % 86400000
  END AS ts,
  round(avg(latency_ms), 1) AS avg_ms
FROM queries
WHERE ts >= max(:from, :to - 604800000) AND ts < :to
  AND served_from IN ('upstream', 'fallback')
  AND (:client IS NULL OR client = :client)
GROUP BY 1
ORDER BY 1";

const BY_DEVICE: &str = concat!(
    hourly_edges!(),
    "\
SELECT device, outcome, sum(n) AS n
FROM (
",
    hourly_parts!(
        "client, device, outcome, n",
        "client, device, outcome, 1 AS n",
        "    AND (:client IS NULL OR client = :client)\n"
    ),
    ")
GROUP BY client, outcome
ORDER BY device, outcome"
);

const DEVICE_TIMELINE: &str = concat!(
    hourly_edges!(),
    "\
SELECT
  CASE
    WHEN :to - :from <= 86400000 THEN t - t % 300000
    WHEN :to - :from <= 604800000 THEN t - t % 3600000
    ELSE t - (t + 19800000) % 86400000
  END AS ts,
  device,
  sum(n) AS n
FROM (
",
    hourly_parts!(
        "hour_ts AS t, client, device, n",
        "ts AS t, client, device, 1 AS n",
        "    AND (:client IS NULL OR client = :client)\n"
    ),
    ")
GROUP BY 1, client
ORDER BY 1, device"
);

const TOP_DOMAINS: &str = concat!(
    daily_edges!(),
    "\
SELECT domain, sum(n) AS n
FROM (
",
    daily_parts!(
        "domain, n",
        "domain, 1 AS n",
        "    AND (:client IS NULL OR client = :client)\n"
    ),
    ")
GROUP BY domain
ORDER BY n DESC, domain
LIMIT 20"
);

const TOP_BLOCKED: &str = concat!(
    daily_edges!(),
    "\
SELECT domain, sum(n) AS n
FROM (
",
    daily_parts!(
        "domain, n",
        "domain, 1 AS n",
        "    AND outcome = 'blocked'\n    AND (:client IS NULL OR client = :client)\n"
    ),
    ")
GROUP BY domain
ORDER BY n DESC, domain
LIMIT 20"
);

// The chosen domain and its subdomains, newest first; with no domain, every lookup.
// Raw rows only.
const DOMAIN_LOOKUPS: &str = "\
SELECT time, device, domain, type, outcome, rule, list, answers, served_from, latency_ms
FROM queries
WHERE ts >= :from AND ts < :to
  AND (:client IS NULL OR client = :client)
  AND (:domain IS NULL
       OR domain = lower(:domain)
       OR substr(domain, -length(:domain) - 1) = '.' || lower(:domain))
ORDER BY ts DESC
LIMIT 500";

// Not tied to the time range or a device.
const LISTS_TABLE: &str = "\
SELECT id, name, enabled, parsed AS rules, skipped_json AS skipped, fetched_ts, last_error
FROM lists
ORDER BY id";

const TOP_RULES: &str = concat!(
    daily_edges!(),
    "\
SELECT rule, list, sum(n) AS n
FROM (
",
    daily_parts!(
        "rule, list_id, list, n",
        "rule, list_id, list, 1 AS n",
        "    AND rule IS NOT NULL\n    AND (:client IS NULL OR client = :client)\n"
    ),
    ")
GROUP BY list_id, rule
ORDER BY n DESC, rule
LIMIT 20"
);

// MATERIALIZED builds the set of hit rules once; inlined, it would be re-run per rule.
// DISTINCT keeps each hit rule once.
const NEVER_HIT: &str = concat!(
    daily_edges!(),
    ",
hit AS MATERIALIZED (
SELECT DISTINCT list_id, rule
FROM (
",
    daily_parts!(
        "list_id, rule",
        "list_id, rule",
        "    AND rule IS NOT NULL\n    AND (:client IS NULL OR client = :client)\n"
    ),
    "))
SELECT r.list, r.text AS rule
FROM rules r
WHERE NOT EXISTS (SELECT 1 FROM hit h WHERE h.list_id = r.list_id AND h.rule = r.text)
ORDER BY r.list_id, r.id
LIMIT 500"
);

const RECENT: &str = "\
SELECT ts, time, device, domain, type, outcome, rule, served_from, latency_ms
FROM queries
WHERE ts >= :from AND ts < :to
  AND (:client IS NULL OR client = :client)
ORDER BY ts DESC
LIMIT 200";
