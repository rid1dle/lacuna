-- sieve's public views, schemaVersion 1: the contract Sonder's dashboards query with
-- their own SQL. A change that breaks old SQL bumps schema_version.
--
-- Every open drops and recreates these from the running build, so the labels always
-- match its enums. Expressions in braces are filled in from Rust (store::views_sql):
-- code labels from src/codes.rs, list names, and time constants.
--
-- Conventions:
-- * Every unix millisecond column ends in _ts.
-- * Indexed filters: queries.ts, queries.client with queries.ts, hourly.hour_ts and
--   daily.day_ts. Bound a query by one of these; other filters scan within that range.
-- * device and list are live joins on client_names and list_meta, looked up at query
--   time: renaming a device or a list relabels its history.
-- * list_id 0 is the user rules from config.toml, named 'user rules'.
-- * answers: A/AAAA addresses joined by commas, '' when the response had none.
-- * counters: queries_total counts every query handled, logged or dropped;
--   log_dropped counts records lost (channel full or a failed write); log_late counts
--   rows that reached the log after their hour or day was rolled up (they are added to
--   the rollups when written).

CREATE VIEW queries AS
SELECT
    q.ts,
    strftime('%Y-%m-%dT%H:%M:%fZ', q.ts / 1000.0, 'unixepoch') AS time,
    q.client,
    coalesce(c.name, q.client) AS device,
    d.name AS domain,
    {type_label} AS type,
    {rcode_label} AS rcode,
    {outcome_label} AS outcome,
    {reason_label} AS reason,
    r.text AS rule,
    r.list_id,
    {list_name} AS list,
    {served_from_label} AS served_from,
    q.upstream,
    q.latency_us / 1000.0 AS latency_ms,
    q.answers,
    {source_label} AS source
FROM raw_queries q
LEFT JOIN domain_names d ON d.id = q.domain_id
LEFT JOIN client_names c ON c.ip = q.client
LEFT JOIN rule_texts r ON r.id = q.rule_id
LEFT JOIN list_meta l ON l.id = r.list_id;

CREATE VIEW hourly AS
SELECT
    h.hour_ms AS hour_ts,
    h.client,
    coalesce(c.name, h.client) AS device,
    {outcome_label} AS outcome,
    h.n,
    h.latency_us_sum / 1000.0 / h.n AS avg_latency_ms
FROM hourly_counts h
LEFT JOIN client_names c ON c.ip = h.client;

CREATE VIEW daily AS
SELECT
    strftime('%Y-%m-%d', (dc.day_ts + {ist_offset_ms}) / 1000, 'unixepoch') AS day,
    dc.day_ts,
    dc.client,
    coalesce(c.name, dc.client) AS device,
    d.name AS domain,
    {outcome_label} AS outcome,
    r.text AS rule,
    r.list_id,
    {list_name} AS list,
    dc.n
FROM daily_counts dc
LEFT JOIN domain_names d ON d.id = dc.domain_id
LEFT JOIN client_names c ON c.ip = dc.client
LEFT JOIN rule_texts r ON r.id = dc.rule_id
LEFT JOIN list_meta l ON l.id = r.list_id;

CREATE VIEW devices AS
SELECT
    ip AS client,
    coalesce(name, ip) AS device,
    origin,
    first_seen AS first_seen_ts,
    last_seen AS last_seen_ts
FROM client_names;

CREATE VIEW lists AS
SELECT id, name, url, enabled, parsed, skipped_json, fetched_at AS fetched_ts, last_error
FROM list_meta;

CREATE VIEW rules AS
SELECT r.id, r.list_id, {list_name} AS list, r.text
FROM rule_texts r
LEFT JOIN list_meta l ON l.id = r.list_id;

CREATE VIEW counters AS
SELECT name, value FROM counter_values;
