-- sieve's query log, schema version 1.
--
-- Tables are internal: they may change between releases. The VIEWS at the bottom are
-- the public contract that Sonder's dashboards query with their own SQL. A view change
-- that breaks old SQL bumps schema_version.
--
-- Times are unix milliseconds, UTC. Enum columns hold the integer codes from
-- src/codes.rs; the views turn them into labels. The label expressions in braces are
-- generated from those Rust enums when the schema is applied (store::schema_sql), so
-- each label has one definition.

CREATE TABLE meta (
    key   TEXT PRIMARY KEY,
    value
);

CREATE TABLE counter_values (
    name  TEXT PRIMARY KEY,
    value INTEGER NOT NULL
);

CREATE TABLE domain_names (
    id   INTEGER PRIMARY KEY,
    name TEXT UNIQUE NOT NULL
);

CREATE TABLE list_meta (
    id           INTEGER PRIMARY KEY,
    name         TEXT,
    url          TEXT,
    enabled      INTEGER,
    parsed       INTEGER,
    skipped_json TEXT,
    fetched_at   INTEGER,
    last_error   TEXT
);

-- list_id 0 is the user rules from config.toml.
CREATE TABLE rule_texts (
    id      INTEGER PRIMARY KEY,
    list_id INTEGER NOT NULL,
    text    TEXT NOT NULL,
    UNIQUE (list_id, text)
);

-- Every client the writer has seen. name and origin ('config' or 'ptr') stay NULL
-- until a name is known.
CREATE TABLE client_names (
    ip         TEXT PRIMARY KEY,
    name       TEXT,
    origin     TEXT,
    first_seen INTEGER NOT NULL,
    last_seen  INTEGER NOT NULL
);

-- answers: A/AAAA addresses joined by commas; '' when the response had none.
CREATE TABLE raw_queries (
    ts          INTEGER NOT NULL,
    client      TEXT NOT NULL,
    domain_id   INTEGER NOT NULL,
    qtype       INTEGER NOT NULL,
    rcode       INTEGER NOT NULL,
    outcome     INTEGER NOT NULL,
    reason      INTEGER NOT NULL,
    rule_id     INTEGER,
    served_from INTEGER NOT NULL,
    upstream    TEXT,
    latency_us  INTEGER NOT NULL,
    answers     TEXT,
    source      INTEGER NOT NULL
);
CREATE INDEX raw_queries_ts ON raw_queries (ts);
CREATE INDEX raw_queries_client_ts ON raw_queries (client, ts);

CREATE TABLE hourly_counts (
    hour_ms        INTEGER NOT NULL,
    client         TEXT NOT NULL,
    outcome        INTEGER NOT NULL,
    n              INTEGER NOT NULL,
    latency_us_sum INTEGER NOT NULL,
    PRIMARY KEY (hour_ms, client, outcome)
);

-- day: house day number in IST, (ts + 19800000) / 86400000.
-- rule_id 0 means no rule: SQLite treats NULLs in a primary key as distinct, so a
-- NULL would let the rollup's upsert add duplicate rows instead of summing.
CREATE TABLE daily_counts (
    day       INTEGER NOT NULL,
    client    TEXT NOT NULL,
    domain_id INTEGER NOT NULL,
    outcome   INTEGER NOT NULL,
    rule_id   INTEGER NOT NULL,
    n         INTEGER NOT NULL,
    PRIMARY KEY (day, client, domain_id, outcome, rule_id)
);

INSERT INTO meta (key, value) VALUES ('schema_version', 1);
-- queries_total counts every query handled, logged or dropped.
INSERT INTO counter_values (name, value) VALUES ('log_dropped', 0), ('queries_total', 0);

-- Public views (schemaVersion 1) ----------------------------------------------------

CREATE VIEW queries AS
SELECT
    q.ts,
    strftime('%Y-%m-%dT%H:%M:%fZ', q.ts / 1000.0, 'unixepoch') AS time,
    q.client,
    coalesce(c.name, q.client) AS device,
    d.name AS domain,
    {type_label} AS type,
    {outcome_label} AS outcome,
    {reason_label} AS reason,
    r.text AS rule,
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
    strftime('%Y-%m-%d', dc.day * 86400, 'unixepoch') AS day,
    dc.day * 86400000 - 19800000 AS day_ts,
    dc.client,
    coalesce(c.name, dc.client) AS device,
    d.name AS domain,
    {outcome_label} AS outcome,
    r.text AS rule,
    {list_name} AS list,
    dc.n
FROM daily_counts dc
LEFT JOIN domain_names d ON d.id = dc.domain_id
LEFT JOIN client_names c ON c.ip = dc.client
LEFT JOIN rule_texts r ON r.id = dc.rule_id
LEFT JOIN list_meta l ON l.id = r.list_id;

CREATE VIEW devices AS
SELECT ip AS client, coalesce(name, ip) AS device, origin, first_seen, last_seen
FROM client_names;

CREATE VIEW lists AS
SELECT id, name, url, enabled, parsed, skipped_json, fetched_at, last_error
FROM list_meta;

CREATE VIEW rules AS
SELECT r.id, {list_name} AS list, r.text
FROM rule_texts r
LEFT JOIN list_meta l ON l.id = r.list_id;

CREATE VIEW counters AS
SELECT name, value FROM counter_values;
