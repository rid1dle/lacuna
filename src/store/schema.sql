-- sieve's query log tables, schema version 1. Created once, for a new database.
--
-- Tables are internal: they may change between releases. The public contract is the
-- views in views.sql. Times are unix milliseconds, UTC. Enum columns hold the integer
-- codes from src/codes.rs; the views turn them into labels.

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
-- until a name is known. named_at (unix ms) is when a PTR lookup last ran, found or not,
-- so a client with no name is asked again only after a day.
CREATE TABLE client_names (
    ip         TEXT PRIMARY KEY,
    name       TEXT,
    origin     TEXT,
    named_at   INTEGER,
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

-- day_ts: the IST midnight that starts the house day, stored rather than computed so
-- range filters on it use the primary key.
-- rule_id 0 means no rule: SQLite treats NULLs in a primary key as distinct, so a
-- NULL would let the rollup's upsert add duplicate rows instead of summing.
CREATE TABLE daily_counts (
    day_ts    INTEGER NOT NULL,
    client    TEXT NOT NULL,
    domain_id INTEGER NOT NULL,
    outcome   INTEGER NOT NULL,
    rule_id   INTEGER NOT NULL,
    n         INTEGER NOT NULL,
    PRIMARY KEY (day_ts, client, domain_id, outcome, rule_id)
);

INSERT INTO meta (key, value) VALUES ('schema_version', 1);
