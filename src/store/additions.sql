-- Internal objects added after schema version 1 shipped. Run at every open, so a
-- database made by an older build gets them at its next start. Each is IF NOT EXISTS
-- and nothing older reads them, so going back to an older build needs no migration
-- (SQLite keeps an index it does not know about up to date by itself).

-- The domain lookups panel: the newest queries of a few domain ids. client makes the
-- index cover the panel's first pass, which finds the cutoff time without reading rows.
CREATE INDEX IF NOT EXISTS raw_queries_domain_ts ON raw_queries (domain_id, ts, client);

-- The rule_texts ids in the live rule set, replaced at every swap. rule_texts keeps
-- every rule ever loaded, so this is what tells a rule still in force from one its
-- list (or the config) has since dropped.
CREATE TABLE IF NOT EXISTS live_rules (
    id INTEGER PRIMARY KEY
);
