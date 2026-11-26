# lacuna integration contract

This is the HTTP API that lacuna serves for Sonder (or any other consumer). It is the
only thing the two share. Sonder reads lacuna's data through it, shows lacuna's default
dashboards, runs user-written SQL, and triggers runtime actions.

- Base URL: `http://lacuna:8053` on the internal `lacuna-api` network.
- Contract version: `schemaVersion` 1 (see [Versioning](#versioning)).
- All bodies are JSON (`Content-Type: application/json`), field names in camelCase.

## Calls at a glance

| Call | Purpose |
|---|---|
| `GET /integration/manifest` | What lacuna offers: views, variables, dashboards, actions |
| `POST /integration/query` | Run one read-only SQL query, get a frame of rows |
| `POST /integration/actions/{id}` | Run a runtime action (pause, resume, ...) |

## Authentication

Every request, including unknown paths, carries:

```
Authorization: Bearer <secret>
```

The secret is a file mounted into lacuna (default `/run/secrets/lacuna_api`, set by
`api.secret_file`), read once at startup. Surrounding whitespace, such as a trailing
newline, is ignored. The comparison runs in constant time.

| Situation | Status | Body |
|---|---|---|
| lacuna has no secret (file missing or empty) | 503 | `{"error":"api secret not configured"}` |
| No `Authorization` header | 401 | `{"error":"missing bearer token"}` |
| Wrong token, or not the `Bearer` scheme | 401 | `{"error":"wrong bearer token"}` |

With no secret configured lacuna refuses every request (fail closed); DNS keeps working.
A new secret takes effect at the next restart of lacuna.

## Errors

Every error is a JSON object with one field, `error`, holding a message meant for a
person. Status codes:

| Status | When |
|---|---|
| 400 | The request or the SQL is at fault: bad JSON, unknown fields, bad SQL, a write attempt, a limit passed, the time limit reached |
| 401 | Missing or wrong bearer token |
| 404 | Unknown path or unknown action id |
| 429 | `{"error":"busy"}`: no query slot came free within 2 seconds |
| 500 | A bug in lacuna |
| 503 | No secret configured; or, on `/integration/query` only, the query log could not open |

An action that runs but does not succeed (bad parameter, failed fetch) is not an HTTP
error: it answers 200 with `"ok": false`.

## GET /integration/manifest

Describes everything else. It never changes while lacuna runs; fetch it on page load,
or cache it until lacuna restarts. It also serves as the "is lacuna up" check: there is no
separate status call.

Request:

```
GET /integration/manifest HTTP/1.1
Host: lacuna:8053
Authorization: Bearer 7f3c9a...
```

Response `200`, abridged: the real one lists all eight views with every column, both
variables, all seven dashboards with every panel, and all five actions. Each part's
shape is shown in full once.

```json
{
  "name": "lacuna",
  "version": "0.1.0",
  "schemaVersion": 1,
  "maxConcurrent": 2,
  "schema": [
    {
      "name": "queries",
      "kind": "view",
      "description": "Every query handled, kept 30 days. Bound it by ts, or by client with ts, which are indexed.",
      "columns": [
        { "name": "ts", "type": "integer", "description": "When the query arrived, unix ms UTC" },
        { "name": "domain", "type": "text", "description": "Name asked for, lowercase, no trailing dot" },
        { "name": "latency_ms", "type": "real", "description": "Time to answer, milliseconds" }
      ]
    }
  ],
  "variables": [
    {
      "id": "client",
      "label": "Device",
      "type": "text",
      "optionsSql": "SELECT client AS value, device AS label FROM devices ORDER BY label"
    },
    { "id": "domain", "label": "Domain", "type": "text" }
  ],
  "dashboards": [
    {
      "id": "overview",
      "title": "Overview",
      "variables": ["client"],
      "panels": [
        {
          "id": "blocked_pct",
          "title": "Blocked %",
          "kind": "stat",
          "sql": "-- [lo, hi): whole hours read from the hourly rollup. ...\nWITH lo AS (\n  ...\n),\nhi AS (\n  ...\n)\nSELECT\n  round(100.0 * sum(CASE WHEN outcome = 'blocked' THEN n ELSE 0 END)\n        / nullif(sum(n), 0), 1) AS blocked_pct,\n  coalesce(sum(n), 0) AS queries\nFROM (\n  ...\n)",
          "layout": { "x": 0, "y": 8, "w": 4, "h": 4 },
          "options": { "y": "blocked_pct" }
        }
      ]
    }
  ],
  "actions": [
    {
      "id": "pause",
      "label": "Pause blocking",
      "params": [ { "id": "minutes", "label": "Minutes", "type": "int", "min": 1, "max": 1440 } ]
    },
    { "id": "resume", "label": "Resume blocking", "params": [] }
  ]
}
```

`maxConcurrent` is how many queries lacuna runs at once; see [Limits](#limits). It was
added within `schemaVersion` 1, so treat it as optional and assume 1 when absent.

### schema

The public views, which are the only surface SQL should be written against. Each view
has a `description` and its `columns` in order, each with a `type` of `integer`, `real`
or `text`. lacuna's internal tables (`raw_queries`, `hourly_counts`, ...) are readable
too, but they may change in any release without notice; the views do not change within
a `schemaVersion`.

The eight views in version 1:

| View | Rows | Bound it by (indexed) |
|---|---|---|
| `queries` | every query, kept 30 days | `ts`, `client` with `ts`, or `domain_id` with `ts` |
| `hourly` | counts per hour, client and outcome, kept a year | `hour_ts` |
| `daily` | counts per IST day, client, domain, outcome and rule, kept a year | `day_ts` |
| `devices` | every client seen, with its name | (small) |
| `lists` | filter lists from the config, with their last fetch | (small) |
| `rules` | every rule text ever loaded; `live` is 1 for the rules in force now | (scanned) |
| `domains` | every name ever asked for, with the `id` that `queries.domain_id` holds | `name` |
| `counters` | running totals: `queries_total`, `log_dropped`, `log_late` | (small) |

Conventions in the views:

- Every unix millisecond column ends in `_ts` (UTC). `queries.time` is the same instant
  as ISO 8601 text.
- House days are Asia/Kolkata (UTC+05:30, no DST). `daily.day_ts` is the IST midnight
  that starts the day, `daily.day` its `YYYY-MM-DD` label.
- `device` and `list` are looked up when the query runs: renaming a device or a list
  relabels its history.
- `list_id` 0 is the user rules from lacuna's config, named `user rules`.
- `answers` is the A/AAAA addresses sent, comma separated, `''` when there were none.
- `rcode` is NULL when the response code is unknown: only imported AdGuard history
  whose stored answer could not be decoded (`source` `adguard`). Count by
  `rcode IS NULL` rather than reading it as NOERROR.
- `upstream` names the upstream that answered. It is NULL for cache hits and local
  answers (imported history included) and when no upstream answered.

**Never create views in lacuna's database.** At every start lacuna drops every view in
the database file, its own and any other, and recreates its own. A view added by
anyone else is silently lost at the next restart. (The query API cannot create one
anyway; this is for anyone opening the file directly.)

### variables

Variables are values the user picks on a dashboard and SQL reads as `:id`.

- `client` (label "Device"): its `optionsSql` lists the choices; run it through
  `/integration/query` like any panel and offer its rows, `value` to bind and `label`
  to show.
- `domain` (label "Domain"): free text, no `optionsSql`. lacuna lowercases it where it is
  used; the user may type `Example.com`.

A dashboard's `variables` lists the ids it shows pickers for.

### dashboards and panels

| Field | Meaning |
|---|---|
| `id` | Stable id. Dashboard ids: `overview`, `devices`, `domains`, `rules`, `live`, `background`, `health` |
| `title` | For people |
| `variables` | Variable ids to show pickers for |
| `panels[].kind` | `stat`, `timeseries`, `bar`, `table` or `log` |
| `panels[].sql` | One read-only statement, run through `/integration/query` |
| `panels[].layout` | `{ x, y, w, h }` on a 12-column grid; `x + w <= 12`; `h` is in rows of the consumer's choosing |
| `panels[].options` | Which result columns play which role (below) |

Option roles, each naming a result column (absent roles are not set):

| Kind | Roles | Drawing |
|---|---|---|
| `stat` | `y` | The `y` value of the first row. `null` means "no data", not 0 |
| `timeseries` | `x`, `y`, `series` (optional) | `x` is unix ms; one line per distinct `series` value |
| `bar` | `label`, `y`, `series` (optional) | One bar per `label`; `series` splits each bar |
| `table` | none | Every column, in order |
| `log` | none | Every column, newest rows first, as lacuna returns them |

Any kind may also carry `refreshSeconds`: redraw that often while the page is open.
In version 1 only `live.recent` sets it (5).

Default panels count exactly the queries in `[from, to)`. Up to 24 hours they read the
raw `queries` view (5-minute buckets for time series). Longer ranges read the `hourly`
or `daily` rollups only for whole hours or IST days inside the range that are already
rolled up, and raw rows for the partial hour or day at the start and everything after
the last whole rolled-up bucket (time series use hourly buckets up to 7 days, IST days
beyond). Nothing is missed or counted twice. One approximation: when `from` is older
than the raw rows kept (30 days), the hour or day holding `from` is counted whole.
Panels whose title says "last N days at most" read raw rows only, and only the last N
days of the range: 30 (raw retention) for the domain lookups, 7 for cache hit % and
upstream latency, which aggregate raw rows and timed out over a month under DNS load.
Each default panel's SQL starts with comment lines explaining this, so a cloned panel
keeps the explanation.

### actions

Each action has an `id` (used in the URL), a `label`, and `params`, each with an `id`,
`label`, `type` (`int` or `text`) and, for `int`, optional `min` and `max`.

## POST /integration/query

Runs one read-only SQL statement against lacuna's log and returns the rows.

Request body:

| Field | Type | Meaning |
|---|---|---|
| `sql` | string | Exactly one statement; trailing whitespace and comments are fine |
| `params` | object | Values for the `:name` parameters in the SQL (optional) |

Parameters:

- Only the `:name` style; `?`, `?1`, `@name` and `$name` are refused.
- A value is an integer, a string, or `null`. Floats, booleans, arrays and objects are
  refused.
- Values are bound, never pasted into the SQL text, so quotes in them are harmless.
- A parameter the SQL uses but `params` lacks is a 400 (`parameter :x has no value`).
  Parameters the SQL does not use are ignored.

**What to bind.** On every panel query and every `optionsSql`, bind:

- `from` and `to`: the dashboard's time range as unix ms UTC, half open
  (`from <= ts < to`). For a relative range such as "last 24 hours", recompute both at
  each refresh, so `to` is now.
- every variable in the manifest's `variables`, by its `id`, as the chosen value or
  `null` when nothing is chosen (default panels read `null` as "all").

Request:

```
POST /integration/query HTTP/1.1
Host: lacuna:8053
Authorization: Bearer 7f3c9a...
Content-Type: application/json

{
  "sql": "SELECT outcome, count(*) AS n FROM queries WHERE ts >= :from AND ts < :to AND (:client IS NULL OR client = :client) GROUP BY outcome ORDER BY n DESC",
  "params": { "from": 1795546800000, "to": 1795633200000, "client": null, "domain": null }
}
```

Response `200` (the counts are illustrative):

```json
{
  "columns": [
    { "name": "outcome", "type": "text" },
    { "name": "n", "type": "integer" }
  ],
  "rows": [
    ["allowed", 131204],
    ["blocked", 11573],
    ["rewritten", 2210]
  ],
  "truncated": false,
  "elapsedMs": 412
}
```

The frame:

| Field | Meaning |
|---|---|
| `columns` | Result columns in order. `type` is that of the column's first non-null value: `integer`, `real`, `text`, or `null` when every value is null or there are no rows |
| `rows` | Arrays in column order. Blobs appear as the text `"<blob N bytes>"`; an infinite or NaN real as `null` |
| `truncated` | `true` when the query had more rows than the row cap; `rows` then holds exactly the cap |
| `elapsedMs` | Time the query took in lacuna, milliseconds |

The body is streamed as it is written (chunked). Read it to the end before parsing. If
it does not parse, treat the call as failed: a body cut short is the only sign of a
fault in lacuna once a 200 has been sent.

Errors, all `400` unless noted:

| Cause | Example `error` |
|---|---|
| Not JSON, an unknown field | ``bad request body: unknown field `extra`, expected `sql` or `params` at line 1 column 8`` |
| No `sql` | `the request has no sql` |
| A param of the wrong type | `bad request body: an integer, text or null at line 1 column 19` |
| Anything but reading | `only reading is allowed, refused: Delete { table_name: "raw_queries" }` |
| More than one statement | `only one statement is allowed` |
| A parameter with no value | `parameter :client has no value` |
| SQL error | `no such column: domian in SELECT domian FROM queries at offset 7` |
| Too many function calls | `the query calls more than 64 functions` |
| Result too big | `result passed 8388608 bytes; select fewer rows or columns` |
| Time limit | `query stopped at the time limit of 5000 ms` |
| No query slot free in 2 s (429) | `busy` |
| Query log could not open (503) | `log store unavailable: <reason>` |

### Limits

| Limit | Value | Past it |
|---|---|---|
| Request body | 256 KiB | 400 |
| SQL text | 100,000 bytes | 400 (`statement too long` from SQLite) |
| Rows | 10,000 (`api.row_cap`) | `truncated: true`, not an error |
| One value (string or blob) | 16 KiB, read or built | 400 (`string or blob too big`) |
| Columns | 100 | 400 (`too many columns in result set`) |
| Whole result | 8 MiB, counted as rows are read (32 bytes per value plus its text) | 400 |
| Function references in the SQL | 64 (calls inside the views do not count) | 400 |
| Time | 5 s (`api.query_timeout_ms`), approximate | 400 |
| Queries at once | 2 (`api.max_concurrent`, sent as the manifest's `maxConcurrent`) | wait up to 2 s, then 429 `busy` |

The time limit is checked between steps of SQLite's work, and one step can be one long
function call, so a hostile query can overrun it. The worst measured: 64 expensive calls
in one row ran 1.07 s against a 200 ms limit. Expect a query to end within the limit
plus about 1.2 s.

A query holds its slot until its whole response has been sent, so read the body
promptly. A client that takes no data for 30 s has the response cut off (it will not
parse) and the slot freed. Set the consumer's HTTP timeout for this call to at least
15 s (2 s queueing + 5 s limit + overrun + transfer).

Queries run on their own threads, at most `maxConcurrent` (from the manifest) at a
time, and never hold up DNS. Send at most `maxConcurrent` queries at once: a dashboard
with more panels than that should queue its panel queries rather than fire them all.
On 429 `busy`, retry that query after a backoff (for example 0.5 s, then 1 s, then
2 s), and give up and show the error after a few tries.

## POST /integration/actions/{id}

Runs a runtime action. Durable settings live in lacuna's `config.toml`; actions only act
on the running process (a pause does not survive a restart).

Request body: `{ "params": { ... } }`. An empty body is the same as no params.

Response `200`: `{ "ok": <bool>, "message": <text for a person> }`. `ok: false` means
the action did not do what was asked; the message says why. An unknown action id is a
404.

| id | params | What it does |
|---|---|---|
| `pause` | `minutes`: int, 1 to 1440 | Stops filtering rules for that long. Rewrites and refused names still apply |
| `resume` | none | Ends a pause |
| `refresh_lists` | none | Fetches every enabled list now and rebuilds the rules. Waits for the fetch (up to 30 s per list) |
| `reload_config` | none | Re-reads `config.toml`; see below |
| `test_domain` | `name`: text | Says which refused names, rewrites and rules match the name now (CNAME targets are not followed) |

`reload_config` applies the lists, user rules, rewrites, refused names, blocked TTL and
device names, rebuilding the rules from the list copies on disk. A list that is new to
the running config (added, enabled, or moved to another URL) has no usable copy yet:
those are fetched in the background, the message ends with `; refreshing N new lists`,
and they block once the fetch is done (seconds; up to 30 s per list). If the file does
not load or fails validation, nothing changes and the answer is `ok: false` with the
error. `[upstreams]`, `dns.listen`, `dns.max_inflight`, `dns.router`, `dns.neighbors` and the `[api]` and
`[store]` sections need a restart.

`test_domain` checks the name itself in DNS order: refused names, rewrites, then the
rules. It does not resolve the name, so a block that DNS would make on a CNAME target
does not show. Messages:
`allowed`, `allowed by <rule> (<list>)`, `blocked by <rule> (<list>)`,
`answered <ip> by <rule> (<list>)`, `rewritten to <ip>`,
`refused: lacuna never answers this name`. During a pause a blocking verdict reads
`allowed: blocking is paused (otherwise blocked by ...)`.

Set the consumer's HTTP timeout for actions to at least 2 minutes (`refresh_lists`
waits for the network).

### Examples

Pause:

```
POST /integration/actions/pause HTTP/1.1
Host: lacuna:8053
Authorization: Bearer 7f3c9a...
Content-Type: application/json

{ "params": { "minutes": 30 } }
```

```json
{ "ok": true, "message": "blocking paused for 30 minutes" }
```

The same with `"minutes": 0`:

```json
{ "ok": false, "message": "minutes must be a whole number from 1 to 1440" }
```

Resume (no body needed):

```
POST /integration/actions/resume HTTP/1.1
Host: lacuna:8053
Authorization: Bearer 7f3c9a...
```

```json
{ "ok": true, "message": "blocking resumed" }
```

Refresh lists:

```
POST /integration/actions/refresh_lists HTTP/1.1
Host: lacuna:8053
Authorization: Bearer 7f3c9a...
```

```json
{ "ok": true, "message": "lists refreshed (swapped: true): list 1: parsed 193886 skipped 661" }
```

`ok` is false when any enabled list failed to fetch; that list keeps its last good copy.

Reload config:

```
POST /integration/actions/reload_config HTTP/1.1
Host: lacuna:8053
Authorization: Bearer 7f3c9a...
```

```json
{ "ok": true, "message": "config reloaded: 2 lists, 0 user rules, 2 rewrites, 0 device names. [upstreams], dns.listen, dns.max_inflight, dns.router, dns.neighbors and the [api] and [store] sections apply at the next restart." }
```

With a broken file:

```json
{ "ok": false, "message": "config not reloaded, the running one stays: in /config/config.toml: TOML parse error at line 1, column 6\n  |\n1 | this is not toml\n  |      ^\nkey with no value, expected `=`\n" }
```

Test a domain:

```
POST /integration/actions/test_domain HTTP/1.1
Host: lacuna:8053
Authorization: Bearer 7f3c9a...
Content-Type: application/json

{ "params": { "name": "ads.adnet.com" } }
```

```json
{ "ok": true, "message": "blocked by ||adnet.com^ (AdGuard DNS filter)" }
```

## Versioning

`schemaVersion` versions the views. Within one version, SQL written against the views
keeps working. A change that breaks such SQL (removing or renaming a view or a column,
changing what a column means or its unit) bumps `schemaVersion`. Adding a view or a
column does not.

The consumer stores, with every panel it saves, the `schemaVersion` it was written
against, and shows which saved panels are older than the current one. Default
dashboards are read live from the manifest, so they always match.

`version` is lacuna's build version, for display only.
