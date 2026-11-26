-- Starter queries for targets.md. Each block is one target's first look, not its answer.
-- Run: see research/README.md (ask.py). Times are shown in IST (UTC + 5:30).

-- name: t1 lookups that went through the router, per IST day, last 14 days
SELECT strftime('%Y-%m-%d', (hour_ts + 19800000) / 1000, 'unixepoch') AS day_ist,
       sum(CASE WHEN client = '192.168.0.1' THEN n ELSE 0 END) AS via_router,
       sum(n) AS total,
       round(100.0 * sum(CASE WHEN client = '192.168.0.1' THEN n ELSE 0 END) / sum(n), 1) AS pct_via_router
FROM hourly
WHERE hour_ts >= (strftime('%s', 'now') - 14 * 86400) * 1000
GROUP BY day_ist ORDER BY day_ist

-- name: t1 silent stretches: minutes in a row with no lookup logged at all, last 7 days
WITH mins AS (
  SELECT DISTINCT ts / 60000 AS minute FROM queries
  WHERE ts >= (strftime('%s', 'now') - 7 * 86400) * 1000
), gaps AS (
  SELECT minute, minute - lag(minute) OVER (ORDER BY minute) AS gap FROM mins
)
SELECT strftime('%Y-%m-%d %H:%M', (minute - gap) * 60 + 19800, 'unixepoch') AS silent_from_ist,
       gap - 1 AS silent_minutes
FROM gaps WHERE gap > 2 ORDER BY gap DESC LIMIT 20

-- name: t2 blocked lookups per IST hour and record type, MacBookAir, last 2 days
SELECT strftime('%Y-%m-%d %H:00', (ts + 19800000) / 1000, 'unixepoch') AS hour_ist, type, count(*) AS n
FROM queries
WHERE device = 'MacBookAir' AND outcome = 'blocked'
  AND ts >= (strftime('%s', 'now') - 2 * 86400) * 1000
GROUP BY hour_ist, type ORDER BY hour_ist, type

-- name: t2 most repeated blocked names since the SOA fix (26 Nov, 14:04 IST)
SELECT device, domain, type, count(*) AS n
FROM queries
WHERE outcome = 'blocked' AND ts >= strftime('%s', '2026-11-26 08:34:11') * 1000
GROUP BY device, domain, type ORDER BY n DESC LIMIT 15

-- name: t3 failed lookups per IST hour: which kind, and how many devices at once, last 7 days
SELECT strftime('%Y-%m-%d %H:00', (ts + 19800000) / 1000, 'unixepoch') AS hour_ist,
       CASE WHEN upstream IS NULL THEN 'no upstream answered' ELSE 'name failed' END AS kind,
       count(*) AS n, count(DISTINCT client) AS devices
FROM queries
WHERE rcode = 'SERVFAIL' AND ts >= (strftime('%s', 'now') - 7 * 86400) * 1000
GROUP BY hour_ist, kind ORDER BY hour_ist

-- name: t4 share of each device's lookups that were blocked, last 7 days
SELECT device, sum(n) AS total,
       sum(CASE WHEN outcome = 'blocked' THEN n ELSE 0 END) AS blocked,
       round(100.0 * sum(CASE WHEN outcome = 'blocked' THEN n ELSE 0 END) / sum(n), 1) AS pct_blocked
FROM daily
WHERE day >= date('now', '-7 day')
GROUP BY device HAVING sum(n) >= 100 ORDER BY pct_blocked DESC

-- name: t5 who asks for what between 02:00 and 05:00 IST, last 7 days
SELECT device, domain, outcome, count(*) AS n
FROM queries
WHERE ts >= (strftime('%s', 'now') - 7 * 86400) * 1000
  AND CAST(strftime('%H', (ts + 19800000) / 1000, 'unixepoch') AS INTEGER) BETWEEN 2 AND 4
GROUP BY device, domain, outcome ORDER BY n DESC LIMIT 25

-- name: t6 where answers came from and how long they took, last 24 hours
SELECT served_from, count(*) AS n,
       round(100.0 * count(*) / (SELECT count(*) FROM queries WHERE ts >= (strftime('%s', 'now') - 86400) * 1000), 1) AS pct,
       round(avg(latency_ms), 2) AS avg_ms,
       round(100.0 * sum(latency_ms < 1) / count(*), 1) AS pct_under_1ms,
       round(max(latency_ms), 0) AS max_ms
FROM queries
WHERE ts >= (strftime('%s', 'now') - 86400) * 1000
GROUP BY served_from ORDER BY n DESC
