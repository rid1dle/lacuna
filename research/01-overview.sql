-- name: history span (daily rollup) and raw span
SELECT (SELECT min(day) FROM daily) AS first_day, (SELECT max(day) FROM daily) AS last_day,
       (SELECT count(DISTINCT day) FROM daily) AS days,
       (SELECT sum(n) FROM daily) AS daily_total,
       (SELECT strftime('%Y-%m-%d', min(ts)/1000, 'unixepoch') FROM queries) AS raw_from
-- name: devices, last 7 days (hourly)
SELECT device, client, sum(n) AS n,
       round(100.0 * sum(CASE WHEN outcome = 'blocked' THEN n ELSE 0 END) / sum(n), 1) AS blocked_pct
FROM hourly WHERE hour_ts >= :d7 GROUP BY client ORDER BY n DESC
-- name: devices known (devices view)
SELECT client, device, origin, strftime('%Y-%m-%d', first_seen_ts/1000, 'unixepoch') AS first_seen,
       strftime('%Y-%m-%d %H:%M', last_seen_ts/1000, 'unixepoch') AS last_seen
FROM devices ORDER BY last_seen_ts DESC
-- name: outcome and reason, 7 days raw
SELECT outcome, reason, served_from, count(*) AS n FROM queries WHERE ts >= :d7
GROUP BY 1, 2, 3 ORDER BY n DESC
-- name: record types, 7 days
SELECT type, count(*) AS n FROM queries WHERE ts >= :d7 GROUP BY type ORDER BY n DESC LIMIT 12
-- name: rcode, 7 days
SELECT rcode, count(*) AS n FROM queries WHERE ts >= :d7 GROUP BY rcode ORDER BY n DESC
