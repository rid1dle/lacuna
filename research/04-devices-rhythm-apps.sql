-- name: what are the unnamed devices (top names, 7 days)
SELECT client, domain, count(*) AS n FROM (
  SELECT client, domain, row_number() OVER (PARTITION BY client ORDER BY count(*) DESC) AS rk, count(*) AS c
  FROM queries WHERE ts >= :d7 AND client IN ('192.168.0.117', '192.168.0.145', '192.168.0.171', '192.168.0.180')
  GROUP BY client, domain) x JOIN queries USING (client, domain)
WHERE rk <= 5 AND ts >= :d7 GROUP BY client, domain ORDER BY client, n DESC
-- name: hour-of-day rhythm (IST), phones and laptops, 7 days, share of each device's day
SELECT device, (((hour_ts + 19800000) / 3600000) % 24) AS ist_hour, sum(n) AS n
FROM hourly WHERE hour_ts >= :d7 AND client IN ('192.168.0.175', '192.168.0.196', '192.168.0.100', '192.168.0.136')
GROUP BY client, ist_hour ORDER BY device, ist_hour
-- name: app families per device, 7 days (rough screen-time proxy: distinct 5-minute buckets)
SELECT device, app, count(DISTINCT ts / 300000) AS active_5min, count(*) AS n FROM (
  SELECT device, ts, CASE
    WHEN domain LIKE '%whatsapp%' THEN 'WhatsApp'
    WHEN domain LIKE '%instagram%' OR domain LIKE '%cdninstagram%' THEN 'Instagram'
    WHEN domain LIKE '%googlevideo.com' OR domain LIKE '%youtube%' OR domain LIKE '%ytimg%' THEN 'YouTube'
    WHEN domain LIKE '%netflix%' OR domain LIKE '%nflx%' THEN 'Netflix'
    WHEN domain LIKE '%pv-cdn.net' OR domain LIKE '%primevideo%' OR domain LIKE '%aiv-%' THEN 'Prime Video'
    WHEN domain LIKE '%spotify%' THEN 'Spotify'
    WHEN domain LIKE '%slack%' THEN 'Slack'
    WHEN domain LIKE '%twimg%' OR domain LIKE '%twitter%' OR domain = 'x.com' OR domain LIKE '%.x.com' THEN 'X'
    WHEN domain LIKE '%reddit%' OR domain LIKE '%redd.it' THEN 'Reddit'
    WHEN domain LIKE '%hotstar%' OR domain LIKE '%jiocinema%' THEN 'Hotstar'
    END AS app
  FROM queries WHERE ts >= :d7 AND client NOT IN ('192.168.224.1', '192.168.0.107', '127.0.0.1')
) WHERE app IS NOT NULL GROUP BY device, app HAVING active_5min >= 20 ORDER BY active_5min DESC LIMIT 25
-- name: weekly trend since September (daily rollup), per week
SELECT strftime('%Y-%W', (day_ts + 19800000) / 1000, 'unixepoch') AS week, sum(n) AS n,
       round(100.0 * sum(CASE WHEN outcome = 'blocked' THEN n ELSE 0 END) / sum(n), 1) AS blocked_pct,
       count(DISTINCT client) AS devices, count(DISTINCT domain) AS names
FROM daily GROUP BY week ORDER BY week
-- name: upstream speed and share, 7 days
SELECT coalesce(upstream, '(none)') AS upstream, served_from, count(*) AS n,
       round(avg(latency_ms), 1) AS avg_ms, round(max(latency_ms)) AS max_ms
FROM queries WHERE ts >= :d7 AND served_from IN ('upstream', 'fallback') GROUP BY 1, 2 ORDER BY n DESC
