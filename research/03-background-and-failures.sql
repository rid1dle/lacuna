-- name: pollers, 24 h: steady intervals per device and domain (median-ish gap)
WITH q AS (
  SELECT device, domain, ts, ts - lag(ts) OVER (PARTITION BY client, domain ORDER BY ts) AS gap
  FROM queries WHERE ts >= :d1 AND client NOT IN ('192.168.224.1', '127.0.0.1')
)
SELECT device, domain, count(*) AS n, round(avg(gap) / 1000.0, 1) AS avg_gap_s,
       round(min(gap) / 1000.0, 1) AS min_s, round(max(gap) / 1000.0, 1) AS max_s
FROM q WHERE gap IS NOT NULL GROUP BY device, domain HAVING n >= 200 ORDER BY n DESC LIMIT 20
-- name: NXDOMAIN top, 7 days
SELECT device, domain, count(*) AS n FROM queries WHERE ts >= :d7 AND rcode = 'NXDOMAIN'
  AND client <> '192.168.224.1' GROUP BY device, domain ORDER BY n DESC LIMIT 15
-- name: SERVFAIL by hour (UTC), 7 days, hours with > 5
SELECT strftime('%m-%d %H', ts/1000, 'unixepoch') AS hour_utc, count(*) AS n, count(DISTINCT domain) AS names
FROM queries WHERE ts >= :d7 AND rcode = 'SERVFAIL' GROUP BY 1 HAVING n > 5 ORDER BY 1
-- name: new names per day (first day seen in the year of rollups), last 14 days
WITH first AS (SELECT domain, min(day_ts) AS d FROM daily GROUP BY domain)
SELECT strftime('%Y-%m-%d', (d + 19800000) / 1000, 'unixepoch') AS day, count(*) AS new_names
FROM first WHERE d >= :now - 14 * 86400000 GROUP BY d ORDER BY d
-- name: CNAME-cloaked blocks, 30 days
SELECT domain, rule, count(*) AS n FROM queries WHERE ts >= :d30 AND reason = 'cname'
GROUP BY domain, rule ORDER BY n DESC LIMIT 10
-- name: blocked retry storms, 24 h (same device asks a blocked name > 300 times)
SELECT device, domain, rule, count(*) AS n FROM queries WHERE ts >= :d1 AND outcome = 'blocked'
GROUP BY client, domain HAVING n > 300 ORDER BY n DESC LIMIT 12
