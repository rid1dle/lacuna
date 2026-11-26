-- name: SERVFAIL, 7 days: did an upstream answer, and for which names
SELECT CASE WHEN upstream IS NULL THEN 'no upstream answered' ELSE 'upstream said SERVFAIL' END AS kind,
       served_from, source, domain, count(*) AS n, count(DISTINCT client) AS devices
FROM queries WHERE ts >= :d7 AND rcode = 'SERVFAIL' GROUP BY 1, 2, 3, 4 ORDER BY n DESC LIMIT 15
-- name: the two spike hours (Nov 23 21:00, Nov 24 19:00 UTC)
SELECT strftime('%m-%d %H', ts/1000, 'unixepoch') AS hour_utc, domain, device, upstream, source, count(*) AS n
FROM queries WHERE rcode = 'SERVFAIL' AND ((ts >= 1795467600000 AND ts < 1795471200000) OR (ts >= 1795546800000 AND ts < 1795550400000))
GROUP BY 1, 2, 3, 4, 5 ORDER BY n DESC LIMIT 10
-- name: lookups where no upstream answered, by day and source
SELECT strftime('%m-%d', ts/1000, 'unixepoch') AS day, source, rcode, count(*) AS n, round(avg(latency_ms)) AS avg_ms
FROM queries WHERE ts >= :d7 AND served_from = 'upstream' AND upstream IS NULL GROUP BY 1, 2, 3 ORDER BY 1
-- name: upstream labels by source (7 days)
SELECT source, upstream, count(*) AS n FROM queries WHERE ts >= :d7 AND upstream IS NOT NULL GROUP BY 1, 2 ORDER BY n DESC
