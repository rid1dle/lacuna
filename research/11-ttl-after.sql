-- name: dit.whatsapp.net from MacBookAir: before (06:46-08:06 UTC) vs after the reload at 08:06:46 UTC
SELECT CASE WHEN ts < 1795680406000 THEN 'before (80 min)' ELSE 'after' END AS period,
       count(*) AS n, round((max(ts) - min(ts)) / 60000.0, 1) AS span_min,
       strftime('%H:%M:%S', max(ts)/1000, 'unixepoch') AS last_utc
FROM queries WHERE client = '192.168.0.196' AND domain = 'dit.whatsapp.net' AND ts >= 1795675606000
GROUP BY 1
