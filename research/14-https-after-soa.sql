-- name: MacBookAir dit.whatsapp.net by type, since the SOA restart (08:34:11 UTC)
SELECT type, count(*) AS n, group_concat(strftime('%H:%M:%S', ts/1000, 'unixepoch'), ' ') AS times
FROM queries WHERE client = '192.168.0.196' AND domain = 'dit.whatsapp.net' AND ts >= 1795682051000 GROUP BY type
