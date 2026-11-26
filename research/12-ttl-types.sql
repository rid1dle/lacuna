-- name: after the reload: which record types are still asked
SELECT type, count(*) AS n, group_concat(strftime('%H:%M:%S', ts/1000, 'unixepoch'), ' ') AS times
FROM queries WHERE client = '192.168.0.196' AND domain = 'dit.whatsapp.net' AND ts >= 1795680406000 GROUP BY type
