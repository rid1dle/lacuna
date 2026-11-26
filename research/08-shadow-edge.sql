-- name: .224.1 rows around the cutover (UTC)
SELECT strftime('%H:%M:%f', ts/1000.0, 'unixepoch') AS utc, ts, domain, type, outcome FROM queries
WHERE client = '192.168.224.1' AND ts >= 1795619400000 AND ts < 1795623000000 ORDER BY ts
-- name: .224.1 first rows (UTC)
SELECT strftime('%m-%d %H:%M:%f', ts/1000.0, 'unixepoch') AS utc, ts, domain, type FROM queries
WHERE client = '192.168.224.1' ORDER BY ts LIMIT 10
