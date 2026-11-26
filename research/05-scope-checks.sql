-- name: what 127.0.0.1 and 172.20.0.1 ask, 7 days
SELECT client, domain, type, count(*) AS n FROM queries
WHERE ts >= :d7 AND client IN ('127.0.0.1', '172.20.0.1') GROUP BY 1, 2, 3 ORDER BY n DESC LIMIT 12
-- name: test traffic rows to remove (raw, hourly, daily)
SELECT (SELECT count(*) FROM queries WHERE client = '192.168.224.1') AS raw_rows,
       (SELECT sum(n) FROM hourly WHERE client = '192.168.224.1') AS hourly_n,
       (SELECT sum(n) FROM daily WHERE client = '192.168.224.1') AS daily_n,
       (SELECT strftime('%Y-%m-%d %H:%M', min(ts)/1000, 'unixepoch') FROM queries WHERE client = '192.168.224.1') AS first_utc,
       (SELECT strftime('%Y-%m-%d %H:%M', max(ts)/1000, 'unixepoch') FROM queries WHERE client = '192.168.224.1') AS last_utc
-- name: 224.1 after the shadow run (anything real?)
SELECT strftime('%m-%d %H:%M', ts/1000, 'unixepoch') AS utc, domain, type FROM queries
WHERE client = '192.168.224.1' AND ts >= 1795618800000 ORDER BY ts LIMIT 30
-- name: retry gap of the top blocked storms vs blocked answer TTL, 24 h
SELECT device, domain, type, count(*) AS n FROM queries
WHERE ts >= :d1 AND outcome = 'blocked' AND domain IN ('dit.whatsapp.net', 'extension.femetrics.grammarly.io', 'slackb.com')
GROUP BY 1, 2, 3 ORDER BY n DESC
