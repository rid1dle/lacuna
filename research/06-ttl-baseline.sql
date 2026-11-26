-- name: blocked storm lookups per hour (UTC), last 6 hours
SELECT strftime('%m-%d %H', ts/1000, 'unixepoch') AS hour_utc, device, domain, count(*) AS n
FROM queries WHERE ts >= :now - 6 * 3600000 AND outcome = 'blocked'
  AND domain IN ('dit.whatsapp.net', 'extension.femetrics.grammarly.io', 'slackb.com', 'f-log-extension.grammarly.io')
GROUP BY 1, 2, 3 ORDER BY 1, n DESC
-- name: all blocked lookups per hour (UTC), last 6 hours
SELECT strftime('%m-%d %H', ts/1000, 'unixepoch') AS hour_utc, count(*) AS blocked, 
       (SELECT count(*) FROM queries q2 WHERE q2.ts >= :now - 6 * 3600000 AND strftime('%m-%d %H', q2.ts/1000, 'unixepoch') = strftime('%m-%d %H', q.ts/1000, 'unixepoch')) AS total
FROM queries q WHERE ts >= :now - 6 * 3600000 AND outcome = 'blocked' GROUP BY 1 ORDER BY 1
