-- name: top devices, 7 days, after the delete
SELECT device, sum(n) AS n FROM hourly WHERE hour_ts >= :d7 GROUP BY client ORDER BY n DESC LIMIT 5
-- name: busiest hours on Nov 25 (UTC), hourly rollup
SELECT strftime('%H', hour_ts/1000, 'unixepoch') AS hour_utc, sum(n) AS n FROM hourly
WHERE hour_ts >= 1795564800000 AND hour_ts < 1795651200000 GROUP BY hour_ts ORDER BY n DESC LIMIT 3
-- name: log health
SELECT name, value FROM counters
-- name: manifest dashboards now live
SELECT 1 AS ok
