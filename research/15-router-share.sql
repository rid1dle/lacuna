-- name: lookups arriving through the router (OpenWrt) vs all, per hour (UTC), last 12 h
SELECT strftime('%m-%d %H', hour_ts/1000, 'unixepoch') AS hour_utc,
       sum(CASE WHEN client = '192.168.0.1' THEN n ELSE 0 END) AS via_router, sum(n) AS total,
       round(100.0 * sum(CASE WHEN client = '192.168.0.1' THEN n ELSE 0 END) / sum(n), 1) AS router_pct
FROM hourly WHERE hour_ts >= :now - 12 * 3600000 GROUP BY hour_ts ORDER BY hour_ts
