-- name: raw rows the delete removes
SELECT count(*) AS raw_rows, min(ts) AS first_ts, max(ts) AS last_ts FROM raw_queries
WHERE client = '192.168.224.1' AND ts < 1795620000000
-- name: hourly groups: what is subtracted vs what is there
WITH w AS (SELECT ts - ts % 3600000 AS hour_ms, outcome, count(*) AS n, sum(latency_us) AS lat
           FROM raw_queries WHERE client = '192.168.224.1' AND ts < 1795620000000 GROUP BY 1, 2)
SELECT count(*) AS groups, sum(w.n) AS subtract_n, sum(h.n) AS have_n,
       sum(CASE WHEN h.n IS NULL OR h.n < w.n OR h.latency_us_sum < w.lat THEN 1 ELSE 0 END) AS short_groups,
       sum(CASE WHEN h.n = w.n THEN 1 ELSE 0 END) AS groups_emptied
FROM w LEFT JOIN hourly_counts h ON h.hour_ms = w.hour_ms AND h.client = '192.168.224.1' AND h.outcome = w.outcome
-- name: daily groups: what is subtracted vs what is there
WITH w AS (SELECT (ts + 19800000) / 86400000 * 86400000 - 19800000 AS day_ts, domain_id, outcome,
                  coalesce(rule_id, 0) AS rule_id, count(*) AS n
           FROM raw_queries WHERE client = '192.168.224.1' AND ts < 1795620000000 GROUP BY 1, 2, 3, 4)
SELECT count(*) AS groups, sum(w.n) AS subtract_n, sum(d.n) AS have_n,
       sum(CASE WHEN d.n IS NULL OR d.n < w.n THEN 1 ELSE 0 END) AS short_groups,
       sum(CASE WHEN d.n = w.n THEN 1 ELSE 0 END) AS groups_emptied
FROM w LEFT JOIN daily_counts d ON d.day_ts = w.day_ts AND d.client = '192.168.224.1'
  AND d.domain_id = w.domain_id AND d.outcome = w.outcome AND d.rule_id = w.rule_id
-- name: what stays for .224.1 after the delete
SELECT count(*) AS raw_rows_kept, min(strftime('%m-%d %H:%M', ts/1000, 'unixepoch')) AS first_kept_utc
FROM raw_queries WHERE client = '192.168.224.1' AND ts >= 1795620000000
