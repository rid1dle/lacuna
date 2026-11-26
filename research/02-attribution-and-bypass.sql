-- name: 224.1 by hour (UTC) since it appeared
SELECT strftime('%m-%d %H', hour_ts/1000, 'unixepoch') AS hour_utc, sum(n) AS n
FROM hourly WHERE client = '192.168.224.1' GROUP BY hour_ts ORDER BY hour_ts
-- name: 224.1 top domains, 2 days
SELECT domain, count(*) AS n FROM queries WHERE client = '192.168.224.1' AND ts >= :now - 2 * 86400000
GROUP BY domain ORDER BY n DESC LIMIT 15
-- name: router .1 top domains, 7 days
SELECT domain, count(*) AS n FROM queries WHERE client = '192.168.0.1' AND ts >= :d7
GROUP BY domain ORDER BY n DESC LIMIT 12
-- name: homelab top domains, 7 days
SELECT domain, count(*) AS n FROM queries WHERE client = '192.168.0.107' AND ts >= :d7
GROUP BY domain ORDER BY n DESC LIMIT 12
-- name: DNS bypass signals, 30 days (encrypted DNS / private relay canaries)
SELECT device, domain, outcome, count(*) AS n FROM queries
WHERE ts >= :d30 AND (domain IN ('mask.icloud.com', 'mask-h2.icloud.com', 'mask-api.icloud.com',
   'use-application-dns.net', 'dns.google', 'dns.google.com', 'cloudflare-dns.com',
   'chrome.cloudflare-dns.com', 'mozilla.cloudflare-dns.com', 'dns.quad9.net', 'doh.opendns.com',
   'dns.nextdns.io', 'one.one.one.one', 'dns.adguard-dns.com', 'doh.dns.apple.com', 'dns11.quad9.net')
   OR domain LIKE '%.dns.nextdns.io')
GROUP BY device, domain, outcome ORDER BY n DESC LIMIT 30
