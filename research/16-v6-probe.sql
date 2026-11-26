-- name: who lacuna recorded for the IPv6 probe
SELECT time, client, device, domain, type FROM queries WHERE domain = 'v6probe-1795683158.example'
