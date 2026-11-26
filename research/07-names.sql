-- name: device names after reload
SELECT client, device, origin FROM devices WHERE origin = 'config' ORDER BY client
