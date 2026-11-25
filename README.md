# lacuna

A small ad-blocking DNS server in Rust, built to replace AdGuard Home on this
server. One static binary in a `scratch` image (about 17 MB on disk, 3 MB of RAM
idle), SQLite compiled in, no database server.

What it does: blocks names from AdGuard-syntax filter lists, answers a few local
names itself (`*.home.riddlelab.dev` -> 192.168.0.107), races DoH upstreams
(Quad9, Cloudflare) with plain-DNS fallback, caches, and logs every query to
SQLite. A read-only API on port 8053 (private network `lacuna-api`) serves the
dashboards in Sonder. The wire contract with Sonder is `CONTRACT.md`.

## Commands

```
lacuna serve <config.toml>
lacuna check-config <config.toml>
lacuna ask <name> [type] [--server addr] [--expect ip]
lacuna import-adguard <file|-> [--db path] [--now-ms n] [--force]
lacuna compare --a addr --b addr --names file [--limit n]
```

`ask` exits 1 on a timeout or when `--expect` is not among the answers. The
container healthcheck is exactly that, asking for `home.riddlelab.dev` and
expecting 192.168.0.107. `compare` sends each name (A and AAAA) to both servers
and prints one line per difference: `name type a_outcome b_outcome a_answers
b_answers`, then the totals. Outcome differences (blocked on one side, allowed on
the other) are what matter. Answer differences on allowed names are normal, since
CDNs rotate addresses.

## Test

From this folder. Cargo never runs on the host (no C compiler); it runs in the
`rust:1-alpine` container:

```bash
docker run --rm -v "$PWD":/src -w /src \
  -v lacuna-cargo-registry:/usr/local/cargo/registry -v lacuna-cargo-target:/src/target \
  rust:1-alpine sh -c 'apk add -q musl-dev && cargo test --locked'
```

Add ` -- <filter>` inside the quotes for one test. Tests marked `#[ignore]` hit the
live network: `-- --ignored <name>`.

## Run (shadow mode)

Shadow means lacuna answers on host port 5300 while AdGuard keeps serving :53, so
nothing in the house depends on it yet.

1. Create the network (once): `scripts/provision/networks.sh`. It adds
   `lacuna-api` (192.168.208.0/20, internal) next to the others.
2. Create the data folder, owned by the container user. **It must not exist with
   an older database in it**: the schema changed during development without a
   version bump, so a smoke-test database keeps the old column definitions. If one
   exists, delete `lacuna.db`, `lacuna.db-wal` and `lacuna.db-shm` from
   `/srv/appdata/lacuna/` first.
   ```bash
   sudo install -d -o 3070 -g 3070 -m 0750 /srv/appdata/lacuna
   ```
3. Create the API secret, the same value Sonder is given. The container runs as
   uid 3070 and must be able to read it:
   ```bash
   mkdir -p deploy/secrets
   openssl rand -hex 32 > deploy/secrets/lacuna_api
   sudo chgrp 3070 deploy/secrets/lacuna_api && chmod 0640 deploy/secrets/lacuna_api
   ```
   Compose will not start the container without `deploy/secrets/lacuna_api`. An
   empty file starts fine: every API request then gets 503
   `{"error":"api secret not configured"}` and DNS still works. Sonder reads the
   same value (wired in Sonder's own plan).
4. Build, validate, start (the image must exist before `check-config` can run it):
   ```bash
   cd deploy && docker compose build
   docker run --rm -v "$PWD/config.toml:/c.toml:ro" --entrypoint /lacuna \
     homelab/lacuna:latest check-config /c.toml
   docker compose up -d
   docker compose ps          # "healthy" within about 15 s
   ```
5. Try it:
   ```bash
   dig @127.0.0.1 -p 5300 home.riddlelab.dev +short       # 192.168.0.107
   dig @127.0.0.1 -p 5300 doubleclick.net +short          # 0.0.0.0 once lists load
   ```
   The lists are fetched shortly after start and then daily.
6. Import AdGuard's history so the dashboards start with data. The log is piped
   out of AdGuard and into lacuna (neither container does the heavy work; the
   image has no shell, so `docker exec` runs the binary directly):
   ```bash
   docker exec adguard cat /opt/adguardhome/work/data/querylog.json \
     | docker exec -i lacuna /lacuna import-adguard -
   ```
   Re-running skips what is already imported; `--force` forgets the previous
   import first.
7. Compare against AdGuard on real names, one per line. Do this after step 6:
   compare's queries land in AdGuard's log, and an import run afterwards would
   bring them in as if you had made them.
   ```bash
   docker run --rm --network host -v "$PWD/names.txt:/names.txt:ro" \
     --entrypoint /lacuna homelab/lacuna:latest \
     compare --a 127.0.0.1:5300 --b 192.168.0.107:53 --names /names.txt --limit 500
   ```
   `errors` must be 0 (the command exits 1 otherwise), or the rest says nothing
   about the names that failed. Then read `differ_outcome`; investigate each line
   before cutover.

## Cutover (your step)

Not automated. When the comparison is clean and memory is under AdGuard's:

1. Prepare, with no downtime: edit `deploy/compose.yml`, changing the two port
   lines from `5300` to `53` (`"53:5353/udp"`, `"53:5353/tcp"`), then
   `cd deploy && docker compose config -q` (it prints nothing when the file is valid).
2. Swap, back to back. `&&` means lacuna is only started if AdGuard stopped:
   ```bash
   (cd services/adguard && docker compose stop) && (cd deploy && docker compose up -d)
   ```
3. Check from another LAN machine, UDP and TCP:
   ```bash
   dig @192.168.0.107 home.riddlelab.dev +short           # 192.168.0.107
   dig +tcp @192.168.0.107 home.riddlelab.dev +short      # 192.168.0.107
   dig @192.168.0.107 doubleclick.net +short              # 0.0.0.0
   ```
   The last one proves the lists loaded, and also that DoH and TLS work from the
   scratch image (nothing else proves that). On the server, `docker compose ps`
   must show `healthy`.
4. **If `up` fails or any check fails, run Rollback now.** Do not debug while the
   house has no DNS.

Note: after cutover, queries made on the server itself reach lacuna through
docker-proxy and show a bridge IP as the client. LAN clients keep their own IP.

## Rollback

1. Free port 53 and start AdGuard. **Starting AdGuard is what restores DNS.**
   ```bash
   (cd deploy && docker compose stop) && (cd ../services/adguard && docker compose start)
   ```
2. Afterwards, with DNS back, change the two port lines in `deploy/compose.yml`
   back to `5300`.

The data folder is kept, so lacuna can come back later with its history.

## Where things live

| What | Where |
|---|---|
| Config | `deploy/config.toml`, mounted read-only at `/config/config.toml` |
| Database (query log, rollups, device names) | `/srv/appdata/lacuna/lacuna.db` (WAL mode, so `-wal` and `-shm` files beside it) |
| Downloaded filter lists (last good copies) | `/srv/appdata/lacuna/lists/` |
| SQLite temp files | `/srv/appdata/lacuna/tmp/` (`SQLITE_TMPDIR`, created by `serve`) |
| API secret | `deploy/secrets/lacuna_api` (gitignored), `/run/secrets/lacuna_api` inside |

Config changes: edit `deploy/config.toml`, then `check-config`, then restart the
container (or use the API's reload, see `CONTRACT.md`). The container is
read-only with all capabilities dropped and a 96 MB limit.
