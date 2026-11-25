# lacuna

A small ad-blocking DNS server in Rust, built to replace AdGuard Home on this
server. One static binary in a `scratch` image (about 17 MB on disk; 26 to 37 MB
of RAM with the AdGuard DNS filter loaded, 59 MB at the daily rule rebuild,
against AdGuard's 81 MiB), SQLite compiled in, no database server.

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

**Every command in this section, in Cutover and in Rollback runs from this
folder, `lacuna/deploy/`.** Nothing here needs a `cd`.

1. Create the network (once): `~/homelab/scripts/provision/networks.sh`. It adds
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
   mkdir -p secrets
   openssl rand -hex 32 > secrets/lacuna_api
   sudo chgrp 3070 secrets/lacuna_api && chmod 0640 secrets/lacuna_api
   ```
   Compose will not start the container without `secrets/lacuna_api`. An
   empty file starts fine: every API request then gets 503
   `{"error":"api secret not configured"}` and DNS still works. Sonder reads the
   same value (wired in Sonder's own plan).
4. Build, validate, start (the image must exist before `check-config` can run it):
   ```bash
   docker compose build
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
   A second run is refused, because it would count every query twice.
   `--force` forgets the previous import and imports again (only into a fresh
   database, or the history is doubled). The shadow run imported 4,464,298 lines
   in 68 s.
7. Compare against AdGuard on real names, one per line in `names.txt` (in this
   folder). Do this after step 6:
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

## Shadow run results (2026-11-25)

Measured on this server, lacuna on port 5300 next to the live AdGuard, with the
AdGuard DNS filter (194,783 rules parsed, 22 regex rules skipped). Build: commit
56a2f0b unless a row says otherwise.

| Check | Result |
|---|---|
| History import | 4,464,298 AdGuard log lines: 1,716,701 kept raw (last 30 days), 2,747,597 into the hourly and daily counts only, 0 skipped. Rollups plus the raw tail equal the lines imported exactly. 68 s; slowest write batch 70 ms. |
| Compare, 3,378 names from the last 24 h (A and AAAA) | 0 outcome differences. 932 answer differences: 928 are CDN address rotation (724 different address sets, 204 overlapping), 4 are AAAA answers empty on one side only (Stripe and CloudFront names). 2 errors: one name timed out on both servers. |
| Before the wildcard work (build 0292946) | 64 outcome differences over 33 names, all from rule forms lacuna skipped (`*` inside a name, `\|` anchors, a leading dot). Over the imported window AdGuard blocked 328,342 queries; those forms decided 20,769 blocks lacuna would have missed (6.3%) and 1,065 allowed queries it would have blocked. |
| Memory, process RSS (build c819788) | 26 MB after a fresh start; 37 MB with the DNS cache full (filled past its 4,000 cap with 5,225 real names); 46 MB under DNS load (3 compare streams) plus 4 concurrent dashboard queries over a 30-day range (2 cache hit %, which reads at most 7 days, and 2 top domains per device); 59 MB at the peak of a rule rebuild with the cache full (list refresh or config reload), settling at 37 MB, with no swapping and no container memory-limit events. AdGuard: 81 MiB. Before rule text moved into SQLite (build b769f88) the same rebuild peaked at 100 MB, at the 96 MiB limit. |
| Disk | `lacuna.db` 244 MB after the import (1.7M raw rows, about 77 days of rollups); filter list copies 4.6 MB. |
| Dashboards | Every default panel answers over 1 and 30 days. Slowest at 30 days, idle: cache hit % 0.74 s, top domains per device 0.59 s, all others under 0.3 s. Cache hit % and upstream latency read raw rows and cover at most the last 7 days: before that clamp, cache hit % over 30 days took 2.4 s alone and timed out (6 of 6) with two running under load. With 4 concurrent requests and 2 query slots, 2 get `429 busy`, as the contract specifies. |
| API | 401 without the secret, 401 with a wrong one, 200 with it, from the `lacuna-api` network. |

Not covered by the shadow run: real clients on port 53 (no device uses 5300),
so the first hour after cutover is the real load test.

## Cutover (your step)

Run from `lacuna/deploy/`, no `cd`. Not automated. When the comparison is clean and memory is under AdGuard's:

1. Prepare, with no downtime: edit `compose.yml`, changing the two port
   lines from `5300` to `53` (`"53:5353/udp"`, `"53:5353/tcp"`), then
   `docker compose config -q` (it prints nothing when the file is valid).
2. Swap, back to back. `&&` means lacuna is only started if AdGuard stopped:
   ```bash
   docker stop adguard && docker compose up -d
   ```
3. Check. The server has no `dig`, so use lacuna's own `ask` there (exit 0
   means the answer matched `--expect`, exit 1 means it did not):
   ```bash
   docker run --rm --network host --entrypoint /lacuna homelab/lacuna:latest \
     ask home.riddlelab.dev A --server 192.168.0.107:53 --expect 192.168.0.107; echo "exit=$?"
   docker run --rm --network host --entrypoint /lacuna homelab/lacuna:latest \
     ask doubleclick.net A --server 192.168.0.107:53 --expect 0.0.0.0; echo "exit=$?"
   docker run --rm --network host --entrypoint /lacuna homelab/lacuna:latest \
     ask example.com A --server 192.168.0.107:53; echo "exit=$?"
   docker compose ps          # must show healthy
   ```
   The first proves the rewrite table, the second that the block lists loaded,
   the third (any real address) that the upstreams answer over DoH from the
   scratch image. `ask` speaks UDP only, so check TCP once from a Mac on the LAN
   (macOS ships `dig`):
   ```bash
   dig +tcp @192.168.0.107 home.riddlelab.dev +short      # 192.168.0.107
   ```
4. **If `up` fails or any check fails, run Rollback now.** Do not debug while the
   house has no DNS.

Note: after cutover, queries made on the server itself reach lacuna through
docker-proxy and show a bridge IP as the client. LAN clients keep their own IP.

First hour after cutover (the shadow run had no real clients, so this is the
real load test). Until Sonder's dashboards exist, read the numbers through the
API from the `lacuna-api` network (see `CONTRACT.md` for the call):

- Counters, from `lacuna/deploy/` (a throwaway curl container on the API network;
  the secret file is group 3070, hence `--group-add`):
  ```bash
  docker run --rm --network lacuna-api --group-add 3070 \
    -v "$PWD/secrets/lacuna_api:/run/secrets/lacuna_api:ro" \
    --entrypoint sh curlimages/curl:8.10.1 -c \
    'curl -sS -H "Authorization: Bearer $(cat /run/secrets/lacuna_api)" \
       -H "Content-Type: application/json" \
       -d "{\"sql\":\"SELECT name, value FROM counters\"}" \
       http://lacuna:8053/integration/query'
  ```
  `log_dropped` must stay 0, and `queries_total` must keep rising.
- Memory, as process RSS (how the shadow numbers were taken; `docker stats`
  also counts page cache, so it reads higher):
  ```bash
  grep VmRSS /proc/$(docker inspect lacuna --format '{{.State.Pid}}')/status
  ```
  Normal is under 50 MB (shadow run: 37 MB idle with the cache full, 46 MB under
  DNS load plus dashboard queries). Brief peaks up to about 60 MB come from the
  daily rule rebuild (59 MB measured). A steady climb past 60 MB is a reason to
  roll back.
- Browse normally on a phone and a laptop. A site that breaks and works with
  AdGuard is a rule difference: note the name, then check it with the
  `test_domain` action.

Keep AdGuard's container and data for 14 days after cutover, so Rollback stays
one command. Remove them only after that, as a separate step.

## Rollback

Run from `lacuna/deploy/`, no `cd`.

1. Free port 53 and start AdGuard. **Starting AdGuard is what restores DNS.**
   Container names, not `docker compose`, so this works even if the port edit
   broke `compose.yml`:
   ```bash
   docker stop lacuna; docker start adguard
   ```
   `;`, not `&&`: AdGuard must start whatever the first command says. Stopping
   an already stopped container exits 0, but a missing one (a failed `up` can
   leave none) exits 1, and `&&` would then skip AdGuard.
2. Afterwards, with DNS back, change the two port lines in `compose.yml`
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
