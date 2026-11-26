"""Run named read-only SQL queries against lacuna's query API, one at a time.
Usage: ask.py queries.sql  (blocks separated by lines '-- name: <name>')."""
import json, sys, time, urllib.request, urllib.error

KEY = open("/key").read().strip()
NOW = int(time.time() * 1000)
DAY = 86_400_000


def run(sql):
    params = {"now": NOW, "d1": NOW - DAY, "d7": NOW - 7 * DAY, "d30": NOW - 30 * DAY}
    used = {k: v for k, v in params.items() if f":{k}" in sql}
    req = urllib.request.Request("http://lacuna:8053/integration/query", method="POST",
                                 data=json.dumps({"sql": sql, "params": used}).encode(),
                                 headers={"Authorization": f"Bearer {KEY}", "Content-Type": "application/json"})
    t = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            body = json.loads(r.read())
            return body, int((time.monotonic() - t) * 1000)
    except urllib.error.HTTPError as e:
        return {"error": f"{e.code} {e.read().decode()[:300]}"}, int((time.monotonic() - t) * 1000)


blocks, name, buf = [], None, []
for line in open(sys.argv[1]):
    if line.startswith("-- name:"):
        if name:
            blocks.append((name, "".join(buf)))
        name, buf = line.split(":", 1)[1].strip(), []
    else:
        buf.append(line)
if name:
    blocks.append((name, "".join(buf)))

limit = int(sys.argv[2]) if len(sys.argv) > 2 else 40
for name, sql in blocks:
    body, ms = run(sql)
    print(f"\n### {name}  ({ms} ms)")
    if "error" in body:
        print("ERROR", body["error"])
        continue
    cols = [c["name"] for c in body["columns"]]
    print(" | ".join(cols))
    for row in body["rows"][:limit]:
        print(" | ".join("" if v is None else str(v) for v in row))
    if len(body["rows"]) > limit:
        print(f"... {len(body['rows'])} rows")
