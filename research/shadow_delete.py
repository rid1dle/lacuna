"""One-off: remove the shadow-run test traffic (client 192.168.224.1 before the
2026-11-25 cutover) from lacuna's query log, and the same counts from the hourly
and daily rollups, so every chart agrees with the raw rows.

Run as lacuna's uid with the data folder mounted. It backs the database up
first, then does everything in ONE transaction that checks its own result
against the dry run and rolls back on any difference.

  docker run --rm --user 3070:3070 -v /srv/appdata/lacuna:/data \
    -v ~/lacuna/research:/p:ro python:3-alpine python -I /p/shadow_delete.py [--apply]

Without --apply it does the same work and rolls back (a rehearsal).
"""
import sqlite3, sys

DB = "/data/lacuna.db"
BACKUP = "/data/lacuna.pre-shadow-delete.db"
CLIENT = "192.168.224.1"
END = 1795620000000  # 2026-11-25 15:20 UTC; the last test row is 14:15:58, the first real one 15:25:29
IST, DAY, HOUR = 19800000, 86400000, 3600000
# From the dry run (research/09-shadow-delete-dryrun.sql), 2026-11-26.
REMOVED = 184499
EXPECT = {"raw": REMOVED, "hourly_left": 0, "raw_kept_min": 80}

apply = "--apply" in sys.argv
conn = sqlite3.connect(DB, timeout=10, isolation_level=None)
conn.execute("PRAGMA busy_timeout = 10000")

if apply:
    # The backup API copies a consistent snapshot while lacuna keeps writing.
    with sqlite3.connect(BACKUP) as dst:
        conn.backup(dst)
    print("backup written:", BACKUP)

conn.execute("BEGIN IMMEDIATE")
try:
    w = "client = ? AND ts < ?"
    total = "SELECT coalesce(sum(n), 0) FROM {} WHERE client = ?"
    daily_before = conn.execute(total.format("daily_counts"), (CLIENT,)).fetchone()[0]
    hourly_before = conn.execute(total.format("hourly_counts"), (CLIENT,)).fetchone()[0]
    EXPECT["daily_total"] = daily_before - REMOVED
    EXPECT["hourly_total"] = hourly_before - REMOVED
    conn.execute(f"""
        UPDATE hourly_counts AS h SET n = h.n - x.n, latency_us_sum = h.latency_us_sum - x.lat
        FROM (SELECT ts - ts % {HOUR} AS hour_ms, outcome, count(*) AS n, sum(latency_us) AS lat
              FROM raw_queries WHERE {w} GROUP BY 1, 2) AS x
        WHERE h.client = ? AND h.hour_ms = x.hour_ms AND h.outcome = x.outcome""", (CLIENT, END, CLIENT))
    conn.execute(f"""
        UPDATE daily_counts AS d SET n = d.n - x.n
        FROM (SELECT (ts + {IST}) / {DAY} * {DAY} - {IST} AS day_ts, domain_id, outcome,
                     coalesce(rule_id, 0) AS rule_id, count(*) AS n
              FROM raw_queries WHERE {w} GROUP BY 1, 2, 3, 4) AS x
        WHERE d.client = ? AND d.day_ts = x.day_ts AND d.domain_id = x.domain_id
          AND d.outcome = x.outcome AND d.rule_id = x.rule_id""", (CLIENT, END, CLIENT))
    neg = conn.execute("SELECT (SELECT count(*) FROM hourly_counts WHERE n < 0 OR latency_us_sum < 0)"
                       " + (SELECT count(*) FROM daily_counts WHERE n < 0)").fetchone()[0]
    conn.execute("DELETE FROM hourly_counts WHERE client = ? AND n = 0", (CLIENT,))
    conn.execute("DELETE FROM daily_counts WHERE client = ? AND n = 0", (CLIENT,))
    raw = conn.execute(f"DELETE FROM raw_queries WHERE {w}", (CLIENT, END)).rowcount

    got = {
        "raw": raw,
        # Whole hours before END only: the 15:00 bucket also holds real rows from 15:25.
        "hourly_left": conn.execute("SELECT coalesce(sum(n), 0) FROM hourly_counts WHERE client = ? AND hour_ms < ?",
                                    (CLIENT, END - END % HOUR)).fetchone()[0],
        "daily_total": conn.execute(total.format("daily_counts"), (CLIENT,)).fetchone()[0],
        "hourly_total": conn.execute(total.format("hourly_counts"), (CLIENT,)).fetchone()[0],
        "raw_kept_min": conn.execute("SELECT count(*) FROM raw_queries WHERE client = ?", (CLIENT,)).fetchone()[0],
    }
    print("negative counts:", neg)
    print("got   ", got)
    print("expect", EXPECT)
    ok = neg == 0 and all(got[k] == v for k, v in EXPECT.items() if k != "raw_kept_min") \
        and got["raw_kept_min"] >= EXPECT["raw_kept_min"]
    if apply and ok:
        conn.execute("COMMIT")
        print("COMMITTED")
    else:
        conn.execute("ROLLBACK")
        print("ROLLED BACK", "(rehearsal)" if ok else "(result differs from the dry run)")
except Exception:
    conn.execute("ROLLBACK")
    raise
