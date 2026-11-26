# Six targets: decisions the DNS data can settle

A chart with no question behind it can't give a conclusion. So each target here starts
from a **decision**, and works backwards:

> decision → the question that settles it → my guess → look → what I saw → conclusion → action

**How to use it.** Pick one. Write your guess *before* you look. Then run its starter
query and fill in the rest. A wrong guess is the useful kind: it shows where your picture
of the network was off.

**Starter queries** are the named blocks in `17-targets.sql` (same folder). They are a
first look, not the answer; change them as your question sharpens. Run all of them with:

```
cd ~/lacuna/research && docker run --rm --network lacuna-api -v "$PWD":/p:ro \
  -v ~/sonder/deploy/secrets/integrations/lacuna:/key:ro python:3-alpine python -I /p/ask.py /p/17-targets.sql
```

Times in the queries are IST. The views they read (`queries`, `hourly`, `daily`) are
described in `~/lacuna/CONTRACT.md`.

**This now lives in Sonder** as a workbook with live charts and answer boxes:
https://sonder.home.riddlelab.dev/learn/dns-targets (source: `~/sonder/content/pages/dns-targets.json`).
This file stays as the plain-text copy; answer in Sonder, where "Download as Markdown" saves
the page with your answers.

---

## 1. Should the router stay in the IPv4 DNS list?

*An open decision ("step 2").* Keeping the router second gives the house DNS when lacuna is
down. It also means some lookups go through the router and are logged as "OpenWrt" instead
of the real device.

- **Question:** how often was lacuna actually silent, compared with how many lookups lose
  their device name by going through the router?
- **Starter queries:** `t1 lookups that went through the router`, `t1 silent stretches`
- **What to watch for:** a silent stretch can be a restart you ran yourself. Check the
  times against when you restarted lacuna.

| | |
|---|---|
| My guess | |
| What I looked at | |
| What I saw | |
| Conclusion | |
| Action | |

*A conclusion sounds like:* "The fallback covered N minutes this month, and cost me X% of my
attribution, every day."

---

## 2. Did the SOA fix stop the retry storms?

*An open check from 26 Nov.* Before 14:04 IST that day, the MacBookAir asked for the same
blocked names every few seconds, because blocked "no such record" answers couldn't be kept.

- **Question:** does any device still ask for the same blocked name over and over?
- **Starter queries:** `t2 blocked lookups per IST hour and record type`,
  `t2 most repeated blocked names since the SOA fix`
- **What to watch for:** split by record type. The address (A) fix and the HTTPS fix were
  two different changes.

| | |
|---|---|
| My guess | |
| What I looked at | |
| What I saw | |
| Conclusion | |
| Action | |

*A conclusion sounds like:* "Fixed: from N an hour to M." Or: "Name Z still storms, from
device D, and here's why."

---

## 3. Is my internet provider actually bad, or does it just feel that way?

- **Question:** when lookups fail, does the whole house fail at the same moment, or is it
  one device?
- **Starter query:** `t3 failed lookups per IST hour`
- **What to watch for:** this is the trap Claude fell into on 26 Nov. One phone's cached
  failures looked like two outages. "No upstream answered" means lacuna couldn't reach the
  internet; "name failed" means the name itself is broken. Many devices at once is an outage;
  one device is that device.

| | |
|---|---|
| My guess | |
| What I looked at | |
| What I saw | |
| Conclusion | |
| Action | |

*A conclusion sounds like:* "Two real outages this week: Tuesday 21:10 for 4 minutes,
everyone affected. Everything else was one device."

---

## 4. Is the ad blocking worth it, and for whom?

- **Question:** what share of each device's lookups is blocked, and which device is the
  most tracked?
- **Starter query:** `t4 share of each device's lookups that were blocked`
- **What to watch for:** a device with few lookups can show a big percentage from very little.
  The query skips devices under 100 lookups for that reason.

| | |
|---|---|
| My guess | |
| What I looked at | |
| What I saw | |
| Conclusion | |
| Action | |

*A conclusion sounds like:* "Blocking removes 18% of the MacBookAir's lookups but 60% of the
Echo's: the Echo is mostly a tracker."

---

## 5. Is anything in the house calling home that I didn't know about?

- **Question:** between 02:00 and 05:00 IST, when nobody is using anything, who still asks,
  and for what?
- **Starter query:** `t5 who asks for what between 02:00 and 05:00 IST`
- **What to watch for:** separate "the server itself" (homelab) from the other devices. Then
  ask, for each top name: do I know what this is, and do I want it?

| | |
|---|---|
| My guess | |
| What I looked at | |
| What I saw | |
| Conclusion | |
| Action | |

*A conclusion sounds like:* "Device X asks Y every 15 minutes all night. I'll block it." Or:
"That's the clock sync, fine." This one later becomes a lacuna watch rule.

---

## 6. Does lacuna make browsing slower?

- **Question:** how long do answers take from the cache versus from the internet, and how
  often is each one used?
- **Starter query:** `t6 where answers came from and how long they took`
- **What to watch for:** "stale_cache" means lacuna answered at once from an expired copy and
  refreshed it in the background. Look at the share as well as the speed: a slow path that is
  rarely used matters less than a medium one used all the time.

| | |
|---|---|
| My guess | |
| What I looked at | |
| What I saw | |
| Conclusion | |
| Action | |

*A conclusion sounds like:* "Nine in ten answers come back in under a millisecond; the
internet is the slow part, so a bigger cache would or wouldn't help, because…"
