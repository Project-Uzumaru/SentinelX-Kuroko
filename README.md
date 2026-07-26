# Connection Log Classification Engine — Architecture (Handover Doc)

> 中文版本：[README_CN.md](README_CN.md)

This directory holds two independent but structurally symmetric Python scripts that perform
security classification on connection logs from an IDC fleet.
This document lets a future maintainer (human or AI) understand the design without reading
all the code.

## 1. What problem it solves

Every node in the fleet exports two "connection log" snapshots per day (last 24 hours):
- **Successful connections** (info): the TCP session was actually established.
- **Failed connections** (warning): the connection attempt failed.

The raw logs are already aggregated as `origin (internal source IP) → destination (host:port) → hit count`.
The engine's job: pick out **large-scale scanning / port probing / botnet behavior / P2P**, while
**avoiding false positives on legitimate traffic** as much as possible. The key case: customer-operated
REALITY proxy nodes generate heavy traffic to big-brand domains such as visa.cn / qualcomm.cn for SNI
camouflage — these must never be flagged as threats.

## 2. The two scripts

| Script | Handles | Distinctive traits |
|---|---|---|
| `classify_logs.py` | Failed connections (`warning_*`) | High-risk port set **excludes** 22 |
| `classify_info_logs.py` | Successful connections (`info_*`) | High-risk port set **includes** 22 (success = already got in, more serious); adds an `xref` axis that cross-references the same-date warning results; thresholds are tighter in the success context |

Both share the same parsing, cross-day correlation, fleet suppression, and report rendering logic
(each keeps its own copy so the files stay standalone).
`classify_info_logs.py` does `import classify_logs` to reuse the warning engine for cross-referencing.

## 3. Data / directory layout

```
Archive/
  classify_logs.py, classify_info_logs.py
  info_YYYY-MM-DD/raw/<SERVER>.txt         # input
  info_YYYY-MM-DD/result/<SERVER>.txt      # per-node, per-day output (script-generated)
  warning_YYYY-MM-DD/raw|result/...
  FLEET_SUMMARY_info.txt                   # cross-day overview (script-generated)
  FLEET_SUMMARY_warning.txt
```

The scripts auto-discover every `info_*` / `warning_*` date directory and load them all;
**no arguments needed**.

### Input line format
- origin line: `10.111.111.96  17189` (IP + 2 or more spaces + total hit count)
- destination line: `  1.1.1.1:53: 1664` (indent + host:port + hit count)
- excluded line: `  [excluded: 1.1.1.1:53, 40069 hits, 77.6% ...]` — the original report strips out any
  single destination accounting for ≥75% of traffic as "high-frequency noise". The engine uses
  `effective_dests()` to **bring it back into detection** (otherwise an entire telnet flood written off
  as noise would be missed wholesale), without changing the semantics of the total count.

## 4. Severity model

```
CLEAN  <  WATCH  <  SUSPICIOUS  <  MALICIOUS
```
- **WATCH**: matched a suspicious rule, but cross-day analysis judged it "stably recurring = resident
  automation / ops tooling". Benign, but kept visible; excluded from the threat alert list.
- Only **IPv4 destinations** participate in threat judgments; **domain destinations are inherently
  immune** → this is the structural reason REALITY's borrowed SNI is never falsely flagged.

## 5. Single-day detection axes (compute each day's base severity first)

1. **Horizontal high-risk port scan**: one origin hits N unrelated public IPs on the same high-risk port.
   - Threshold `(suspicious, malicious)` = number of distinct target IPs. Default `(5,20)`;
     port 22 in the info context is specially tuned to `(8,25)`.
   - High-risk port set: telnet (23/2323), RDP (3389), SMB (445), 1433/3306/6379/135/139/21/5900/8291/
     37215/52869/7547/1900, etc. (info additionally includes 22).
2. **Vertical single-target port scan**: one origin knocks on N ports ≤1024 on **the same** IP (nmap style).
   - Thresholds: warning `(10,20)`, info `(8,15)`.
   - `COMMON_SERVICE_PORTS` (80/443/53/22/853/993…) are excluded from the count, so hitting a CDN on
     80+443+853 is not mistaken for a scan.
3. **P2P/BitTorrent**: ≥3 distinct IPs matching BT-characteristic ports (6881-6889/6969/1337/51413…).
   This is a **classification tag** (ToS concern), not a security severity.
4. **OpenAI/ChatGPT auth abuse (account-registration bots / token farms)**: on a given day, auth domain
   (auth.openai.com etc.) hits ≥ `OPENAI_AUTH_MIN_HITS` (300), and product domain
   (chat.openai.com / api.openai.com etc.) hits account for ≤ `OPENAI_USAGE_MAX_RATIO` (5%) of the
   combined "auth + product" total → SUSPICIOUS. This is a **ratio-based** judgment rather than an
   absolute count: even a legitimate user behind a proxy/relay with heavy volume still sends far less
   auth traffic than actual product usage; repeatedly running the auth flow while barely touching the
   product itself is the account-farm signature. This is the **only axis that counts domain
   destinations** (all other axes count bare IPv4 only), and it applies solely to those two exact domain
   allowlists, so it does not affect the overall REALITY/SNI domain exemption design.
   It does not participate in cross-day streak escalation/de-escalation (no cross-day correlation; each
   day is judged independently).
5. **Domain destinations too scattered**: on a given day the number of distinct domain destinations is
   ≥ `DOMAIN_SCATTER_MIN_DISTINCT` (300), and no single domain exceeds `DOMAIN_SCATTER_MAX_TOP_SHARE`
   (10%) of "all domain hits" → judged **WATCH** directly (not SUSPICIOUS/MALICIOUS — this is a newer
   exploratory rule, so it lands at the observation tier rather than the alert tier). Calibrated on the
   full dataset: median distinct-domain count is 7, p90 ≈ 251, p95 ≈ 539; this axis sets its threshold
   around p90. Hits are usually one of two things: shared proxy/relay nodes carrying traffic from many
   different real users (benign), or bulk probing / automated access across many domains. Likewise it
   only applies to domain destinations and does not affect the REALITY/SNI domain exemption; it does not
   participate in cross-day streaks.
6. **xref (info only)**: the warning engine already flagged this (node, origin) as a threat on the same
   date → corroborating evidence in the success log.

## 6. Cross-day correlation (the core, `apply_cross_day`)

Findings are grouped by the signature `(node, origin, axis, port/target)` and processed
**day by day along a global timeline**, maintaining `prior_pool` (the union of targets from all previous
days) and a "consecutive suspicious" counter `streak`:

- `novelty` = the fraction of today's targets not in `prior_pool` (share of new faces).
- **`prior_pool` non-empty and `novelty` ≤ NOVELTY_STABLE (0.5)** → judged **WATCH** (stable recurrence =
  automation), `streak` reset to zero.
- Otherwise → stays **SUSPICIOUS**, `streak += 1`; once **`streak ≥ ESCALATE_STREAK_DAYS (3)`** →
  escalate to **MALICIOUS** (sustained scanning with rotating targets).
- Days whose single-day counts already reached the malicious line: stay MALICIOUS.
- **Missing data / CLEAN / WATCH days all break the streak** (reset to zero).
- **Retroactive de-escalation**: for signatures that were never escalated, span ≥2 days, and where a
  suspicious day's targets are a subset of other days' targets (novelty ≤ 0.5), that suspicious day is
  demoted to WATCH — so **the first day of appearance is not penalized** for having no history to
  compare against.

**Directionality**: de-escalation only goes downward (SUSPICIOUS → WATCH); escalation only comes from a
consecutive streak (SUSPICIOUS → MALICIOUS). Cross-day correlation **never** overrides a MALICIOUS
verdict produced by single-day counts.

## 7. False-positive-avoidance design (why it judges this way)

1. **Domains are not counted** → immunity for REALITY/SNI borrowing.
2. **Fleet-shared suppression**: if the same `(destination IP, port)` appears on
   `≥ FLEET_SHARED_MIN_SERVERS (5)` nodes → treated as a mass-deployed shared application
   (Telegram/Steam/STUN/monitoring probes/mainland ISP probe pools, etc.), listed at the end of
   FLEET_SUMMARY and excluded from threat judgment. **But high-risk ports are exempt from this
   suppression** (attackers converging on the same target is not a free pass).
   The domain variant works the same way: a domain appearing on `≥ FLEET_SHARED_DOMAIN_MIN_SERVERS (15)`
   nodes → treated as fleet-wide common infrastructure (CDN/ads/big-brand domains, etc.) and removed
   from the statistics of the "domain scatter" axis (noise reduction for that one axis only; no other
   judgment is affected). Calibrated on full data from 87 nodes: the median node-coverage count for a
   domain is just 1, p95 = 4, so 15 is already far above the noise line — spot-checking around that
   threshold shows nothing but CDNs, ad SDKs, and big-brand domains.
3. **The vertical axis excludes common service ports**, avoiding false positives from multi-port CDN access.
4. **Novelty stability judgment**: target reuse = automation = WATCH; only continuously "rotating to new
   targets" escalates.
5. **Retroactive de-escalation on first appearance**: during batch processing, data from other days is
   used to re-judge a stable signature's first day as WATCH.

## 8. Stateless & single-day usability

- The engine is **stateless**: no database, no reading of the previous `result/`; every run recomputes
  from the raw files currently on disk.
- **It works with a single day**: the only feature that depends on history is cross-day
  de-escalation/escalation. With just one day, stable automation cannot be proven → it will
  conservatively show up as SUSPICIOUS (**over-report rather than under-report**), and the escalation
  path (which needs ≥3 consecutive days) does not trigger. This is graceful degradation.

## 9. Tunable parameters (all at the top of each file)

| Parameter | Meaning |
|---|---|
| `HIGH_RISK_PORTS` / `TELNET_PORTS` | High-risk port sets |
| `PORT_THRESHOLDS` / `DEFAULT_THRESHOLDS` | Horizontal axis (suspicious, malicious) distinct-IP thresholds |
| `N_LOW_PORTS_SUSPICIOUS/MALICIOUS` | Vertical axis low-port count thresholds |
| `COMMON_SERVICE_PORTS` | Common service ports excluded from the vertical axis |
| `TORRENT_PORTS` / `TORRENT_MIN_DISTINCT` | P2P detection |
| `FLEET_SHARED_MIN_SERVERS` | Node-count threshold for shared applications |
| `NOVELTY_STABLE` | ≤ this value counts as "stable recurrence" → demote to WATCH (default 0.5) |
| `ESCALATE_STREAK_DAYS` | Consecutive suspicious days needed to escalate to MALICIOUS (default 3) |
| `OPENAI_AUTH_DOMAINS` / `OPENAI_USAGE_DOMAINS` | OpenAI auth domain / product domain allowlists |
| `OPENAI_AUTH_MIN_HITS` / `OPENAI_USAGE_MAX_RATIO` | Hit-count threshold / product-share ceiling for the auth-abuse rule |
| `DOMAIN_SCATTER_MIN_DISTINCT` / `DOMAIN_SCATTER_MAX_TOP_SHARE` | Distinct-domain-count threshold / max single-domain share for the domain-scatter rule |

## 10. Running it

```
python classify_logs.py        # run first, so info can cross-reference it
python classify_info_logs.py
```
Output: per-date `result/<SERVER>.txt` files plus `FLEET_SUMMARY_{info,warning}.txt` in the root.
Every entry in FLEET_SUMMARY carries two explanation lines: "trigger" (which rule matched, at what
scale, against what threshold) and "rating" (why this severity / what the cross-day judgment was).

## 11. Known boundaries / design trade-offs

- `origin` is an internal IP; the same origin IP on different nodes **does not mean the same device** —
  statistics use "node-IP" as the unique unit.
- Thresholds are calibrated against 24h snapshots (an earlier version merged a full month of data; the
  reason strings have been reworded to per-day phrasing).
- IP attribution analysis (ipinfo.io) was done **manually and offline**; it is **not in the scripts**
  (keeping them purely offline and reproducible).
- Escalation requires ≥3 **consecutive calendar days** that all have data and are all judged suspicious;
  **intermittent suspicion (with clean days or missing data in between) does not escalate**. This is
  deliberate ("consecutive" semantics).
- On the point that "persistence itself can also be a threat": currently only "persistent + rotating
  targets" escalates; "persistent + fixed targets" is judged WATCH.
