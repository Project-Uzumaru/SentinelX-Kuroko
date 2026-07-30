# SentinelX Kuroko

**Connection Log Classification Engine — Architecture (Handover Doc)**

> 中文版本：[README_CN.md](README_CN.md)

This repository holds two independent but structurally symmetric Python scripts that perform
security classification on connection logs from an IDC fleet.
This document lets a future maintainer (human or AI) understand the design without reading
all the code.

## 0. Where this repo sits in SentinelX

**SentinelX as a whole is not open source.** To avoid confusion, the project has been split into
two separate repositories, and **only SentinelX Kuroko — this repository — is open source**:

| Component | Responsibility | Status |
|---|---|---|
| **SentinelX Misaka** | Data collection and network control: raw data acquisition, traffic interception, website blocking, connection logging, and other related security functions | **Closed source** |
| **SentinelX Kuroko** (this repo) | The log analysis algorithm that classifies the collected connection logs | **Open source** (CC BY-NC 4.0) |

Kuroko consumes the connection logs that Misaka produces, but it has no dependency on Misaka's
code: it reads plain text snapshots off disk (see §3) and is fully runnable on its own.

### Versioning

Because of the split, the previous unified version numbers no longer apply. **Misaka and Kuroko now
keep independent version histories, both restarting from `v1.0.0`.** The two version numbers are
unrelated and are **not** expected to stay in sync — each repository follows its own development and
release cycle.

**Current version of this repository: Kuroko v1.1.0** (see §12 for the changelog).

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

## 3. Input

Each node produces one 24h snapshot per log kind per day (this is the SentinelX Misaka side of the
system), already aggregated as
`origin (internal source IP) → destination (host:port) → hit count`. The engine auto-discovers every
available date and loads them all; no arguments needed. Any log source that emits the same aggregated
text format works — Misaka is not required to run Kuroko.

One quirk of the upstream export matters algorithmically: it strips out any single destination
accounting for ≥75% of an origin's traffic, labelling it "high-frequency noise". `effective_dests()`
**puts that destination back before detection runs** — otherwise an entire telnet flood written off
as noise would be missed wholesale — without changing the semantics of the total count.

### Timestamp field (added 2026-07-29, optional)

Destination lines with ≥2 hits may carry a trailing timestamp suffix
`[t first~last avg=<mean interval> secs=<distinct seconds hit>]`, for example:

```
  www.visa.cn:443: 1485  [t 00:00:30~23:59:48 avg=58.2秒 secs=1484]
```

`DEST_RE` matches it with an **optional** non-capturing suffix group, so lines with and without the
field both parse. The four parsed values are normalised to seconds and stored on
`Dest.first_s / last_s / avg_sec / distinct_secs` (`None` for the old format and single-hit lines).
`first_s/last_s/avg_sec` are **purely informational** — they only enrich the `openai_auth` axis's
reason text and **feed no threshold whatsoever**. This was verified against the new data: ordinary
users' auth requests are frequently small bursts within a few seconds too, so treating "burstiness"
itself as a signal would cause false positives. `distinct_secs` is the sole input to the domain
concurrency axis (§5.6).

> Be careful when editing this regex: old-format lines survive only because the suffix group is
> optional (`(?:...)?`). If the upstream format changes again and the suffix stops matching outright,
> `parse_file` will **silently drop the whole line** rather than raise. Always run `parse_file` over a
> day of fresh data and spot-check `by_port` / `domain_counts` — do not just check that the script
> exits without an error.

## 4. Severity model

```
CLEAN  <  INFO  <  WATCH  <  SUSPICIOUS  <  MALICIOUS
```
- **INFO** (added 2026-07-31, one tier below WATCH): an exploratory / observational verdict. It is
  **never "a suspected threat that got demoted"** — the rule is designed to be informational only and
  carries no security concern. Currently only `domain_scatter` (domain destinations too scattered)
  uses this tier. It gets its own section in the reports rather than being mixed into WATCH, so that
  "verified across days and genuinely demoted" (WATCH) is not confused with "not a threat signal at
  all" (INFO).
- **WATCH**: matched a suspicious rule, but cross-day analysis judged it "stably recurring = resident
  automation / ops tooling", or other evidence supports a benign reading (e.g. the `openai_auth`
  axis's cross-day real-usage verification). Benign, but kept visible; excluded from the threat alert
  list.
- Only **IPv4 destinations** participate in the horizontal/vertical port-scan axes and most other
  threat judgments; **domain destinations are inherently immune to those axes** → this is the
  structural reason REALITY's borrowed SNI is never falsely flagged. There are exactly two exceptions:
  `openai_auth` (§5.4) and `domain_concurrency` (§5.6). Both act only on precisely enumerated domains
  or on a domain-concurrency signal, and both were validated against real data as not harming REALITY
  — the overarching principle that domains are immune to scan-type judgments is unchanged.

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
   product itself is the account-farm signature. This is **one of the two axes that count domain
   destinations** (the other is domain concurrency, §5.6; every other axis counts bare IPv4 only), and
   it applies solely to those two explicitly enumerated domain allowlists, so it does not affect the
   overall REALITY/SNI domain exemption design.
   It does not participate in the novelty/streak escalation applied to `horiz`/`vert` inside
   `apply_cross_day` (the auth domains are a fixed handful, so there is no "target set" whose newness
   could be compared).
   - **Cross-day real-usage verification (added 2026-07-31)**: `apply_cross_day` routes this axis
     through its own branch — it checks whether the same `(node, origin IP)` ever recorded
     ≥ `OPENAI_CROSSDAY_USAGE_MIN` (50) product-domain hits on **any other loaded date**. If so, the
     verdict is demoted to `final_sev = WATCH` and `repeat_note` records exactly which day and how
     many hits, explaining that a low product share on this particular day more likely means "only
     refreshed a token, didn't chat" than an account farm. Otherwise the original SUSPICIOUS stands.
   - **Motivation**: a real false positive was observed — one origin had 390 auth hits and 0 product
     hits on a single day, matching the trigger exactly, yet the same origin had 1777 genuine
     chatgpt.com hits on another day. That is a normal heavy user who happened not to chat that day,
     not a registration bot. By contrast, the confirmed real bot was 100% auth on every single day it
     appeared, never touching a product domain on any day. The two patterns separate cleanly once you
     look across days; judging each day independently cannot tell them apart.
   - This verification **only looks at whether the product was genuinely used on other days; it leaves
     the two single-day thresholds untouched** (300 and 5% are unchanged).
5. **Domain destinations too scattered**: on a given day the number of distinct domain destinations is
   ≥ `DOMAIN_SCATTER_MIN_DISTINCT` (300), and no single domain exceeds `DOMAIN_SCATTER_MAX_TOP_SHARE`
   (10%) of "all domain hits" → judged **INFO** directly (changed from WATCH to INFO on 2026-07-31, and
   given its own section in the reports — this rule is exploratory by nature and does not represent a
   cross-day-verified threat demotion, so mixing it into real WATCH entries was misleading). Calibrated
   on the full dataset: median distinct-domain count is 7, p90 ≈ 251, p95 ≈ 539; this axis sets its
   threshold around p90. Hits are usually one of two things: shared proxy/relay nodes carrying traffic
   from many different real users (benign), or bulk probing / automated access across many domains.
   Likewise it only applies to domain destinations and does not affect the REALITY/SNI domain exemption;
   it does not participate in cross-day streaks.
6. **Domain concurrency anomaly (added 2026-07-31 — the only axis that acts on *any* domain)**:
   domain destinations are otherwise immune to every scan-type threat axis in this engine (the §4
   principle); this is the one exception that is not restricted to a fixed domain list (`openai_auth`,
   §5.4, also counts domains but only the two explicitly enumerated sets). Using the timestamp field
   it computes
   `count / distinct_secs` (a domain's hits that day ÷ the number of distinct seconds in which those
   hits landed) to measure "how many hits are being crammed into the same second". If a domain's daily
   hit count is ≥ `DOMAIN_CONCURRENCY_MIN_HITS` (20) and that ratio is
   ≥ `DOMAIN_CONCURRENCY_RATIO_MIN` (2.0) → SUSPICIOUS. **Calibrated against real data**: across 29635
   samples with `count ≥ 20` and timestamps present (including the known REALITY SNI-borrowing domains
   visa.cn / qualcomm.cn, plus all domains without restriction), the ratio never exceeded 1.833;
   REALITY's own heartbeat sits at exactly 1.0 (low frequency, never concurrent). So "the same domain
   being hit repeatedly within a single second" is a clean statistical anomaly in real traffic — it
   looks like a script/tool opening multi-threaded concurrent connections, not browser or normal client
   behaviour — and it does not affect the overall REALITY/SNI domain exemption.
   - **Explicitly not done**: no "multi-domain scanning/enumeration" rule (one origin touching a large
     number of distinct domains in a short window). Testing showed that pattern is indistinguishable,
     on the temporal-clustering dimension, from "open one ad-heavy web page and dozens of third-party
     tracking domains load at once" (real samples turned out to be Feishu / WeChat / Ziniao Browser and
     other ordinary office traffic). Shipping it would have burned normal heavy users, so it was
     dropped.
7. **xref (info only)**: the warning engine already flagged this (node, origin) as a threat on the same
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

1. **Scan-type judgments do not count domains** → immunity for REALITY/SNI borrowing. The horizontal,
   vertical, and P2P axes only ever look at bare IPv4; domain destinations never enter their counts.
   No matter which big-brand SNI REALITY borrows or how much traffic it carries, it structurally
   cannot trigger a scan verdict — the immunity comes from the shape of the algorithm, not from a
   whitelist holding it back.
   - Neither exception weakens this: `openai_auth` (§5.4) fires only on two **explicitly enumerated**
     sets of OpenAI domains, and borrowed SNI domains are not on those lists;
     `domain_concurrency` (§5.6) does apply to any domain, but it judges *hits crammed into the same
     second*, not *which domain was visited* — and REALITY's heartbeat measures a constant 1.0 (low
     frequency, never concurrent), nowhere near the 2.0 threshold. In other words: **the act of
     REALITY borrowing an SNI produces no signal on any axis.**
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
- **It works with a single day**: only the cross-day machinery depends on history, in two places —
  (1) cross-day de-escalation/escalation for `horiz`/`vert`, and (2) the `openai_auth` cross-day
  real-usage verification. With just one day neither has evidence to work with: stable automation
  cannot be proven, and genuine product usage on other days cannot be looked up → both conservatively
  stay at SUSPICIOUS (**over-report rather than under-report**), and the escalation path (which needs
  ≥3 consecutive days) does not trigger either. This is graceful degradation; every single-day axis
  still works normally.

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
| `OPENAI_CROSSDAY_USAGE_MIN` | Cross-day real-usage verification threshold: product-domain hits ≥ this on any other day demotes to WATCH (default 50) |
| `DOMAIN_CONCURRENCY_MIN_HITS` / `DOMAIN_CONCURRENCY_RATIO_MIN` | Minimum hit count / `count ÷ distinct_secs` concurrency ratio for the domain-concurrency rule |
| `DOMAIN_SCATTER_MIN_DISTINCT` / `DOMAIN_SCATTER_MAX_TOP_SHARE` | Distinct-domain-count threshold / max single-domain share for the domain-scatter rule |

## 10. Running it

```
python classify_logs.py        # run first, so info can cross-reference it
python classify_info_logs.py
```
Both write a per-node report for each date plus a fleet-wide cross-day summary. Reports and summaries
are sectioned as `MALICIOUS / SUSPICIOUS / WATCH / INFO` (INFO gets its own section and is never mixed
into WATCH). Every flagged entry carries two explanation lines: **trigger** (which rule matched, at
what scale, against what threshold) and **rating** (why this severity / what the cross-day judgment
was) — the reasoning is always reconstructable from the output alone.

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
- The domain-concurrency axis depends on the upstream timestamp field, which only exists from
  2026-07-29 onward. **Older dates carry no such field, so the axis is silently inert on those days** —
  that is missing input, not a missed detection.

## 12. Changelog

### v1.1.0

- **New INFO severity tier** (`CLEAN < INFO < WATCH < SUSPICIOUS < MALICIOUS`). Exploratory /
  informational verdicts land here and get their own section in both the per-node reports and
  FLEET_SUMMARY, instead of being mixed into WATCH (which means "verified across days and demoted").
- **`domain_scatter` (domains too scattered) moved from WATCH to INFO.** Detection logic and
  thresholds are unchanged; only the tier it reports at changed.
- **New `domain_concurrency` axis**: uses `count ÷ distinct_secs` to detect hits crammed into the same
  second, rated SUSPICIOUS. Calibrated on 29635 real samples (observed ratio never exceeded 1.833;
  REALITY's heartbeat sits at exactly 1.0). It is the only axis that acts on any domain rather than a
  fixed enumerated list (`openai_auth` counts domains too, but only its two allowlists).
- **`openai_auth` gains cross-day real-usage verification**: ≥ `OPENAI_CROSSDAY_USAGE_MIN` (50)
  product-domain hits on any other date demotes the finding to WATCH, naming the day and hit count.
  This fixed a real false positive (a heavy user who happened to only refresh a token one day). The
  single-day 300 / 5% thresholds are unchanged.
- **Parser accepts the optional timestamp suffix on destination lines**
  (`[t first~last avg=… secs=…]`, produced upstream from 2026-07-29), stored on
  `Dest.first_s / last_s / avg_sec / distinct_secs`. Old-format lines still parse as before.
- **`openai_auth` reason text now includes a timing description** (first/last hit, span, mean
  interval) for human review only — it feeds no threshold.
- New tunable parameters: `OPENAI_CROSSDAY_USAGE_MIN`, `DOMAIN_CONCURRENCY_MIN_HITS`,
  `DOMAIN_CONCURRENCY_RATIO_MIN`.

### v1.0.0

First standalone release after SentinelX was split into Misaka (closed source) and Kuroko (this
repository, open source); version numbering restarts here.

## 13. License

**SentinelX Kuroko** is released under the
[Creative Commons Attribution-NonCommercial 4.0 International License (CC BY-NC 4.0)](LICENSE).

You are free to **use, modify, and redistribute** this code, provided that:

- **Attribution** — you give appropriate credit to **Uzumaru** and the **SentinelX Kuroko** project,
  include a link to the license, and indicate whether you made changes.
- **NonCommercial** — you may **not** use it for commercial purposes, including selling it,
  selling a service built on it, or bundling it into a paid product.

This license covers **this repository only**. **SentinelX Misaka and the complete SentinelX system
remain closed source** and are not licensed under CC BY-NC 4.0.

Copyright © 2026 Uzumaru.
