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

**Current version of this repository: Kuroko v1.2.0** (see §12 for the changelog).

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
`first_s/last_s` feed the single-domain connection storm axis (§5.6), which computes a sustained rate
as `count ÷ (last − first)`. `avg_sec` and `distinct_secs` currently **feed no threshold**: `avg_sec`
only enriches the `openai_auth` axis's reason text (verified against real data — ordinary users' auth
requests are frequently small bursts within a few seconds too, so treating "burstiness" itself as a
signal would cause false positives); `distinct_secs` was the sole input to the v1.1.0 domain
concurrency axis, which was overturned and rewritten in v1.2.0 (see §5.6) — the field is still parsed
but no longer read.

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
  structural reason REALITY's borrowed SNI is never falsely flagged. There are exactly three
  exceptions: `openai_auth` (§5.4), `domain_storm` (§5.6), and `mining` (§5.9). `openai_auth` and
  `mining` act only on precisely enumerated domain lists; `domain_storm` judges *sustained rate*
  rather than *which domain was visited*. All three were validated against real data as not harming
  REALITY — the overarching principle that domains are immune to scan-type judgments is unchanged.

## 5. Single-day detection axes (compute each day's base severity first)

1. **Horizontal high-risk port scan**: one origin hits N unrelated public IPs on the same high-risk port.
   - Threshold `(suspicious, malicious)` = number of distinct target IPs. Default `(5,20)`;
     port 22 in the info context is specially tuned to `(8,25)`; 6667/6697/5432 use `(8,25)`;
     7001 uses `(20,40)` (rationale below).
   - High-risk port set: telnet (23/2323), RDP (3389), SMB (445), 1433/3306/6379/135/139/21/5900/8291/
     37215/52869/7547/1900 (info additionally includes 22), plus these added in v1.2.0:
     **2375/2376** (Docker unauthenticated RCE), **4444** (Metasploit), **5601** (Kibana),
     **7001** (WebLogic), **9200** (Elasticsearch), **11211** (memcached), **2181** (ZooKeeper),
     **5984** (CouchDB), **623** (IPMI/BMC), **6667/6697** (IRC — common botnet C2),
     **5432** (PostgreSQL).
   - **`SHAREABLE_HIGH_RISK_PORTS` (new in v1.2.0)**: 7001/5432/6667/6697/5601/9200/2181/5984 are
     genuine attack surface, but they **also have legitimate multi-customer shared uses** (app
     control panels, managed databases, IRC servers, proxy backends), so they **do** participate in
     fleet-shared suppression (§7.2). Ports that normal business would never dial at all
     (telnet/RDP/SMB/Docker) still do not.
   - > **Do not add 27017 (MongoDB) to the high-risk set.** It also falls inside the Steam /
     > Source-engine game server port range 27015–27030. An origin was rated malicious over it
     > ("27017 successfully connected to 53 unrelated public IPs"), but it was hitting the **entire
     > 27015–27098 range** with every target inside Valve's netblocks — it was playing Steam.
     > **Before adding any high-risk port, confirm it does not sit inside a port range commonly used
     > by games / P2P / proxies**, or it will produce false positives on any dataset full of consumer
     > traffic.
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
6. **Single-domain connection storm (rewritten in v1.2.0, replacing v1.1.0's "domain concurrency
   anomaly")**: the criterion is **sustained rate**, `rate = count ÷ (last − first)`. All three
   conditions must hold: daily hits ≥ `DOMAIN_STORM_MIN_HITS` (150), span
   ≥ `DOMAIN_STORM_MIN_SPAN_SEC` (20s), and `rate` ≥ `DOMAIN_STORM_MIN_RATE` (2.0 hits/sec)
   → SUSPICIOUS. Stacking the three thresholds eliminates ordinary browsing, telemetry, keepalives,
   and REALITY heartbeats, leaving only genuine retry storms / brute force / API hammering.

   > **⚠️ The v1.1.0 rule was overturned — do not go back to `count ÷ distinct_secs`.** The old rule
   > used that ratio as a "concurrency" measure with a 2.0 threshold and claimed "the ratio never
   > exceeded 1.833 in testing". That calibration used only two days of data and collapsed completely
   > on the following 25 days: **this single axis produced 2166 findings, 87% of all findings**
   > (every other axis combined produced 321), hitting domains like www.google.com,
   > cp.cloudflare.com, apple.com, netflix.com, and browser.events.data.microsoft.com.
   >
   > Root cause: `count ÷ distinct_secs` does not measure burstiness at all — it measures **how many
   > connections the client opens per event**. In the data the ratio is frequently exactly 7.00
   > (21/3, 28/4, 35/5, 399/57…), which is precisely the browser's 6+1 per-host connection pool — a
   > property of the network stack, not of behaviour. It is completely insensitive to time span:
   > `browser.events.data.microsoft.com` with 316 hits spread over **22 hours** (4.3 min mean
   > interval, one connection each for IPv4/IPv6 → ratio 2.14) and `app.wilsonmk.xyz` with 399 hits
   > crammed into **61 seconds** (one every 0.15s) were treated identically. Switching to rate
   > separates them by three orders of magnitude (0.004 vs 6.5 hits/sec).

   - **Explicitly not done**: no "multi-domain scanning/enumeration" rule (one origin touching a large
     number of distinct domains in a short window). Testing showed that pattern is indistinguishable,
     on the temporal-clustering dimension, from "open one ad-heavy web page and dozens of third-party
     tracking domains load at once" (real samples turned out to be Feishu / WeChat / Ziniao Browser and
     other ordinary office traffic). Shipping it would have burned normal heavy users, so it was
     dropped.
7. **xref (info only)**: the warning engine already flagged this (node, origin) as a threat on the same
   date → corroborating evidence in the success log. **The direction is one-way**: info consults
   warning, warning never consults info. In testing, the same origin was rated CLEAN on the warning
   side and MALICIOUS on the info side.
8. **Multi-port horizontal scan (new in v1.2.0, port-agnostic)**: the horizontal axis only looks at the
   high-risk port allowlist and the vertical axis only at ports ≤1024, so neither covers the most
   common scanner behaviour of all — sweeping an entire netblock with a custom port list. This axis
   ignores what the ports are and looks only at **shape**:
   - First derive the "reused port" set = ports seen on ≥ `MULTIPORT_PORT_MIN_IPS` (3) distinct IPs
     (excluding `COMMON_SERVICE_PORTS`, `TORRENT_PORTS`, and fleet-shared destinations);
   - then count how many target IPs were hit on ≥ `MULTIPORT_MIN_PORTS` (3) of those reused ports;
   - that count ≥ `MULTIPORT_SUSPICIOUS` (warning 8 / info 6) → SUSPICIOUS,
     ≥ `MULTIPORT_MALICIOUS` (warning 20 / info 15) → MALICIOUS. Participates in cross-day
     novelty/streak.

   **P2P is not caught**: BT peer ports are random and are not reused across peers, so no "reused
   port" set can form — the axis simply never fires on it.

   > **⚠️ Those four parameters alone produce heavy false positives; the four noise filters below are
   > mandatory.** On a fleet whose business is **predominantly proxy traffic**, "one origin connecting
   > to many IPs on many non-standard ports" is inherently ambiguous — it is simultaneously the shape
   > of a scanner and the shape of a proxy client. Three classes of benign traffic were caught:
   > - **Port-mapping gateways**: each gateway IP owns its own **contiguous** port block
   >   (8531-8541, 8561-8573, 8621-8630), one port per backend exit;
   > - **Proxy subscription nodes**: ports not contiguous, but each `(IP, port)` is hit hundreds of
   >   times across many hours — a sustained relationship, not probing;
   > - **Cloudflare clients**: all targets in 104.17-19.x on CF's official alternate ports
   >   2052/2053/2082/2083/2086/2087/2095/2096/8880.
   >
   > **Measures that were tried and did NOT work (all empirically tested — do not repeat)**: share of
   > "core" ports across targets, mean pairwise Jaccard of per-target port sets, and /24 clustering of
   > target IPs. Real scans and proxy pools **overlap completely** on all three — one proxy pool
   > scored a Jaccard of 0.329, squarely inside the real scans' 0.297–0.392 range, and one gateway
   > cluster sat entirely within a single /24, more concentrated than the scanners.
   >
   > **What actually works is port semantics**: scanners probe exploitable services
   > (2375/2376/3389/4444/5601/6697); proxy pools use arbitrary mapped ports (8501-8700,
   > 20004-20129, 30804-30845). Hence four filters:
   >
   > | Parameter / condition | Effect |
   > |---|---|
   > | `MULTIPORT_MAX_HITS` (5) | An `(IP, port)` hit more than this = sustained relationship, not probing — excluded |
   > | `MULTIPORT_MAX_RUN` (5) | Longest contiguous run in one IP's port set reaching this = port-mapping gateway — whole host excluded |
   > | `MULTIPORT_MIN_HIGHRISK` (2) | The reused port set must contain at least this many `HIGH_RISK_PORTS` (global semantic anchor) |
   > | Per-host anchor | Each target IP must **itself** be hit on ≥1 `HIGH_RISK_PORTS` |
   >
   > **That last per-host anchor is not optional.** With only the global check, one false positive
   > slipped through: an origin had touched 7001/9200 **elsewhere**, which effectively issued a permit
   > for its entire Cloudflare fan-out — while none of those CF targets carried a single high-risk port.
   >
   > With all four in place, 10 manually reviewed cases separate **100% correctly**: all 4 real scans
   > retained and still far above the malicious line, all 6 proxy pools excluded; finding counts
   > dropped from 36→8 (warning) and 127→6 (info).
9. **Mining pool domains (new in v1.2.0)**: same family as `openai_auth` — substring matching against a
   precise signature list (`MINING_DOMAIN_HINTS`: stratum / nanopool / minexmr / f2pool / ethermine,
   etc.). Split into **two tiers by shape**:
   - Hits landing on `MINING_STRATUM_PORTS`
     (3333/4444/5555/7777/8888/9999/14444/45700/3032/1234), or a single domain with
     ≥ `MINING_SESSION_MIN_HITS` (50) hits → `mining`, **SUSPICIOUS** (this machine is mining);
   - Sparse contact on 80/443 only → `mining_web`, **INFO** (somebody opened a mining pool's website
     or their own pool dashboard in a browser).

   > The split was forced by real data: the first version rated any match SUSPICIOUS with no hit
   > threshold, and all 23 findings turned out to be 443-port, single-digit-hit visits to
   > www.f2pool.com / static.f2pool.com and similar **marketing sites** (one origin checked it almost
   > daily, like someone watching their own pool dashboard). Actual mining is a persistent connection
   > on a stratum port with hit counts in the thousands.

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
   - None of the three exceptions weakens this: `openai_auth` (§5.4) and `mining` (§5.9) fire only on
     **explicitly enumerated** domain lists, and borrowed SNI domains are not on them;
     `domain_storm` (§5.6) does apply to any domain, but it judges *sustained rate*, not *which
     domain was visited* — REALITY's heartbeat is low-frequency, averages well under 1 hit/sec across
     the day, and never reaches the 150-hit floor. In other words: **the act of REALITY borrowing an
     SNI produces no signal on any axis.**
2. **Fleet-shared suppression**: if the same `(destination IP, port)` appears on
   `≥ FLEET_SHARED_MIN_SERVERS (5)` nodes → treated as a mass-deployed shared application
   (Telegram/Steam/STUN/monitoring probes/mainland ISP probe pools, etc.), listed at the end of
   FLEET_SUMMARY and excluded from threat judgment. **High-risk ports are exempt from this
   suppression as a rule** (attackers converging on the same target is not a free pass), except for
   `SHAREABLE_HIGH_RISK_PORTS` (§5.1), which have legitimate multi-customer shared uses.

   > **v1.2.0 fixed a doc-vs-implementation mismatch here**: the claim that shared destinations are
   > "excluded from threat judgment" was **never actually implemented** for the IP variant —
   > `fleet_shared` was computed and then only handed to report rendering for labelling; it never
   > reached `analyze_origin` (the domain variant, `fleet_shared_domains`, *was* wired in). It is now
   > wired in.
   >
   > This fix was forced by real data: port 7001 produced 20 findings across 20 unrelated customers,
   > all targeting the same set of cloud IPs with heavy overlap between customers — an application or
   > proxy backend. One of those destinations appeared on 6 distinct nodes, already past
   > `FLEET_SHARED_MIN_SERVERS`, yet was shielded by the "high-risk ports are exempt" rule. Wiring in
   > the suppression cut 20 findings to 6; the remainder were the same phenomenon below the 5-node
   > threshold, so 7001's threshold was then raised above the observed benign ceiling (15 hosts) to
   > `(20,40)`, following the same approach already used for port 22. That port's precision on this
   > dataset was 0/20.
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
| `SHAREABLE_HIGH_RISK_PORTS` | High-risk ports with legitimate multi-customer shared uses, which therefore **do** participate in fleet-shared suppression |
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
| `DOMAIN_STORM_MIN_HITS` / `_MIN_RATE` / `_MIN_SPAN_SEC` | Single-domain connection storm: hit floor 150 / sustained rate floor 2.0 per second / span floor 20 seconds |
| `DOMAIN_SCATTER_MIN_DISTINCT` / `DOMAIN_SCATTER_MAX_TOP_SHARE` | Distinct-domain-count threshold / max single-domain share for the domain-scatter rule |
| `MULTIPORT_PORT_MIN_IPS` / `_MIN_PORTS` / `_SUSPICIOUS` / `_MALICIOUS` | Multi-port horizontal scan: min IPs for a port to count as reused / reused ports per target IP / suspicious and malicious host-count thresholds |
| `MULTIPORT_MAX_HITS` / `_MAX_RUN` / `_MIN_HIGHRISK` | The multi-port axis's three noise filters: sustained-relationship ceiling / contiguous-port-block ceiling / minimum high-risk ports for the semantic anchor |
| `MINING_DOMAIN_HINTS` | Mining pool domain signature substrings |
| `MINING_STRATUM_PORTS` / `MINING_SESSION_MIN_HITS` | Stratum port set / sustained-session hit threshold used to separate "actually mining" from "just browsed a pool's website" |

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
- The single-domain connection storm axis depends on the upstream timestamp field, which only exists
  from 2026-07-29 onward. **Older dates carry no such field, so the axis is silently inert on those
  days** — that is missing input, not a missed detection.
- **This engine was calibrated on a fleet whose business is predominantly proxy / VPN traffic.**
  Several noise-reduction rules (`SHAREABLE_HIGH_RISK_PORTS`, the multi-port axis's four filters,
  7001's special threshold) target benign shapes specific to that environment — proxy pools,
  subscription node lists, port-mapping gateways, CDN alternate ports. In a different environment
  (a pure corporate intranet, say) these rules will be over-conservative and can be relaxed.
  Conversely, any newly added high-risk port must first be checked for collisions with the port
  ranges that environment's ordinary business uses.
- **The `openai_auth` axis produced zero findings across the most recent 25 days, so its code path has
  not been exercised in practice.** The threshold was lowered from 300 to 150 (300 was above the
  observed population maximum of 251, which had silently disabled the axis), but whether it fires
  correctly after that change has not been confirmed against a real sample.
- Output not yet reviewed entry by entry: both engines' SUSPICIOUS lists, and the `domain_scatter`
  and `torrent` entries.

## 12. Changelog

### v1.2.0

This release came out of a **manual, log-by-log review** of 25 days of full data (reading the raw
logs and comparing them line by line against the engine's output). It fixes three sources of false
positives and two structural blind spots.

**Missed-detection fixes**

- **New `multiport` axis (multi-port horizontal scan, port-agnostic).** Previously the horizontal axis
  only looked at the high-risk port allowlist and the vertical axis only at ports ≤1024, so neither
  covered the most common scanner behaviour of all — sweeping an entire netblock with a custom port
  list. In testing, an origin was re-scanning whole hosting netblocks on
  2375/2376/5601/6697/7001/8118 every 40–60 minutes, and the old engine rated the entire node
  "0 malicious / 0 suspicious / 12 clean". See §5.8 for the four accompanying noise filters.
- **`HIGH_RISK_PORTS` expanded**: added 2375/2376 (Docker), 4444 (Metasploit), 5601 (Kibana),
  7001 (WebLogic), 9200 (Elasticsearch), 11211 (memcached), 2181 (ZooKeeper), 5984 (CouchDB),
  623 (IPMI), 6667/6697 (IRC), 5432 (PostgreSQL). **Deliberately excludes 27017** (collides with
  Steam's game server port range — see §5.1).
- **New `mining` / `mining_web` axes**: mining pool domains were previously invisible entirely,
  because domains are immune to every other axis.
- **`OPENAI_AUTH_MIN_HITS` lowered from 300 to 150**: the observed population maximum for daily auth
  hits was only 251, so a threshold of 300 sat above the entire population and had silently disabled
  the axis (0 findings in 25 days). The real discriminator is the product-usage share (≤5%); the hit
  count only filters out small samples.

**False-positive fixes**

- **`domain_concurrency` overturned and rewritten as `domain_storm`** (§5.6). The old axis alone
  produced 2166 findings — 87% of all findings — hitting Google / Cloudflare / Apple / Netflix /
  Microsoft telemetry. Root cause: `count ÷ distinct_secs` measures how many connections a client
  opens per event (a browser's 6+1 per-host pool makes the ratio exactly 7), not burstiness, and is
  insensitive to time span. After switching to sustained rate, findings dropped to 2 (warning) and
  3 (info).
- **Four noise filters on the new `multiport` axis** (§5.8): proxy pools, subscription node lists,
  port-mapping gateways, and Cloudflare alternate ports all match the raw shape. The requirement that
  the semantic anchor be evaluated **per target host** is especially important.
- **`mining` axis tiering** (§5.9): the first version rated "browsing a mining pool's website" as
  SUSPICIOUS; all 23 findings were single-digit-hit visits to pool marketing sites on port 443. Now
  split into `mining` (SUSPICIOUS) and `mining_web` (INFO).

**Structural fixes**

- **`fleet_shared` is now actually passed to `analyze_origin`**: the IP-side fleet-shared suppression
  that §7.2 has always described was **never implemented** — the set was only used for report
  labelling and never entered the judgment logic (the domain-side variant *was* wired in).
- **New `SHAREABLE_HIGH_RISK_PORTS`**: separates high-risk ports that ordinary business would never
  dial (telnet/RDP/SMB/Docker — exempt from shared suppression) from those with legitimate
  multi-customer shared uses (app panels / managed databases / IRC / proxy backends — subject to it).
- **`PORT_THRESHOLDS[7001] = (20,40)`**: this port has a large legitimate shared-use population on
  this fleet; measured precision was 0/20 with a benign ceiling of 15 hosts, so the threshold was
  raised above that ceiling following the approach already used for port 22.
- **xref now gets fleet context**: `load_warning_status` previously called `analyze_origin(o)` bare,
  with no fleet parameters at all, effectively disabling shared suppression and making xref more
  sensitive than an actual warning run. It now builds an index from that day's full warning set.

**New tunable parameters**: `SHAREABLE_HIGH_RISK_PORTS`, `MULTIPORT_*` (7), `DOMAIN_STORM_*` (3),
`MINING_DOMAIN_HINTS`, `MINING_STRATUM_PORTS`, `MINING_SESSION_MIN_HITS`.
**Removed**: `DOMAIN_CONCURRENCY_MIN_HITS`, `DOMAIN_CONCURRENCY_RATIO_MIN`.

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
