# -*- coding: utf-8 -*-
# SentinelX — Copyright (c) 2026 Uzumaru
# SPDX-License-Identifier: CC-BY-NC-4.0
# 可自由使用/修改/再分发，须署名 Uzumaru 与 SentinelX，且不得用于商业目的。详见 LICENSE。
"""连接日志分类引擎 —— 成功连接（info）版。

数据是「每天一份的 24 小时快照」，目录形如:
    <Archive>/info_YYYY-MM-DD/raw/<SERVER>.txt   （输入）
    <Archive>/info_YYYY-MM-DD/result/<SERVER>.txt （输出）
自动发现所有 info_* 日期目录，逐日出报告，跨天关联生成
    <Archive>/FLEET_SUMMARY_info.txt

这是 SUCCESS 日志（TCP 连接真的建成了），所以同样的扫描指纹在这里意味着
探测/扫描「已经得手」而不仅是尝试——判定比失败日志更应重视。
交叉比对：同日期的 warning_YYYY-MM-DD 分析结果（若在场）用来佐证。
"""
import re
import statistics
from pathlib import Path
from collections import defaultdict

BASE_DIR = Path(__file__).resolve().parent

ORIGIN_RE = re.compile(r"^(\S+)\s{2,}(\d+)\s*$")
DEST_RE = re.compile(r"^\s+(\S+?):(\d+):\s*(\d+)\s*$")
EXCLUDED_RE = re.compile(
    r"^\s+\[excluded:\s*(\S+?):(\d+),\s*(\d+)\s*hits,\s*([\d.]+)%.*\]\s*$"
)
IPV4_RE = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")

# 横向高危端口：成功连接语境下，port 22 也纳入（SSH 成功多主机连接确实出现过），
# 但 22 的正常多主机运维用途远多于其它端口，所以给它单独更高的阈值。
HIGH_RISK_PORTS = {
    22, 23, 2323, 3389, 445, 1433, 3306, 5900, 8291, 37215,
    52869, 7547, 1900, 6379, 135, 139, 21,
}
TELNET_PORTS = {23, 2323}
# (suspicious_min, malicious_min) on distinct successful raw-IP destinations.
PORT_THRESHOLDS = {
    22: (8, 25),   # 24h 快照下，8 台起提示、25 台起判恶意；配合跨天复现豁免
}
DEFAULT_THRESHOLDS = (5, 20)

# 纵向单目标端口扫描（成功）。成功比失败更严重，阈值收得更紧。
N_LOW_PORTS_SUSPICIOUS = 8
N_LOW_PORTS_MALICIOUS = 15
COMMON_SERVICE_PORTS = {
    20, 21, 22, 25, 53, 80, 110, 123, 143, 443, 465, 587,
    853, 989, 990, 993, 995, 3478, 5222, 5223, 5228, 8080, 8443,
}

TORRENT_PORTS = {6881, 6882, 6883, 6884, 6885, 6886, 6887, 6888, 6889, 6969, 1337, 51413, 6771}
TORRENT_MIN_DISTINCT = 3

FLEET_SHARED_MIN_SERVERS = 5

# OpenAI/ChatGPT 鉴权滥用（账号注册机/token 农场）检测：与 classify_logs.py 一致
# （见该文件同名常量注释）。正常用户即使经代理/中转访问量很大，鉴权域名次数相对
# 真实产品域名次数占比也很小；按比例判定，避免误判重度正常用户。
OPENAI_AUTH_DOMAINS = {"auth.openai.com", "auth0.openai.com", "external.auth.openai.com"}
OPENAI_USAGE_DOMAINS = {
    "chat.openai.com", "chatgpt.com", "api.openai.com", "platform.openai.com",
    "ios.chat.openai.com", "android.chat.openai.com", "sora.chatgpt.com", "ws.chatgpt.com",
}
OPENAI_AUTH_MIN_HITS = 300
OPENAI_USAGE_MAX_RATIO = 0.05

# 域名目的地分布过散：与 classify_logs.py 一致（见该文件同名常量注释），用同一批
# 全量数据校准（不同域名数中位数 7，p90≈251，p95≈539）。
DOMAIN_SCATTER_MIN_DISTINCT = 300
DOMAIN_SCATTER_MAX_TOP_SHARE = 0.10

# 机队共享域名白名单：与 classify_logs.py 一致（见该文件同名常量注释）。
FLEET_SHARED_DOMAIN_MIN_SERVERS = 15

# 跨天升/降级参数。当天目标里『新面孔』占比 <= NOVELTY_STABLE 视为稳定复现（降级
# WATCH）；连续 ESCALATE_STREAK_DAYS 天都是"持续换目标的可疑"则升级 MALICIOUS。
NOVELTY_STABLE = 0.5
ESCALATE_STREAK_DAYS = 3

# REALITY 借用 SNI 的握手目的地（域名）——本引擎所有威胁轴只对裸 IPv4 计数，
# 域名天然不参与判定，故 IDC 客户自建 REALITY 访问 visa.cn/qualcomm.cn 等不会误杀。
REALITY_SNI_HINTS = [
    "visa", "qualcomm", "toutiao", "apple.com", "icloud", "amd.com",
    "dell.com", "cisco", "microsoft", "gstatic", "cloudflare",
]

KNOWN_SERVICE_HINTS = [
    "google", "gstatic", "apple", "microsoft", "microsoftapp", "cloudflare",
    "telegram", "grammarly", "figma", "chatgpt", "feishu", "bing", "epicgames",
    "vscode", "openai", "amd.com", "tiktok", "youtube", "reddit", "icloud",
    "mapbox", "nvidia", "visa", "qualcomm", "toutiao", "ipify", "ip.sb",
    "windowsupdate", "delivery.mp.microsoft.com", "office.com", "xboxservices",
    "digicert", "skype",
]

SEV_ORDER = {"CLEAN": 0, "WATCH": 1, "SUSPICIOUS": 2, "MALICIOUS": 3}


def sev_max(a, b):
    return a if SEV_ORDER[a] >= SEV_ORDER[b] else b


def is_ipv4(host):
    m = IPV4_RE.match(host)
    if not m:
        return False
    return all(0 <= int(g) <= 255 for g in m.groups())


class Dest:
    __slots__ = ("host", "port", "count")

    def __init__(self, host, port, count):
        self.host = host
        self.port = port
        self.count = count


class Origin:
    __slots__ = ("ip", "total", "dests", "excluded", "server_hint")

    def __init__(self, ip, total):
        self.ip = ip
        self.total = total
        self.dests = []
        self.excluded = None
        self.server_hint = None


def parse_file(path):
    origins = []
    current = None
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for raw_line in f:
            line = raw_line.rstrip("\n")
            if not line.strip():
                continue
            if line.startswith("Connection Log Info Report") or \
               line.startswith("All-time info hits") or \
               line.startswith("Last-24h") or \
               line.startswith("Note:") or \
               line.startswith("Generated at:"):
                continue

            m_excl = EXCLUDED_RE.match(line)
            if m_excl and current is not None:
                host, port, count, pct = m_excl.groups()
                current.excluded = (host, int(port), int(count), float(pct))
                continue

            m_dest = DEST_RE.match(line)
            if m_dest and current is not None:
                host, port, count = m_dest.groups()
                current.dests.append(Dest(host, int(port), int(count)))
                continue

            m_origin = ORIGIN_RE.match(line)
            if m_origin:
                ip, total = m_origin.groups()
                current = Origin(ip, int(total))
                origins.append(current)
                continue
    return origins


def effective_dests(origin):
    ds = list(origin.dests)
    if origin.excluded:
        host, port, count, _pct = origin.excluded
        ds.append(Dest(host, port, count))
    return ds


def analyze_origin(origin, warning_status, fleet_shared_domains=frozenset()):
    dests = effective_dests(origin)
    by_port = defaultdict(list)
    by_ip = defaultdict(list)
    for d in dests:
        if is_ipv4(d.host):
            by_port[d.port].append(d)
            by_ip[d.host].append(d)

    findings = []

    # --- 轴 1：横向高危端口（成功连接 = 扫描已得手）---
    for port, plist in sorted(by_port.items()):
        if port not in HIGH_RISK_PORTS:
            continue
        n_ips = len(plist)
        counts = [d.count for d in plist]
        total_hits = sum(counts)
        mean = statistics.fmean(counts)
        lo, hi = min(counts), max(counts)
        susp_min, mal_min = PORT_THRESHOLDS.get(port, DEFAULT_THRESHOLDS)
        is_telnet = port in TELNET_PORTS
        label = "telnet" if is_telnet else ("SSH" if port == 22 else "高危")

        sev = None
        if n_ips >= mal_min:
            sev = "MALICIOUS"
            reason = (
                f"该 origin 当日在端口 {port}（{label}）上成功连接了 {n_ips} 个互不相关的公网 IP"
                f"（单 IP 成功次数 {lo}-{hi}，均值≈{mean:.0f}，合计 {total_hits} 次成功）。这是真实建成的连接，"
                f"一台正常 LAN 客户端不会在 24 小时内对这么多不相关随机主机在该端口反复建成连接——"
                f"是扫描/探测已经得手、对外发起规模化 {label} 连接的信号。"
            )
        elif n_ips >= susp_min:
            sev = "SUSPICIOUS"
            reason = (
                f"该 origin 当日在端口 {port}（{label}）上成功连接了 {n_ips} 个互不相关的公网 IP"
                f"（单 IP 成功次数 {lo}-{hi}）。未达 {mal_min} 个 IP 的恶意线，但明显超出该端口正常使用规模"
                f"（多为管理员对少数几台已知服务器的合法访问），建议人工复核。"
            )
        if sev:
            findings.append({
                "axis": "horiz", "port": port, "target": None,
                "key_set": frozenset(d.host for d in plist),
                "sev": sev, "kind": "threat",
                "detail": (f"  端口 {port}: {n_ips} 个不同公网 IP 成功连接，单 IP 次数 {lo}-{hi}"
                           f"（均值 {mean:.1f}，该端口合计 {total_hits} 次）"),
                "reason": reason,
            })

    # --- 轴 2：纵向单目标端口扫描（成功）---
    for ip, dlist in sorted(by_ip.items()):
        ports_sorted = sorted(d.port for d in dlist)
        low_ports = [p for p in ports_sorted if p <= 1024 and p not in COMMON_SERVICE_PORTS]
        n_low = len(low_ports)
        n_ports = len(dlist)
        counts = [d.count for d in dlist]
        mean = statistics.fmean(counts)
        lo, hi = min(counts), max(counts)

        sev = None
        if n_low >= N_LOW_PORTS_MALICIOUS:
            sev = "MALICIOUS"
            reason = (
                f"该 origin 当日对单一公网 IP {ip} 在 {n_low} 个 1024 以内的常见/特权端口"
                f"（{low_ports[0]}-{low_ports[-1]}，已剔除 80/443/53 等正常服务端口）上成功建立连接，"
                f"该 IP 共涉及 {n_ports} 个端口。成功地对同一主机顺序敲这么多特权端口——"
                f"单目标端口扫描（nmap 式）且已得手。"
            )
        elif n_low >= N_LOW_PORTS_SUSPICIOUS:
            sev = "SUSPICIOUS"
            reason = (
                f"该 origin 当日对单一公网 IP {ip} 在 {n_low} 个 1024 以内端口上成功连接"
                f"（{low_ports[0]}-{low_ports[-1]}，已剔除常见服务端口）。未达 {N_LOW_PORTS_MALICIOUS} 个"
                f"低位端口的恶意线，但明显异于正常访问，疑似单目标端口扫描，建议人工复核。"
            )
        if sev:
            findings.append({
                "axis": "vert", "port": None, "target": ip,
                "key_set": frozenset(low_ports),
                "sev": sev, "kind": "threat",
                "detail": (f"  目标 IP {ip}: 成功命中 {n_low} 个 1024 以内非常见端口"
                           f"（{low_ports[0]}-{low_ports[-1]}），该 IP 共 {n_ports} 个端口，"
                           f"单端口次数 {lo}-{hi}（均值 {mean:.1f}）— 疑似单目标端口扫描已得手"),
                "reason": reason,
            })

    # --- 轴 3：P2P/BitTorrent ---
    bt_ips = set()
    for port in TORRENT_PORTS:
        for d in by_port.get(port, []):
            bt_ips.add(d.host)
    if len(bt_ips) >= TORRENT_MIN_DISTINCT:
        findings.append({
            "axis": "torrent", "port": None, "target": None,
            "key_set": frozenset(bt_ips),
            "sev": "CLEAN", "kind": "torrent",
            "detail": f"  P2P/BT: 成功连接 {len(bt_ips)} 个不同 IP 的 BT 特征端口",
            "reason": (
                f"命中 {len(bt_ips)} 个不同 IP 在 BitTorrent 协议特征端口"
                f"（6881-6889/6969/1337/51413 等）上成功连接，属种子下载/做种行为，"
                f"建议核实是否符合主机/VPS 服务条款。"
            ),
        })

    # --- 轴 4：OpenAI/ChatGPT 鉴权滥用（注册机/账号农场）---
    auth_hits = sum(d.count for d in dests if d.host in OPENAI_AUTH_DOMAINS)
    usage_hits = sum(d.count for d in dests if d.host in OPENAI_USAGE_DOMAINS)
    if auth_hits >= OPENAI_AUTH_MIN_HITS:
        ratio = usage_hits / (auth_hits + usage_hits) if (auth_hits + usage_hits) else 0.0
        if ratio <= OPENAI_USAGE_MAX_RATIO:
            findings.append({
                "axis": "openai_auth", "port": None, "target": None,
                "key_set": frozenset(["openai_auth"]),
                "sev": "SUSPICIOUS", "kind": "threat",
                "detail": (f"  OpenAI/ChatGPT 鉴权域名成功连接 {auth_hits} 次 vs 产品域名(chat/api) {usage_hits} 次"
                           f"（产品占比 {ratio:.1%}）"),
                "reason": (
                    f"该 origin 当日成功连接 OpenAI/ChatGPT 鉴权域名（auth.openai.com 等）{auth_hits} 次，"
                    f"同期成功连接实际聊天/API 域名（chat.openai.com/api.openai.com 等）仅 {usage_hits} 次"
                    f"（产品占比 {ratio:.1%}）。正常用户即使经代理/中转访问量很大，鉴权流量也应远小于实际"
                    f"产品使用量——只反复走鉴权流程、几乎不用产品本身，是账号注册机/token 农场的典型特征。"
                    f"本判定基于当日总连接数比例（日志无请求路径），建议人工核实。"
                ),
            })

    # --- 轴 5：域名目的地分布过散 ---
    domain_counts = defaultdict(int)
    for d in dests:
        if not is_ipv4(d.host) and d.host not in fleet_shared_domains:
            domain_counts[d.host] += d.count
    if domain_counts:
        n_domains = len(domain_counts)
        total_domain_hits = sum(domain_counts.values())
        top_host, top_count = max(domain_counts.items(), key=lambda kv: kv[1])
        top_share = top_count / total_domain_hits if total_domain_hits else 0.0
        if n_domains >= DOMAIN_SCATTER_MIN_DISTINCT and top_share <= DOMAIN_SCATTER_MAX_TOP_SHARE:
            findings.append({
                "axis": "domain_scatter", "port": None, "target": None,
                "key_set": frozenset(["domain_scatter"]),
                "sev": "WATCH", "kind": "threat",
                "detail": (f"  域名目的地分布很散(已剔除机队共享域名): {n_domains} 个不同域名，"
                           f"最大单域名占比 {top_share:.1%}（{top_host}），域名合计 {total_domain_hits} 次"),
                "reason": (
                    f"剔除机队共享域名（在 >={FLEET_SHARED_DOMAIN_MIN_SERVERS} 台节点上都出现过的通用"
                    f"CDN/广告/大厂域名）后，该 origin 当日仍访问了 {n_domains} 个自己独有的不同域名，"
                    f"没有任何单一域名占比超过 {DOMAIN_SCATTER_MAX_TOP_SHARE:.0%}"
                    f"（最大的是 {top_host}，占 {top_share:.1%}）。本引擎其它轴都不对域名计数（避免"
                    f"误杀 REALITY/SNI 借用流量），但这种「域名很多、没有主导目标、还都不是机队通用"
                    f"基础设施」的分布本身也值得关注——可能是共享代理/中转在承载很多不同真实用户的"
                    f"流量（良性），也可能是批量探测/自动化访问大量域名。暂归为 WATCH（观察级），"
                    f"不计入威胁告警，建议留意是否持续。"
                ),
            })

    # --- 轴 6：与同日期失败日志交叉比对 ---
    wkey = (origin.server_hint.upper(), origin.ip) if origin.server_hint else None
    if wkey and warning_status.get(wkey) in ("MALICIOUS", "SUSPICIOUS"):
        wsev = warning_status[wkey]
        findings.append({
            "axis": "xref", "port": None, "target": None,
            "key_set": frozenset([wkey]),
            "sev": "SUSPICIOUS" if wsev == "SUSPICIOUS" else "MALICIOUS",
            "kind": "threat",
            "detail": f"  [交叉比对] 同日期失败日志中该 origin 状态: {wsev}",
            "reason": (
                f"交叉比对：该 origin 在同日期失败连接（端口扫描）分析里已被判定为 {wsev}。"
                f"本报告中的成功连接进一步佐证其确在对外发起规模化连接，两份报告应一并参考。"
            ),
        })

    return findings


# ---------------- 跨天 & 机队级上下文（与 warning 引擎一致） ----------------

def jaccard(a, b):
    if not a and not b:
        return 1.0
    u = len(a | b)
    return len(a & b) / u if u else 0.0


def build_fleet_index(days):
    dp_servers = defaultdict(set)
    domain_servers = defaultdict(set)
    for _date, per_server in days:
        for server, origins in per_server.items():
            for o in origins:
                for d in effective_dests(o):
                    if is_ipv4(d.host):
                        if d.port not in HIGH_RISK_PORTS:
                            dp_servers[(d.host, d.port)].add(server)
                    else:
                        domain_servers[d.host].add(server)
    fleet_shared = {k for k, ss in dp_servers.items() if len(ss) >= FLEET_SHARED_MIN_SERVERS}
    fleet_shared_domains = {h for h, ss in domain_servers.items() if len(ss) >= FLEET_SHARED_DOMAIN_MIN_SERVERS}
    return fleet_shared, dp_servers, fleet_shared_domains, domain_servers


def _novelty(tgt, pool):
    """当天目标里『新面孔』的占比（不在 pool 中的比例）。0=全是老目标。"""
    tgt = set(tgt)
    if not tgt:
        return 0.0
    return len(tgt - set(pool)) / len(tgt)


def apply_cross_day(all_findings, all_dates):
    """跨天关联，逐天沿时间线判定（与 warning 引擎一致）。
      - 当天目标多为老面孔（新目标占比 <= NOVELTY_STABLE）→ WATCH，连续计数清零；
      - 多为新面孔 → 维持 SUSPICIOUS，连续计数 +1；
      - 连续计数 >= ESCALATE_STREAK_DAYS → 升级 MALICIOUS；
      - 缺数据/CLEAN/WATCH 打断连续计数；
      - 未升级、跨多天、始终是老池子子集的签名回溯降级 WATCH（首次出现不吃亏）。
    xref（与失败日志交叉比对）与 torrent 不参与跨天判定。"""
    ordered = sorted(all_dates)

    groups = defaultdict(dict)  # gkey -> {date: finding}
    for (date, server, oip), flist in all_findings.items():
        for f in flist:
            if f["kind"] != "threat" or f["axis"] not in ("horiz", "vert"):
                f["final_sev"] = f["sev"]
                f["repeat_note"] = None
                continue
            gkey = (server, oip, f["axis"], f["port"], f["target"])
            if date in groups[gkey]:
                prev = groups[gkey][date]
                prev["key_set"] = frozenset(set(prev["key_set"]) | set(f["key_set"]))
                f["final_sev"] = prev.get("final_sev", prev["sev"])
                f["repeat_note"] = None
            else:
                groups[gkey][date] = f

    for gkey, byday in groups.items():
        present = sorted(byday)
        prior_pool = set()
        streak = 0
        escalated = False
        for d in ordered:
            if d not in byday:
                streak = 0
                continue
            f = byday[d]
            tgt = set(f["key_set"])
            if f["sev"] == "MALICIOUS":
                f["final_sev"] = "MALICIOUS"
                f["repeat_note"] = "当日单日规模已达恶意判定线。"
                streak += 1
            else:
                nov = _novelty(tgt, prior_pool)
                if prior_pool and nov <= NOVELTY_STABLE:
                    f["final_sev"] = "WATCH"
                    f["repeat_note"] = (
                        f"与此前若干天目标高度重合（当日新目标占比 {nov:.0%}）——稳定复现，"
                        f"判为常驻自动化/运维，降级观察。"
                    )
                    streak = 0
                else:
                    streak += 1
                    if streak >= ESCALATE_STREAK_DAYS:
                        f["final_sev"] = "MALICIOUS"
                        f["repeat_note"] = (
                            f"连续 {streak} 天持续可疑，且每天目标多为新面孔（当日新目标占比 {nov:.0%}）"
                            f"——持续性扫描/探测，升级为恶意。"
                        )
                        escalated = True
                    else:
                        f["final_sev"] = "SUSPICIOUS"
                        if not prior_pool:
                            f["repeat_note"] = "首次出现（此前无历史可比对），暂判可疑，优先复核。"
                        else:
                            f["repeat_note"] = (
                                f"当日目标多为新面孔（新目标占比 {nov:.0%}），未构成稳定复现，维持可疑；"
                                f"已连续 {streak} 天，达 {ESCALATE_STREAK_DAYS} 天将升级为恶意。"
                            )
            prior_pool |= tgt

        if not escalated and len(present) >= 2:
            for d in present:
                f = byday[d]
                if f["final_sev"] != "SUSPICIOUS":
                    continue
                others = set()
                for d2 in present:
                    if d2 != d:
                        others |= set(byday[d2]["key_set"])
                nov = _novelty(set(f["key_set"]), others)
                if nov <= NOVELTY_STABLE:
                    f["final_sev"] = "WATCH"
                    f["repeat_note"] = (
                        f"其目标集是其它天已见目标的子集（新目标占比 {nov:.0%}）——整体稳定复现，"
                        f"判为常驻自动化，降级观察。"
                    )
    return all_findings


# ---------------- 报告渲染 ----------------

def clean_summary_hint(origins):
    hostnames_seen = set()
    reality_seen = set()
    sample_counts = []
    for o in origins:
        for d in o.dests:
            if not is_ipv4(d.host):
                low = d.host.lower()
                for hint in KNOWN_SERVICE_HINTS:
                    if hint in low:
                        hostnames_seen.add(hint)
                        break
                for hint in REALITY_SNI_HINTS:
                    if hint in low:
                        reality_seen.add(hint)
                        break
            sample_counts.append(d.count)
    top_services = ", ".join(sorted(hostnames_seen)[:6]) if hostnames_seen else "常见域名/服务"
    hi = max(sample_counts) if sample_counts else 0
    lo = min(sample_counts) if sample_counts else 0
    return top_services, lo, hi, sorted(reality_seen)


def top_dest_for_origin(origin):
    candidates = [(d, False) for d in origin.dests]
    if origin.excluded:
        host, port, count, _pct = origin.excluded
        candidates.append((Dest(host, port, count), True))
    if not candidates:
        return None, False
    return max(candidates, key=lambda c: c[0].count)


def format_origin_block(origin, sev, findings):
    lines = [f"[{sev}] Origin {origin.ip} (总成功次数 {origin.total})"]
    for f in findings:
        lines.append(f["detail"])
    if origin.excluded:
        host, port, count, pct = origin.excluded
        lines.append(f"  [已被原报告排除的高频噪音: {host}:{port}, {count} 次, 占该 origin 总量 {pct}%]")
    for f in findings:
        lines.append(f"  原因: {f['reason']}")
        if f.get("repeat_note"):
            lines.append(f"  跨天: {f['repeat_note']}")
    return "\n".join(lines)


def render_server_report(server, origins, findings_by_origin, fleet_shared):
    per_origin = {}
    for o in origins:
        flist = findings_by_origin.get(o.ip, [])
        threats = [f for f in flist if f["kind"] == "threat"]
        torrents = [f for f in flist if f["kind"] == "torrent"]
        sev = "CLEAN"
        for f in threats:
            sev = sev_max(sev, f["final_sev"])
        per_origin[o.ip] = (sev, threats, torrents)

    buckets = {"MALICIOUS": [], "SUSPICIOUS": [], "WATCH": [], "CLEAN": []}
    for o in origins:
        buckets[per_origin[o.ip][0]].append(o)
    torrent_origins = [o for o in origins if per_origin[o.ip][2]]

    out = []
    out.append(f"连接日志（成功）分类报告 — {server}")
    out.append(
        f"Origin 总数: {len(origins)} | 恶意/已得手: {len(buckets['MALICIOUS'])} | "
        f"可疑: {len(buckets['SUSPICIOUS'])} | 关注(跨天复现): {len(buckets['WATCH'])} | "
        f"P2P/BT: {len(torrent_origins)} | 干净: {len(buckets['CLEAN'])}"
    )
    out.append("")

    out.append("===== 逐 IP 状态总览 (状态 / 是否得手 / P2P / 总成功次数 / 最多目的地) =====")
    for o in sorted(origins, key=lambda x: -x.total):
        sev, threats, torrents = per_origin[o.ip]
        td, td_excl = top_dest_for_origin(o)
        if td:
            td_str = f"{td.host}:{td.port} ({td.count}次)"
            if td_excl:
                td_str += " [原报告已判定为重复噪音]"
        else:
            td_str = "(无记录)"
        out.append(
            f"{o.ip:<16} | 状态:{sev:<10} | 得手:{'是' if threats else '否'} | "
            f"P2P/BT:{'是' if torrents else '否'} | 总成功次数:{o.total:<10} | 最多目的地: {td_str}"
        )
    out.append("")

    for level, title in [("MALICIOUS", "MALICIOUS 详情（疑似扫描/入侵已得手）"),
                         ("SUSPICIOUS", "SUSPICIOUS 详情（可疑，建议人工复核）"),
                         ("WATCH", "WATCH 详情（跨天稳定复现，疑似常驻自动化/运维，仅关注）")]:
        rows = sorted(buckets[level], key=lambda x: -x.total)
        if rows:
            out.append(f"===== {title} =====")
            for o in rows:
                _sev, threats, _t = per_origin[o.ip]
                out.append(format_origin_block(o, level, threats))
                out.append("")

    torrent_only = [o for o in torrent_origins if per_origin[o.ip][0] == "CLEAN"]
    if torrent_only:
        out.append("===== P2P/BitTorrent 标记详情（ToS 风险，非安全威胁） =====")
        for o in sorted(torrent_only, key=lambda x: -x.total):
            out.append(f"Origin {o.ip} (总成功次数 {o.total})")
            for f in per_origin[o.ip][2]:
                out.append(f"  {f['reason']}")
            out.append("")

    dest_totals = {}
    for o in origins:
        for d in o.dests:
            e = dest_totals.setdefault((d.host, d.port), [0, set()])
            e[0] += d.count
            e[1].add(o.ip)
        if o.excluded:
            host, port, count, _p = o.excluded
            e = dest_totals.setdefault((host, port), [0, set()])
            e[0] += count
            e[1].add(o.ip)
    top_dests = sorted(dest_totals.items(), key=lambda kv: -kv[1][0])[:10]
    out.append("===== 本服务器最活跃目的地 TOP 10（跨全部 origin 汇总） =====")
    if top_dests:
        for (host, port), (total, oips) in top_dests:
            tag = "  [机队共享应用]" if (host, port) in fleet_shared else ""
            out.append(f"  {host}:{port} — 合计 {total} 次，来自 {len(oips)} 个 origin{tag}")
    else:
        out.append("（无）")
    out.append("")

    out.append("===== CLEAN 汇总说明 =====")
    clean = buckets["CLEAN"]
    if clean:
        top_services, lo, hi, reality = clean_summary_hint(clean)
        out.append(
            f"干净 origin 共 {len(clean)} 个：目的地多为可识别的正规域名/服务"
            f"（{top_services} 等），无规模化扫描/入侵或 P2P 特征。"
        )
        if reality:
            out.append(
                f"其中出现 {', '.join(reality)} 等大厂域名目的地——符合 IDC 客户自建 REALITY 节点"
                f"「借用知名域名做 SNI」的握手特征，属预期流量，非可疑连接（本引擎对域名目的地不做威胁判定）。"
            )
        out.append("具体 IP 列表: " + ", ".join(o.ip for o in clean))
    else:
        out.append("（无）")

    return {
        "report_text": "\n".join(out),
        "n_origins": len(origins),
        "buckets": {k: [o.ip for o in v] for k, v in buckets.items()},
        "torrent": [o.ip for o in torrent_origins],
    }


# ---------------- 同日期 warning 交叉状态 ----------------

def load_warning_status(date):
    """用同日期 warning 引擎的检测逻辑，产出 (SERVER, origin_ip) -> severity。
    warning 目录不在场时返回 {}（可选上下文，非硬依赖）。"""
    status = {}
    wdir = BASE_DIR / f"warning_{date}" / "raw"
    if not wdir.is_dir():
        return status
    try:
        import importlib
        wlog = importlib.import_module("classify_logs")
    except Exception:
        return status
    for path in sorted(wdir.glob("*.txt")):
        try:
            origins = wlog.parse_file(path)
        except Exception:
            continue
        for o in origins:
            findings = wlog.analyze_origin(o)
            sev = "CLEAN"
            for f in findings:
                if f["kind"] == "threat":
                    sev = wlog.sev_max(sev, f["sev"])
            if sev != "CLEAN":
                status[(path.stem.upper(), o.ip)] = sev
    return status


# ---------------- 主流程 ----------------

def discover_day_dirs(prefix):
    days = []
    for p in sorted(BASE_DIR.glob(f"{prefix}_*")):
        raw = p / "raw"
        if raw.is_dir():
            date = p.name[len(prefix) + 1:]
            days.append((date, p, raw))
    return days


def main():
    day_dirs = discover_day_dirs("info")
    if not day_dirs:
        print("未发现 info_YYYY-MM-DD/raw 目录。")
        return

    loaded = []  # (date, dir, {server:[Origin]}, warning_status)
    for date, dpath, raw in day_dirs:
        per_server = {}
        for f in sorted(raw.glob("*.txt")):
            origins = parse_file(f)
            for o in origins:
                o.server_hint = f.stem
            per_server[f.stem] = origins
        loaded.append((date, dpath, per_server, load_warning_status(date)))

    fleet_shared, dp_servers, fleet_shared_domains, domain_servers = build_fleet_index(
        [(d, ps) for d, _dp, ps, _w in loaded])

    all_findings = {}
    for date, _dpath, per_server, wstatus in loaded:
        for server, origins in per_server.items():
            for o in origins:
                all_findings[(date, server, o.ip)] = analyze_origin(o, wstatus, fleet_shared_domains)

    apply_cross_day(all_findings, [d for d, _dp, _ps, _w in loaded])

    fleet_rows = []
    for date, dpath, per_server, _w in loaded:
        result_dir = dpath / "result"
        result_dir.mkdir(exist_ok=True)
        for server, origins in per_server.items():
            fbo = {o.ip: all_findings[(date, server, o.ip)] for o in origins}
            r = render_server_report(server, origins, fbo, fleet_shared)
            (result_dir / f"{server}.txt").write_text(r["report_text"] + "\n", encoding="utf-8")
            for sev, ips in r["buckets"].items():
                for ip in ips:
                    fleet_rows.append((date, server, ip, sev, ip in r["torrent"]))

    write_fleet_summary(loaded, all_findings, fleet_shared, dp_servers, fleet_shared_domains, domain_servers)

    n_mal = sum(1 for _d, _s, _i, sev, _t in fleet_rows if sev == "MALICIOUS")
    n_susp = sum(1 for _d, _s, _i, sev, _t in fleet_rows if sev == "SUSPICIOUS")
    n_watch = sum(1 for _d, _s, _i, sev, _t in fleet_rows if sev == "WATCH")
    n_bt = sum(1 for _d, _s, _i, _sev, t in fleet_rows if t)
    print(f"[info] 处理 {len(loaded)} 天。MALICIOUS={n_mal} SUSPICIOUS={n_susp} "
          f"WATCH={n_watch} P2P/BT={n_bt}。跨天汇总: FLEET_SUMMARY_info.txt")


def finding_trigger(f):
    """一句话说明这条 finding 因何触发（用于汇总清单）。"""
    if f["axis"] == "horiz":
        port = f["port"]
        label = "telnet" if port in TELNET_PORTS else ("SSH" if port == 22 else "高危")
        susp, mal = PORT_THRESHOLDS.get(port, DEFAULT_THRESHOLDS)
        return (f"横向高危端口（成功）— 端口 {port}（{label}）成功连接 {len(f['key_set'])} 个"
                f"互不相关公网 IP（阈值 可疑≥{susp}/恶意≥{mal}）")
    if f["axis"] == "vert":
        return (f"纵向单目标端口扫描（成功）— 对 {f['target']} 成功命中 {len(f['key_set'])} 个 ≤1024 非常见端口"
                f"（阈值 可疑≥{N_LOW_PORTS_SUSPICIOUS}/恶意≥{N_LOW_PORTS_MALICIOUS}）")
    if f["axis"] == "torrent":
        return f"P2P/BT — 成功连接 {len(f['key_set'])} 个不同 IP 的 BitTorrent 特征端口（阈值≥{TORRENT_MIN_DISTINCT}）"
    if f["axis"] == "xref":
        return "交叉比对 — 同日期失败日志中该 origin 已被判定为威胁，成功日志进一步佐证"
    if f["axis"] == "openai_auth":
        return f"OpenAI/ChatGPT 鉴权滥用 — {f['detail'].strip()}（阈值 鉴权≥{OPENAI_AUTH_MIN_HITS} 且产品占比≤{OPENAI_USAGE_MAX_RATIO:.0%}）"
    if f["axis"] == "domain_scatter":
        return (f"域名目的地分布过散 — {f['detail'].strip()}"
                f"（阈值 不同域名≥{DOMAIN_SCATTER_MIN_DISTINCT} 且最大域名占比≤{DOMAIN_SCATTER_MAX_TOP_SHARE:.0%}）")
    return f["axis"]


def write_fleet_summary(loaded, all_findings, fleet_shared, dp_servers, fleet_shared_domains=frozenset(), domain_servers=None):
    lines = []
    lines.append("连接日志（成功）跨天分析总览 FLEET_SUMMARY")
    lines.append(f"覆盖日期: {', '.join(d for d, _p, _s, _w in loaded)}")
    lines.append("注意：origin 是内网地址，不同节点的相同 IP 不代表同一设备，统计以「节点-IP」为单位。")
    lines.append("这是成功连接日志；已与同日期失败日志分析结果交叉比对。")
    lines.append("")

    flagged = defaultdict(list)
    torrent = []
    for (date, server, oip), flist in sorted(all_findings.items()):
        threats = [f for f in flist if f["kind"] == "threat"]
        sev = "CLEAN"
        for f in threats:
            sev = sev_max(sev, f["final_sev"])
        if sev != "CLEAN":
            block = [f"  [{sev}] {date} {server} - {oip}"]
            for f in threats:
                if f["final_sev"] == "CLEAN":
                    continue
                block.append(f"      触发: {finding_trigger(f)}")
                if f.get("repeat_note"):
                    block.append(f"      定级: {f['repeat_note']}")
            flagged[sev].append("\n".join(block))
        for f in flist:
            if f["kind"] == "torrent":
                torrent.append(f"  [P2P/BT] {date} {server} - {oip}\n      触发: {finding_trigger(f)}")

    for sev in ["MALICIOUS", "SUSPICIOUS", "WATCH"]:
        lines.append(f"===== {sev} 清单 =====")
        lines.extend(flagged[sev] if flagged[sev] else ["  （无）"])
        lines.append("")

    lines.append("===== P2P/BitTorrent 清单（ToS 风险，非安全威胁） =====")
    lines.extend(torrent if torrent else ["  （无）"])
    lines.append("")

    lines.append(f"===== 机队共享应用流量（同一 目的地IP:端口 出现在 >={FLEET_SHARED_MIN_SERVERS} 个节点，判为共享应用已从威胁判定排除） =====")
    shared_sorted = sorted(((k, len(dp_servers[k])) for k in fleet_shared), key=lambda x: -x[1])[:40]
    if shared_sorted:
        for (host, port), n in shared_sorted:
            lines.append(f"  {host}:{port} — 出现在 {n} 个节点")
    else:
        lines.append("  （无）")
    lines.append("")

    lines.append(f"===== 机队共享域名白名单（同一域名出现在 >={FLEET_SHARED_DOMAIN_MIN_SERVERS} 个节点，判为机队通用基础设施，"
                 f"已从「域名分布过散」轴的统计里剔除） =====")
    domain_servers = domain_servers or {}
    shared_domain_sorted = sorted(
        ((h, len(domain_servers[h])) for h in fleet_shared_domains), key=lambda x: -x[1])[:40]
    if shared_domain_sorted:
        for host, n in shared_domain_sorted:
            lines.append(f"  {host} — 出现在 {n} 个节点")
        if len(fleet_shared_domains) > 40:
            lines.append(f"  ...（共 {len(fleet_shared_domains)} 个域名进入白名单，仅显示覆盖节点数最多的 40 个）")
    else:
        lines.append("  （无）")

    (BASE_DIR / "FLEET_SUMMARY_info.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
