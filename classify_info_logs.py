# -*- coding: utf-8 -*-
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
# 目的地行：host:port: count，>=2 次命中时可能带一段可选的时间戳后缀
# [t 首次~末次 avg=平均间隔(秒/分钟/小时) secs=命中的不同秒数]（2026-07-29 起新增字段）。
# 后缀整体可选，兼容没有该字段的旧格式/单次命中行。
DEST_RE = re.compile(
    r"^\s+(\S+?):(\d+):\s*(\d+)"
    r"(?:\s*\[t\s+(\d{2}:\d{2}:\d{2})~(\d{2}:\d{2}:\d{2})\s+avg=([\d.]+)(秒|分钟|小时)\s+secs=(\d+)\])?"
    r"\s*$"
)
EXCLUDED_RE = re.compile(
    r"^\s+\[excluded:\s*(\S+?):(\d+),\s*(\d+)\s*hits,\s*([\d.]+)%.*\]\s*$"
)
IPV4_RE = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")
_AVG_UNIT_SEC = {"秒": 1.0, "分钟": 60.0, "小时": 3600.0}


def _hhmmss_to_sec(s):
    h, m, sec = (int(x) for x in s.split(":"))
    return h * 3600 + m * 60 + sec

# 横向高危端口：成功连接语境下，port 22 也纳入（SSH 成功多主机连接确实出现过），
# 但 22 的正常多主机运维用途远多于其它端口，所以给它单独更高的阈值。
HIGH_RISK_PORTS = {
    22, 23, 2323, 3389, 445, 1433, 3306, 5900, 8291, 37215,
    52869, 7547, 1900, 6379, 135, 139, 21,
    # 2026-08-25 补充：与 classify_logs.py 同批新增（见该文件同处注释）。这些端口在
    # 07-31~08-24 实测数据里被真实扫描者大量使用，共同点是「未授权即可 RCE / 直接
    # 暴露管理面」。成功语境下命中更严重：意味着对方端口真的开着、连接真的建成了。
    2375, 2376,   # Docker daemon
    4444,         # Metasploit 默认监听
    5601,         # Kibana
    7001,         # WebLogic
    9200,         # Elasticsearch
    # 【不要加回 27017（MongoDB）】它同时落在 Steam 游戏服务器端口段 27015-27030 里，
    # 实测造成误杀（SGSH2 10.10.17.30 打的是整个 27015-27098 段、目标全在 Valve 网段，
    # 是玩 Steam）。详见 classify_logs.py 同处注释。
    11211,        # memcached
    2181,         # ZooKeeper
    5984,         # CouchDB
    623,          # IPMI/BMC
    6667, 6697,   # IRC —— 僵尸网络 C2 常用
    5432,         # PostgreSQL
}
TELNET_PORTS = {23, 2323}
# (suspicious_min, malicious_min) on distinct successful raw-IP destinations.
PORT_THRESHOLDS = {
    22: (8, 25),   # 24h 快照下，8 台起提示、25 台起判恶意；配合跨天复现豁免
    # IRC / PostgreSQL 有一定的正常多主机用途，给更高阈值避免误杀。
    6667: (8, 25),
    6697: (8, 25),
    5432: (8, 25),
    # 7001：本机队有很大的正当共用人群（同一批华为云 IP 被多个不相关客户访问），
    # 实测精确率 0/20、良性规模上限 15 台。按端口 22 的同一思路抬高到良性天花板之上。
    # 详见 classify_logs.py 同处注释。
    7001: (20, 40),
}
DEFAULT_THRESHOLDS = (5, 20)

# 参与机队共享抑制的高危端口：与 classify_logs.py 一致（见该文件同名常量的完整理由）。
# 摘要：telnet/RDP/SMB/Docker 这类端口正常业务根本不会连，撞车不算豁免；但下面这些
# 端口有正当的多客户共用用途（应用面板/托管数据库/IRC/代理后端），实测端口 7001 因此
# 在 20 个互不相关客户上误报，目标是同一批华为云 IP、单个目的地被 6 个节点共用。
SHAREABLE_HIGH_RISK_PORTS = {7001, 5432, 6667, 6697, 5601, 9200, 2181, 5984}

# 纵向单目标端口扫描（成功）。成功比失败更严重，阈值收得更紧。
N_LOW_PORTS_SUSPICIOUS = 8
N_LOW_PORTS_MALICIOUS = 15
COMMON_SERVICE_PORTS = {
    20, 21, 22, 25, 53, 80, 110, 123, 143, 443, 465, 587,
    853, 989, 990, 993, 995, 3478, 5222, 5223, 5228, 8080, 8443,
}

TORRENT_PORTS = {6881, 6882, 6883, 6884, 6885, 6886, 6887, 6888, 6889, 6969, 1337, 51413, 6771}
TORRENT_MIN_DISTINCT = 3

# 多端口横向扫描（2026-08-25 新增，端口无关）：与 classify_logs.py 一致，见该文件同处
# 的完整动机说明。成功语境下阈值收紧一档（扫描已得手比扫描失败更严重）。
MULTIPORT_PORT_MIN_IPS = 3    # 一个端口要在 >= 这么多个不同 IP 上出现，才算进「扫描端口」集合
MULTIPORT_MIN_PORTS = 3       # 单台目标 IP 被 >= 这么多个「扫描端口」打中，才算被多端口探测
MULTIPORT_SUSPICIOUS = 6      # 有 >= 这么多台 IP 被多端口探测 → 可疑
MULTIPORT_MALICIOUS = 15      # → 恶意
# 三条必须的降噪，完整理由见 classify_logs.py 同处注释（含「试过而无效」的判别量清单，
# 别再重走：核心端口占比、pairwise Jaccard、目标 IP 的 /24 聚集度，三个都无法分开
# 真扫描与代理池）。有效的是端口语义锚点：扫描器打可利用服务，代理池打任意映射端口。
MULTIPORT_MAX_HITS = 5        # 单个 (IP,端口) 命中超过此值 → 持续关系而非探测，不计入
MULTIPORT_MAX_RUN = 5         # 单台 IP 的端口集里最长连号达到此值 → 端口映射网关，整台排除
MULTIPORT_MIN_HIGHRISK = 2    # 复用端口集里至少要有这么多个 HIGH_RISK_PORTS（语义锚点）


def _longest_port_run(ports):
    """端口集里最长的连号长度。连号是端口映射网关的指纹（8531,8532,8533…），
    而扫描器的服务端口清单最长只到 2（2375/2376、5003/5004 这种成对出现）。"""
    ps = sorted(ports)
    if not ps:
        return 0
    best = cur = 1
    for a, b in zip(ps, ps[1:]):
        cur = cur + 1 if b == a + 1 else 1
        best = max(best, cur)
    return best

FLEET_SHARED_MIN_SERVERS = 5

# OpenAI/ChatGPT 鉴权滥用（账号注册机/token 农场）检测：与 classify_logs.py 一致
# （见该文件同名常量注释）。正常用户即使经代理/中转访问量很大，鉴权域名次数相对
# 真实产品域名次数占比也很小；按比例判定，避免误判重度正常用户。
OPENAI_AUTH_DOMAINS = {"auth.openai.com", "auth0.openai.com", "external.auth.openai.com"}
OPENAI_USAGE_DOMAINS = {
    "chat.openai.com", "chatgpt.com", "api.openai.com", "platform.openai.com",
    "ios.chat.openai.com", "android.chat.openai.com", "sora.chatgpt.com", "ws.chatgpt.com",
}
# 2026-08-25 下调 300 → 150：与 classify_logs.py 一致。07-31~08-24 全量实测，单日鉴权
# 域名命中数的最大值只有 251，门槛 300 已高于整个总体上限，等于这条轴被静默关闭
# （25 天 0 命中）。真正起判别作用的是产品占比（≤5%），次数门槛只用来滤小样本。
OPENAI_AUTH_MIN_HITS = 150
OPENAI_USAGE_MAX_RATIO = 0.05
# 跨天真实使用核实：与 classify_logs.py 一致（见该文件同名常量注释）——若同一
# (server, origin IP) 在其它已加载日期有 >= 此值的产品域名命中，说明是真实用户，
# 当天低产品占比更可能是当日只刷新 token、没怎么用产品，而非注册机。
OPENAI_CROSSDAY_USAGE_MIN = 50

# 域名目的地分布过散：与 classify_logs.py 一致（见该文件同名常量注释），用同一批
# 全量数据校准（不同域名数中位数 7，p90≈251，p95≈539）。
DOMAIN_SCATTER_MIN_DISTINCT = 300
DOMAIN_SCATTER_MAX_TOP_SHARE = 0.10

# 单域名连接风暴（2026-08-25 重写，取代原「域名并发异常」轴）：与 classify_logs.py 一致，
# 完整的推翻理由见该文件同处注释。摘要：旧的 count/distinct_secs 并发比值量的是「客户端
# 每次事件同时开几条连接」（浏览器每主机 6+1 条 → 比值恒为 7），对时间跨度完全不敏感，
# 在 07-31~08-24 数据上导致 info 侧 2166 条告警里绝大多数是 google/apple/netflix/微软遥测
# 这类误杀（其余所有轴加起来才 321 条）。新规则改看持续速率 count/(末次-首次)。
DOMAIN_STORM_MIN_HITS = 150      # 当日对单一域名的连接次数下限
DOMAIN_STORM_MIN_RATE = 2.0      # 次/秒，count/(末次-首次) 的持续速率下限
DOMAIN_STORM_MIN_SPAN_SEC = 20   # 时间跨度下限，排除「打开一个网页瞬间并发加载」

# 挖矿池域名（2026-08-25 新增）：与 classify_logs.py 一致（见该文件同名常量注释）。
# 摘要：必须区分「真在挖矿」（stratum 端口 / 持续会话量级）和「只是打开了矿池官网」
# （443 端口、个位数次）。实跑发现本轴初版的 23 条命中全部是后者，判 SUSPICIOUS 过重。
MINING_STRATUM_PORTS = {3333, 4444, 5555, 7777, 8888, 9999, 14444, 45700, 3032, 1234}
MINING_SESSION_MIN_HITS = 50
MINING_DOMAIN_HINTS = (
    "stratum", "nanopool", "minexmr", "supportxmr", "hashvault", "moneroocean",
    "2miners", "ethermine", "f2pool", "poolin", "viabtc", "herominers",
    "zergpool", "xmrpool", "nicehash", "unmineable", "miningpoolhub",
)

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

SEV_ORDER = {"CLEAN": 0, "INFO": 1, "WATCH": 2, "SUSPICIOUS": 3, "MALICIOUS": 4}


def sev_max(a, b):
    return a if SEV_ORDER[a] >= SEV_ORDER[b] else b


def is_ipv4(host):
    m = IPV4_RE.match(host)
    if not m:
        return False
    return all(0 <= int(g) <= 255 for g in m.groups())


def _timing_desc(dests, domains):
    """从候选目的地（命中最多、且带时间戳字段的那个）拼一句时间分布描述，仅用于丰富
    reason 文案给人工复核参考，不参与任何判定阈值——新旧数据都验证过，鉴权请求本身
    经常是短时间小突发，突发本身不是可疑信号。没有时间戳数据（旧格式/单次命中）返回 None。"""
    candidates = [d for d in dests if d.host in domains and d.first_s is not None]
    if not candidates:
        return None
    d = max(candidates, key=lambda x: x.count)
    span = d.last_s - d.first_s
    fh, fm, fs = d.first_s // 3600, (d.first_s % 3600) // 60, d.first_s % 60
    lh, lm, ls = d.last_s // 3600, (d.last_s % 3600) // 60, d.last_s % 60
    if d.avg_sec < 60:
        avg_str = f"{d.avg_sec:.1f} 秒"
    elif d.avg_sec < 3600:
        avg_str = f"{d.avg_sec / 60:.1f} 分钟"
    else:
        avg_str = f"{d.avg_sec / 3600:.1f} 小时"
    return (f"时间分布：{d.host} 当日请求集中在 {fh:02d}:{fm:02d}:{fs:02d}~{lh:02d}:{lm:02d}:{ls:02d}"
            f"（跨度约 {span / 3600:.1f} 小时），平均间隔 {avg_str}（仅供参考，不参与判定）。")


class Dest:
    __slots__ = ("host", "port", "count", "first_s", "last_s", "avg_sec", "distinct_secs")

    def __init__(self, host, port, count, first_s=None, last_s=None, avg_sec=None, distinct_secs=None):
        self.host = host
        self.port = port
        self.count = count
        self.first_s = first_s          # 当天首次命中，秒数（0-86399），无时间戳字段则为 None
        self.last_s = last_s            # 当天末次命中，秒数
        self.avg_sec = avg_sec          # 平均命中间隔，统一换算成秒
        self.distinct_secs = distinct_secs  # 有命中的不同秒数（判断是否多次命中压在同一秒）


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
                host, port, count, first_t, last_t, avg_v, avg_u, secs = m_dest.groups()
                first_s = _hhmmss_to_sec(first_t) if first_t else None
                last_s = _hhmmss_to_sec(last_t) if last_t else None
                avg_sec = float(avg_v) * _AVG_UNIT_SEC[avg_u] if avg_v else None
                distinct_secs = int(secs) if secs else None
                current.dests.append(
                    Dest(host, int(port), int(count), first_s, last_s, avg_sec, distinct_secs))
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


def analyze_origin(origin, warning_status, fleet_shared_domains=frozenset(), fleet_shared=frozenset()):
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
        if port in SHAREABLE_HIGH_RISK_PORTS:
            # 这些端口有正当的多客户共用用途，剔除机队共用的目的地后再看规模
            plist = [d for d in plist if (d.host, port) not in fleet_shared]
        if not plist:
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

    # --- 轴 8：多端口横向扫描（端口无关）---
    # 判据见 classify_logs.py 同处注释：只看「同一份端口清单被套用到多台不相关主机」
    # 这个形状，不依赖高危端口白名单是否收录，补的正是白名单覆盖不到的盲区。
    # 同时剔除机队共享的 (IP, 端口)——批量部署的共享应用不是扫描目标。高危端口本来
    # 就不计入 fleet_shared，所以攻击目标撞车不会被豁免。
    port_ips = defaultdict(set)
    for d in dests:
        if (is_ipv4(d.host) and d.port not in COMMON_SERVICE_PORTS
                and d.port not in TORRENT_PORTS and (d.host, d.port) not in fleet_shared
                and d.count <= MULTIPORT_MAX_HITS):
            port_ips[d.port].add(d.host)
    scan_ports = {p for p, ips in port_ips.items() if len(ips) >= MULTIPORT_PORT_MIN_IPS}
    multi_hosts = {}
    # 语义锚点：端口集里没有足够的已知高危服务端口 → 不是在探服务，是代理/端口映射，整条不成立。
    if len(scan_ports & HIGH_RISK_PORTS) >= MULTIPORT_MIN_HIGHRISK:
        for ip, dlist in by_ip.items():
            hit_ports = {d.port for d in dlist
                         if d.port in scan_ports and (ip, d.port) not in fleet_shared
                         and d.count <= MULTIPORT_MAX_HITS}
            if len(hit_ports) < MULTIPORT_MIN_PORTS:
                continue
            if _longest_port_run(hit_ports) >= MULTIPORT_MAX_RUN:
                continue      # 连号端口块 = 端口映射网关，不是扫描目标
            if not (hit_ports & HIGH_RISK_PORTS):
                continue      # 这台目标身上没有任何高危服务端口 → 不是在探它的服务
            multi_hosts[ip] = hit_ports
    if len(multi_hosts) >= MULTIPORT_SUSPICIOUS:
        n_hosts = len(multi_hosts)
        ports_sample = sorted(scan_ports)[:12]
        ports_str = ", ".join(str(p) for p in ports_sample)
        if len(scan_ports) > len(ports_sample):
            ports_str += f" …（共 {len(scan_ports)} 个）"
        hr = sorted(scan_ports & HIGH_RISK_PORTS)
        hr_str = ", ".join(str(p) for p in hr[:8])
        sev = "MALICIOUS" if n_hosts >= MULTIPORT_MALICIOUS else "SUSPICIOUS"
        tail = (
            "规模已达恶意判定线。" if sev == "MALICIOUS"
            else f"未达 {MULTIPORT_MALICIOUS} 台的恶意线，但形状已明确是扫描，建议人工复核。"
        )
        findings.append({
            "axis": "multiport", "port": None, "target": None,
            "key_set": frozenset(multi_hosts),
            "sev": sev, "kind": "threat",
            "detail": (f"  多端口横向扫描（成功）: {n_hosts} 台公网 IP 各被 >={MULTIPORT_MIN_PORTS} 个"
                       f"复用端口成功连上（复用端口: {ports_str}）"),
            "reason": (
                f"该 origin 当日对 {n_hosts} 台互不相关的公网 IP 各自**成功建成**了至少 "
                f"{MULTIPORT_MIN_PORTS} 个端口的连接，且这些端口在多台目标之间重复复用"
                f"（{ports_str}），其中包含已知高危服务端口 {hr_str}。这是「拿一份固定端口清单横扫"
                f"一批主机、逐个试可利用服务」的扫描器指纹，而且是已经得手的那部分——对方端口真的"
                f"开着、连接真的建成了。判定已排除三类良性形状：单个目的地命中超过 {MULTIPORT_MAX_HITS} 次的"
                f"（持续关系而非探测）、端口集是连号块的（每端口映射一个后端出口的代理网关）、"
                f"以及端口集里凑不出 {MULTIPORT_MIN_HIGHRISK} 个高危服务端口的（机场/代理订阅用的是任意"
                f"映射端口，不是可利用服务）。P2P 也不会触发，因为 BT 对端端口随机、不在对端之间复用。{tail}"
            ),
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
            reason = (
                f"该 origin 当日成功连接 OpenAI/ChatGPT 鉴权域名（auth.openai.com 等）{auth_hits} 次，"
                f"同期成功连接实际聊天/API 域名（chat.openai.com/api.openai.com 等）仅 {usage_hits} 次"
                f"（产品占比 {ratio:.1%}）。正常用户即使经代理/中转访问量很大，鉴权流量也应远小于实际"
                f"产品使用量——只反复走鉴权流程、几乎不用产品本身，是账号注册机/token 农场的典型特征。"
                f"本判定基于当日总连接数比例（日志无请求路径），建议人工核实。"
            )
            timing = _timing_desc(dests, OPENAI_AUTH_DOMAINS)
            if timing:
                reason += f" {timing}"
            findings.append({
                "axis": "openai_auth", "port": None, "target": None,
                "key_set": frozenset(["openai_auth"]),
                "sev": "SUSPICIOUS", "kind": "threat",
                "detail": (f"  OpenAI/ChatGPT 鉴权域名成功连接 {auth_hits} 次 vs 产品域名(chat/api) {usage_hits} 次"
                           f"（产品占比 {ratio:.1%}）"),
                "reason": reason,
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
                "sev": "INFO", "kind": "threat",
                "detail": (f"  域名目的地分布很散(已剔除机队共享域名): {n_domains} 个不同域名，"
                           f"最大单域名占比 {top_share:.1%}（{top_host}），域名合计 {total_domain_hits} 次"),
                "reason": (
                    f"剔除机队共享域名（在 >={FLEET_SHARED_DOMAIN_MIN_SERVERS} 台节点上都出现过的通用"
                    f"CDN/广告/大厂域名）后，该 origin 当日仍访问了 {n_domains} 个自己独有的不同域名，"
                    f"没有任何单一域名占比超过 {DOMAIN_SCATTER_MAX_TOP_SHARE:.0%}"
                    f"（最大的是 {top_host}，占 {top_share:.1%}）。本引擎其它轴都不对域名计数（避免"
                    f"误杀 REALITY/SNI 借用流量），但这种「域名很多、没有主导目标、还都不是机队通用"
                    f"基础设施」的分布本身也值得关注——可能是共享代理/中转在承载很多不同真实用户的"
                    f"流量（良性），也可能是批量探测/自动化访问大量域名。暂归为 INFO（信息级，"
                    f"比 WATCH 更低，单独成栏），不计入威胁告警，建议留意是否持续。"
                ),
            })

    # --- 轴 6：单域名连接风暴（取代原「域名并发异常」，见常量处的推翻理由）---
    for d in dests:
        if is_ipv4(d.host) or d.first_s is None or d.count < DOMAIN_STORM_MIN_HITS:
            continue
        span = d.last_s - d.first_s
        if span < DOMAIN_STORM_MIN_SPAN_SEC:
            continue
        rate = d.count / span
        if rate >= DOMAIN_STORM_MIN_RATE:
            findings.append({
                "axis": "domain_storm", "port": None, "target": d.host,
                "key_set": frozenset([d.host]),
                "sev": "SUSPICIOUS", "kind": "threat",
                "detail": (f"  单域名连接风暴: {d.host} 当日成功连接 {d.count} 次压缩在 {span} 秒内"
                           f"（持续 {rate:.1f} 次/秒）"),
                "reason": (
                    f"该 origin 当日成功连接域名 {d.host} {d.count} 次，全部压缩在 {span} 秒的窗口内，"
                    f"持续速率 {rate:.1f} 次/秒。判据是**速率**而不是并发度：正常浏览器每主机会同时开"
                    f"6-7 条连接、双栈客户端每次事件开 2 条，这些「并发」本身完全良性，所以本轴不看"
                    f"并发比值（旧规则正是栽在这里，把网页广告加载、安卓 token 刷新、微软遥测全判成了"
                    f"可疑）。真正异常的是把成百上千次连接持续砸向同一个域名——遥测/保活/REALITY 心跳"
                    f"摊到全天不足 1 次/秒，正常网页加载总量又达不到 {DOMAIN_STORM_MIN_HITS} 次，能同时"
                    f"越过这三道门槛的只有刷接口、暴力破解或自动化批量请求。这是域名目的地在本引擎里"
                    f"参与判定的两个例外之一（另一个是挖矿池域名），不影响 REALITY/SNI 域名豁免。"
                ),
            })

    # --- 轴 9：挖矿池域名（域名清单式判定，与 openai_auth 同类）---
    mining_hits = {}
    mining_session = False
    for d in dests:
        if is_ipv4(d.host):
            continue
        low = d.host.lower()
        for hint in MINING_DOMAIN_HINTS:
            if hint in low:
                mining_hits[d.host] = mining_hits.get(d.host, 0) + d.count
                if d.port in MINING_STRATUM_PORTS or d.count >= MINING_SESSION_MIN_HITS:
                    mining_session = True
                break
    if mining_hits:
        listed = ", ".join(f"{h}({c}次)" for h, c in
                           sorted(mining_hits.items(), key=lambda kv: -kv[1])[:6])
        if mining_session:
            findings.append({
                "axis": "mining", "port": None, "target": None,
                "key_set": frozenset(mining_hits),
                "sev": "SUSPICIOUS", "kind": "threat",
                "detail": f"  挖矿会话: 成功连接 {len(mining_hits)} 个矿池域名（{listed}）",
                "reason": (
                    f"该 origin 当日**成功连接**了已知加密货币矿池域名：{listed}，且命中落在 stratum"
                    f"挖矿端口上或量级已达持续会话（≥{MINING_SESSION_MIN_HITS} 次）——矿池会话真的建立了，"
                    f"这是**这台机器本身在挖矿**的形状，而不是有人打开了矿池网页。可能是主机被植入挖矿"
                    f"木马，也可能是客户自行挖矿（多数 IDC 服务条款禁止）。域名目的地对本引擎其它威胁轴"
                    f"仍然免疫，不影响 REALITY/SNI 豁免。"
                ),
            })
        else:
            findings.append({
                "axis": "mining_web", "port": None, "target": None,
                "key_set": frozenset(mining_hits),
                "sev": "INFO", "kind": "threat",
                "detail": f"  矿池网站访问: {len(mining_hits)} 个矿池域名（{listed}）",
                "reason": (
                    f"该 origin 当日访问了矿池相关域名：{listed}，但**只在 80/443 上、量级很小**，"
                    f"没有落在 stratum 挖矿端口、也达不到持续会话的量级（≥{MINING_SESSION_MIN_HITS} 次）。"
                    f"这是「有人用浏览器看了矿池网站/自己的矿池面板」的形状，不是这台机器在挖矿。"
                    f"故归为 INFO（信息级），不计入威胁告警。"
                ),
            })

    # --- 轴 7：与同日期失败日志交叉比对 ---
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
                        # 高危端口原则上不进共享索引；SHAREABLE_HIGH_RISK_PORTS 例外。
                        if (d.port not in HIGH_RISK_PORTS
                                or d.port in SHAREABLE_HIGH_RISK_PORTS):
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


def apply_cross_day(all_findings, all_dates, usage_by_day=None):
    """跨天关联，逐天沿时间线判定（与 warning 引擎一致）。
      - 当天目标多为老面孔（新目标占比 <= NOVELTY_STABLE）→ WATCH，连续计数清零；
      - 多为新面孔 → 维持 SUSPICIOUS，连续计数 +1；
      - 连续计数 >= ESCALATE_STREAK_DAYS → 升级 MALICIOUS；
      - 缺数据/CLEAN/WATCH 打断连续计数；
      - 未升级、跨多天、始终是老池子子集的签名回溯降级 WATCH（首次出现不吃亏）。
    xref（与失败日志交叉比对）与 torrent 不参与跨天判定。

    openai_auth 轴单独处理：核实同一 (server, origin IP) 在其它任意已加载日期是否有过
    >=OPENAI_CROSSDAY_USAGE_MIN 次真实产品域名访问——命中说明是真实用户，只是当天没怎么
    用产品，降级为 WATCH；否则维持原判（与 classify_logs.py 逻辑一致）。"""
    ordered = sorted(all_dates)
    usage_by_day = usage_by_day or {}

    groups = defaultdict(dict)  # gkey -> {date: finding}
    for (date, server, oip), flist in all_findings.items():
        for f in flist:
            if f["kind"] == "threat" and f["axis"] == "openai_auth":
                other = usage_by_day.get((server, oip), {})
                best_day, best_usage = None, 0
                for d2, uh in other.items():
                    if d2 != date and uh > best_usage:
                        best_day, best_usage = d2, uh
                if best_usage >= OPENAI_CROSSDAY_USAGE_MIN:
                    f["final_sev"] = "WATCH"
                    f["repeat_note"] = (
                        f"该 origin 在 {best_day} 有 {best_usage} 次真实产品域名(chat/api)访问记录——"
                        f"是真实在用产品的用户，本次低产品占比更可能是当日鉴权刷新未伴随实际使用，"
                        f"而非注册机，降级为观察。"
                    )
                else:
                    f["final_sev"] = f["sev"]
                    f["repeat_note"] = None
                continue
            if f["kind"] != "threat" or f["axis"] not in ("horiz", "vert", "multiport"):
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

    buckets = {"MALICIOUS": [], "SUSPICIOUS": [], "WATCH": [], "INFO": [], "CLEAN": []}
    for o in origins:
        buckets[per_origin[o.ip][0]].append(o)
    torrent_origins = [o for o in origins if per_origin[o.ip][2]]

    out = []
    out.append(f"连接日志（成功）分类报告 — {server}")
    out.append(
        f"Origin 总数: {len(origins)} | 恶意/已得手: {len(buckets['MALICIOUS'])} | "
        f"可疑: {len(buckets['SUSPICIOUS'])} | 关注(跨天复现): {len(buckets['WATCH'])} | "
        f"信息: {len(buckets['INFO'])} | "
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
                         ("WATCH", "WATCH 详情（跨天稳定复现，疑似常驻自动化/运维，仅关注）"),
                         ("INFO", "INFO 详情（信息级，探索性判定，非威胁，仅供参考）")]:
        rows = sorted(buckets[level], key=lambda x: -x.total)
        if rows:
            out.append(f"===== {title} =====")
            for o in rows:
                _sev, threats, _t = per_origin[o.ip]
                out.append(format_origin_block(o, level, threats))
                out.append("")

    torrent_only = [o for o in torrent_origins if per_origin[o.ip][0] in ("CLEAN", "INFO")]
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
    per_server = {}
    for path in sorted(wdir.glob("*.txt")):
        try:
            per_server[path.stem] = wlog.parse_file(path)
        except Exception:
            continue
    # 机队上下文：此前这里直接 analyze_origin(o) 不带任何机队参数，等于关掉了机队共享
    # 抑制，使 xref 比真正的 warning 跑更敏感。这里用**当天** warning 全量现算一份索引补上。
    # 仍是近似——真正的 warning 跑是跨全部已加载日期建索引，这里只有一天，但比完全没有
    # 上下文准得多。xref 只在 warning 侧判 MALICIOUS/SUSPICIOUS 时才起作用，宁可稍紧。
    try:
        fshared, _dp, fdomains, _ds = wlog.build_fleet_index([(date, per_server)])
    except Exception:
        fshared, fdomains = frozenset(), frozenset()
    for server, origins in per_server.items():
        for o in origins:
            findings = wlog.analyze_origin(o, fdomains, fshared)
            sev = "CLEAN"
            for f in findings:
                if f["kind"] == "threat":
                    sev = wlog.sev_max(sev, f["sev"])
            if sev != "CLEAN":
                status[(server.upper(), o.ip)] = sev
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
                all_findings[(date, server, o.ip)] = analyze_origin(
                    o, wstatus, fleet_shared_domains, fleet_shared)

    # 每个 (server, origin IP) 在每一天的产品域名命中数，供 openai_auth 轴跨天核实使用
    usage_by_day = defaultdict(dict)
    for date, _dpath, per_server, _w in loaded:
        for server, origins in per_server.items():
            for o in origins:
                uh = sum(d.count for d in effective_dests(o) if d.host in OPENAI_USAGE_DOMAINS)
                usage_by_day[(server, o.ip)][date] = uh

    apply_cross_day(all_findings, [d for d, _dp, _ps, _w in loaded], usage_by_day)

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
    n_info = sum(1 for _d, _s, _i, sev, _t in fleet_rows if sev == "INFO")
    n_bt = sum(1 for _d, _s, _i, _sev, t in fleet_rows if t)
    print(f"[info] 处理 {len(loaded)} 天。MALICIOUS={n_mal} SUSPICIOUS={n_susp} "
          f"WATCH={n_watch} INFO={n_info} P2P/BT={n_bt}。跨天汇总: FLEET_SUMMARY_info.txt")


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
    if f["axis"] == "multiport":
        return (f"多端口横向扫描（成功）— {f['detail'].strip()}"
                f"（阈值 被多端口探测的 IP 数 可疑≥{MULTIPORT_SUSPICIOUS}/恶意≥{MULTIPORT_MALICIOUS}）")
    if f["axis"] == "domain_storm":
        return (f"单域名连接风暴 — {f['detail'].strip()}"
                f"（阈值 当日≥{DOMAIN_STORM_MIN_HITS} 次、跨度≥{DOMAIN_STORM_MIN_SPAN_SEC} 秒"
                f"且持续≥{DOMAIN_STORM_MIN_RATE} 次/秒）")
    if f["axis"] == "mining":
        return (f"挖矿会话 — {f['detail'].strip()}"
                f"（命中 stratum 端口或 ≥{MINING_SESSION_MIN_HITS} 次持续会话）")
    if f["axis"] == "mining_web":
        return f"矿池网站访问（信息级，非挖矿）— {f['detail'].strip()}"
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

    for sev in ["MALICIOUS", "SUSPICIOUS", "WATCH", "INFO"]:
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
