# SentinelX Kuroko

**连接日志分类引擎 — 架构说明（交接文档）**

> English version: [README.md](README.md)

本仓库有两个独立但结构对称的 Python 脚本，用来对 IDC 机队的连接日志做安全分类。
本文件供后续维护者/AI 快速理解设计，无需通读代码。

## 0. 本仓库在 SentinelX 中的位置

**SentinelX 整体并非开源项目。** 为避免混淆，项目已拆分为两个独立仓库，
**仅 SentinelX Kuroko（即本仓库）开源**：

| 组件 | 职责 | 状态 |
|---|---|---|
| **SentinelX Misaka** | 数据采集与网络管控：原始数据获取、流量拦截、网站封锁、连接日志记录及其它相关安全功能 | **闭源** |
| **SentinelX Kuroko**（本仓库） | 对采集到的网络日志做分析的开源日志分析算法 | **开源**（CC BY-NC 4.0） |

Kuroko 消费 Misaka 产出的连接日志，但不依赖 Misaka 的代码：它只从磁盘读取纯文本快照（见 §3），
可以完全独立运行。

### 版本号

因本次拆分，此前的统一版本号不再适用。**Misaka 与 Kuroko 此后各自维护独立的版本历史，
均从 `v1.0.0` 重新开始。** 两者版本号互相独立，**不会**保持同步 —— 各自遵循各自的开发与发布周期。

## 1. 它解决什么问题

机队每台节点每天导出两份「连接日志」快照（最近 24 小时）：
- **成功连接**（info）：TCP 真的建成了。
- **失败连接**（warning）：连接尝试失败。

原始日志已按 `origin(内网源IP) → 目的地(host:port) → 次数` 聚合。引擎的任务：从中挑出
**规模化扫描 / 端口探测 / 僵尸网络行为 / P2P**，同时**尽量不误杀正常业务**（重点：客户自建
的 REALITY 代理节点会大量访问 visa.cn/qualcomm.cn 等大厂域名做 SNI 伪装，绝不能当威胁）。

## 2. 两个脚本

| 脚本 | 处理 | 特有点 |
|---|---|---|
| `classify_logs.py` | 失败连接（warning_*） | 高危端口集**不含** 22 |
| `classify_info_logs.py` | 成功连接（info_*） | 高危端口集**含** 22（成功=已得手更严重），且有 `xref` 轴与同日期 warning 结果交叉比对；成功语境阈值更紧 |

两者共用同一套解析、跨天关联、机队抑制、报告渲染逻辑（各自复制，保持文件独立）。
`classify_info_logs.py` 会 `import classify_logs` 来复用 warning 引擎做交叉比对。

## 3. 输入

每台节点每种日志每天产出一份 24 小时快照（这部分属于 SentinelX Misaka），已按
`origin(内网源IP) → 目的地(host:port) → 次数` 聚合。引擎自动发现所有可用日期并全部载入，**无需参数**。
任何能输出同样聚合文本格式的日志来源都可以，跑 Kuroko 并不需要 Misaka。

原始导出有一点对算法有影响：它会把占某 origin 流量 ≥75% 的单一目的地当「高频噪音」剔除。
`effective_dests()` 在检测前**把这条目的地重新放回来**（否则一片 telnet 洪水若被当噪音剔除
就会整条漏判），但不改变 total 计数语义。

## 4. 严重度模型

```
CLEAN  <  WATCH  <  SUSPICIOUS  <  MALICIOUS
```
- **WATCH**：命中过可疑规则，但跨天判定为「稳定复现＝常驻自动化/运维」。良性但保留可见性，
  不进威胁告警清单。
- 只有 **IPv4 目的地**参与所有威胁判定；**域名目的地天然免疫** → 这就是 REALITY 借用 SNI
  不被误杀的结构性原因。

## 5. 单日检测轴（先算每天的 base 严重度）

1. **横向高危端口扫描**：一个 origin 在某高危端口上连了 N 个互不相关公网 IP。
   - 阈值 `(可疑, 恶意)` = 距离目标 IP 数。默认 `(5,20)`；info 的端口 22 特调 `(8,25)`。
   - 高危端口集：telnet(23/2323)、RDP(3389)、SMB(445)、1433/3306/6379/135/139/21/5900/8291/
     37215/52869/7547/1900 等（info 另含 22）。
2. **纵向单目标端口扫描**：一个 origin 对**同一台** IP 敲了 N 个 ≤1024 端口（nmap 式）。
   - 阈值：warning `(10,20)`、info `(8,15)`。
   - 计数时剔除 `COMMON_SERVICE_PORTS`（80/443/53/22/853/993…），避免把访问某 CDN 的
     80+443+853 误判成扫描。
3. **P2P/BitTorrent**：≥3 个不同 IP 命中 BT 特征端口（6881-6889/6969/1337/51413…）。
   这是**分类标记**（ToS 关注），不是安全严重度。
4. **OpenAI/ChatGPT 鉴权滥用（注册机/token 农场）**：当日鉴权域名（auth.openai.com 等）
   次数 ≥`OPENAI_AUTH_MIN_HITS`(300)，且产品域名（chat.openai.com/api.openai.com 等）次数
   占「鉴权+产品」总量的比例 ≤`OPENAI_USAGE_MAX_RATIO`(5%) → SUSPICIOUS。这是**按比例**判定
   而非绝对次数：正常用户即使经代理/中转访问量很大，鉴权流量也远小于实际产品使用量；只反复
   走鉴权流程、几乎不用产品本身，才是账号农场特征。**唯一对域名目的地计数的检测轴**（其余轴
   仅对裸 IPv4 计数），且只针对这两组精确域名白名单，不影响 REALITY/SNI 域名豁免的整体设计。
   不参与跨天 streak 升降级（无跨天关联，逐天独立判定）。
5. **域名目的地分布过散**：当日不同域名目的地数 ≥`DOMAIN_SCATTER_MIN_DISTINCT`(300)，且没有任何
   单一域名占「全部域名次数」的比例超过 `DOMAIN_SCATTER_MAX_TOP_SHARE`(10%) → 直接判 **WATCH**
   （不是 SUSPICIOUS/MALICIOUS——这是新加的探索性判定，先归入观察级而非告警级）。用全量数据校准：
   不同域名数中位数 7，p90≈251，p95≈539，本轴取门槛在 p90 附近。命中通常是两类：共享代理/中转节点
   承载很多不同真实用户的流量（良性），或批量探测/自动化访问大量域名。同样只对域名目的地生效，
   不影响 REALITY/SNI 域名豁免；不参与跨天 streak。
6. **xref（仅 info）**：同日期 warning 引擎已把该 (节点,origin) 判为威胁 → 在成功日志里佐证。

## 6. 跨天关联（核心，`apply_cross_day`）

把 findings 按 `(节点, origin, 轴, 端口/目标)` 签名分组，**沿全局时间线逐天**处理，维护
`prior_pool`（此前所有天的目标并集）与「连续可疑」计数 `streak`：

- `novelty` = 当天目标里不在 `prior_pool` 的比例（新面孔占比）。
- **prior_pool 非空且 novelty ≤ NOVELTY_STABLE(0.5)** → 判 **WATCH**（稳定复现＝自动化），
  `streak` 清零。
- 否则 → 维持 **SUSPICIOUS**，`streak += 1`；一旦 **`streak ≥ ESCALATE_STREAK_DAYS(3)`**
  → 升级 **MALICIOUS**（持续换目标扫描）。
- 单日计数已达恶意线的天：保持 MALICIOUS。
- **缺数据 / CLEAN / WATCH 的那天都会打断 streak**（清零）。
- **回溯降级**：对「未曾升级、跨≥2 天、且某可疑日的目标是其它天目标子集(novelty≤0.5)」的签名，
  把该可疑日降为 WATCH —— 让**首次出现那天不因无历史可比而吃亏**。

**方向性**：降级只往下（SUSPICIOUS→WATCH），升级只靠连续 streak（SUSPICIOUS→MALICIOUS）。
跨天关联**永远不会**把单日计数判定的 MALICIOUS 改掉。

## 7. 防误杀设计（为什么这么判）

1. **域名不计数** → REALITY/SNI 借用免疫。
2. **机队共享抑制**：同一 `(目的地IP, 端口)` 出现在 `≥FLEET_SHARED_MIN_SERVERS(5)` 个节点
   → 判为批量部署的共享应用（Telegram/Steam/STUN/监控探针/大陆 ISP 探测池等），列入
   FLEET_SUMMARY 末尾并排除出威胁判定。**但高危端口不参与此抑制**（攻击目标撞车不算豁免）。
   域名版本同理：同一域名出现在 `≥FLEET_SHARED_DOMAIN_MIN_SERVERS(15)` 个节点 → 判为机队通用
   基础设施（CDN/广告/大厂域名等），从「域名分布过散」轴的统计里剔除（只用于这一个轴降噪，
   不影响其它任何判定）。用 87 台节点全量数据校准：域名覆盖节点数中位数只有 1，p95=4，
   15 已经是远高于噪声线的门槛，抽样看过这个门槛附近全是 CDN/广告 SDK/大厂域名。
3. **纵向轴剔除常见服务端口**，避免 CDN 多端口访问误判。
4. **novelty 稳定性判定**：目标复用＝自动化＝WATCH；只有持续「换新目标」才升级。
5. **首次出现回溯降级**：批处理时用其它天的数据把第一天的稳定签名补判为 WATCH。

## 8. 无状态 & 单日可用性

- 引擎**无状态**：不读数据库、不读上一次的 `result/`，每次都从当前磁盘上的 raw 重算。
- **单日也能跑**：唯一依赖历史的功能是「跨天降级/升级」。只有一天时，稳定自动化无法被证明
  → 会保守地显示成 SUSPICIOUS（**过报而非漏报**），升级路径（需≥3 连续天）不触发。属优雅降级。

## 9. 可调参数（都在文件顶部）

| 参数 | 含义 |
|---|---|
| `HIGH_RISK_PORTS` / `TELNET_PORTS` | 高危端口集 |
| `PORT_THRESHOLDS` / `DEFAULT_THRESHOLDS` | 横向轴 (可疑,恶意) 距离 IP 数阈值 |
| `N_LOW_PORTS_SUSPICIOUS/MALICIOUS` | 纵向轴低位端口数阈值 |
| `COMMON_SERVICE_PORTS` | 纵向轴剔除的常见服务端口 |
| `TORRENT_PORTS` / `TORRENT_MIN_DISTINCT` | P2P 判定 |
| `FLEET_SHARED_MIN_SERVERS` | 共享应用节点数门槛 |
| `NOVELTY_STABLE` | ≤此值算「稳定复现」→ 降级 WATCH（默认 0.5） |
| `ESCALATE_STREAK_DAYS` | 连续可疑几天升级 MALICIOUS（默认 3） |
| `OPENAI_AUTH_DOMAINS` / `OPENAI_USAGE_DOMAINS` | OpenAI 鉴权域名 / 产品域名白名单 |
| `OPENAI_AUTH_MIN_HITS` / `OPENAI_USAGE_MAX_RATIO` | 鉴权滥用判定的次数门槛 / 产品占比上限 |
| `DOMAIN_SCATTER_MIN_DISTINCT` / `DOMAIN_SCATTER_MAX_TOP_SHARE` | 域名分布过散判定的不同域名数门槛 / 最大单域名占比上限 |

## 10. 运行

```
python classify_logs.py        # 先跑，供 info 交叉比对
python classify_info_logs.py
```
两者各自输出每日每节点的报告，以及一份机队级跨天总览。每条命中项都带两行说明：
**触发**（命中什么规则、规模、阈值）与**定级**（为何是该级别 / 跨天判定结论）——
判定理由始终可以只凭输出复原。

## 11. 已知边界 / 设计取舍

- origin 是内网 IP；不同节点的相同 origin IP **不代表同一设备**，统计以「节点-IP」为唯一单位。
- 阈值按 24h 快照校准（早期曾按整月合并数据，reason 文案已改为按当日措辞）。
- IP 归属（ipinfo.io）分析是**人工离线**做的，**未写进脚本**（保持脚本纯离线可复跑）。
- 升级需≥3 个**连续自然日**都有数据且都判可疑；**断断续续的可疑（中间有 clean/缺数据）不会升级**，
  这是刻意为之（"连续"语义）。
- 「持续性本身也可能是威胁」这一点：当前仅对「持续+换目标」升级；对「持续+固定目标」判 WATCH。

## 12. 许可协议

**SentinelX Kuroko** 采用
[知识共享 署名-非商业性使用 4.0 国际许可协议（CC BY-NC 4.0）](LICENSE) 发布。

你可以自由地**使用、修改、再分发**本代码，但须满足：

- **署名（Attribution）** —— 必须注明 **Uzumaru** 与 **SentinelX Kuroko** 项目，附上许可协议链接，
  并说明是否作过修改。
- **非商业性使用（NonCommercial）** —— **不得**用于商业目的，包括出售本代码、出售基于本代码的
  服务，或将其打包进付费产品。

本许可协议**仅覆盖本仓库**。**SentinelX Misaka 与 SentinelX 完整系统仍为闭源**，
不适用 CC BY-NC 4.0。

版权所有 © 2026 Uzumaru。
