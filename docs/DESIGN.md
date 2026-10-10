# egp 设计文档：用代理 IP 作为 ECS 的互联网出口

## 1. 背景与目标

阿里云 ECS（VPC 网络）的公网访问由绑定的 EIP 或自动分配的公网 IP 经 NAT 完成，实例本身只能看到 `eth0` 上的私网地址。业务上有时需要让这台 ECS 以**指定的代理 IP**访问互联网，例如：

- 访问对来源 IP 有白名单或地域要求的服务；
- 隐藏服务器的真实公网 IP。

**目标**

1. 通过 WebUI 管理上游 SOCKS5 代理（账号密码，TCP + UDP），本机**所有出站流量**都以代理 IP 出网，不需要修改任何程序。
2. **不能把自己锁在门外**：SSH、WebUI 等入站连接不受影响；阿里云元数据、内网 DNS、内网镜像源、VPC 网段照常直连。
3. **不泄露**：代理故障、引擎崩溃、开机阶段、IPv6 等情况下，都不能悄悄回落到 ECS 自身 IP（kill switch）。
4. 单台 ECS 本机部署，作为 Ubuntu systemd 服务一键安装、启动、停止。

**非目标（本期）**：多机集中管理、Docker 桥接网络容器的流量、DNS 走代理、IPv6 代理。见第 10 节。

## 2. 总体架构

```
             浏览器（SSH 隧道 / HTTPS）
                    │
┌───────────────────▼────────────────────────────────────────────┐
│ egp serve（Go 单二进制，root，systemd: egp.service）              │
│                                                                 │
│  web        WebUI + JSON API，会话鉴权、CSRF 防护、登录限速        │
│  controller 唯一的状态变更入口（串行）：应用 / 确认 / 回滚 /       │
│             健康切换 / 引擎重启 / 规则漂移修复                    │
│  ├─ gost    生成配置、监管 gost 子进程、通过 gost API 切换节点     │
│  ├─ fw      生成并下发 iptables 规则（EGP_* 链）与策略路由        │
│  ├─ probe   SOCKS5 测试（CONNECT / UDP ASSOCIATE / STUN）、       │
│  │          出口 IP 校验、阿里云元数据                           │
│  ├─ health  健康状态机（带迟滞）与主备排序                        │
│  └─ store   /etc/egp/state.json 等（0600，原子写）               │
└───────────────────┬────────────────────────────────────────────┘
                    │ 子进程
            ┌───────▼────────┐  SOCKS5 (TCP CONNECT / UDP ASSOCIATE)
本机进程 ──►│ gost  red/redu │────────────────────────────────► 代理 IP ──► 互联网
  (iptables)└────────────────┘
```

- **数据面**：iptables 把本机发出的流量导入 gost。gost 按 hop 中的节点顺序（fifo）选择上游 SOCKS5 代理转发。
- **控制面**：egp 后端。配置变更、健康切换、引擎重启全部由 controller 在一把锁下串行处理，保证 gost 配置和防火墙规则始终一致。

### 为什么选 gost

gost v3 原生提供了 egp 需要的全部能力：

- 透明代理：`red`（TCP，REDIRECT）和 `redu`（UDP，TPROXY）；
- 上游 SOCKS5，标准 UDP ASSOCIATE 需加 `relay=udp`；
- 防回环：`so_mark`；
- 主备选择：`fifo` 选择策略 + 失败标记；
- **运行时 REST API**：可替换 hop，切换代理不需要重启进程，现有服务不中断；
- Prometheus 指标。

egp 只需生成配置并在运行时调用 API。

## 3. 数据面

### 3.1 流量路径

**TCP**

```
应用 connect() ─► nat OUTPUT ─► EGP_TCP_OUT ─► REDIRECT :7892 ─► gost red ─► SOCKS5 CONNECT
```

- nat 表只处理新连接的首包。入站连接（SSH/WebUI）的回包属于已建立连接，**天然不会被重定向**。
- REDIRECT 只匹配 `--syn`。即使 conntrack 表被清空，已有连接的中途报文也不会被误重定向而断开。
- gost 通过 `SO_ORIGINAL_DST` 取得原始目标地址。

**UDP**

```
应用 sendto() ─► mangle OUTPUT ─► EGP_UDP_OUT ─► MARK 0x4000000
            └─► 策略路由 fwmark 0x4000000 → table 7893: local 0.0.0.0/0 dev lo
            └─► 经 lo 重新进入 ─► mangle PREROUTING ─► EGP_UDP_PRE ─► TPROXY :7893 ─► gost redu ─► SOCKS5 UDP ASSOCIATE
```

- 先 RETURN 掉 `--ctdir REPLY`：本机 UDP 服务（DNS、WireGuard 等）的回包不能被导入代理。
- 本机 UDP 服务端口（临时端口范围以下的已绑定端口）按源端口放行。这样即使 conntrack 条目过期，迟到的回包也不会被代理。

### 3.2 防火墙标记

所有标记都是单个比特位，并且始终带掩码使用，刻意避开 kube-proxy（0x4000/0x8000）、Tailscale（0xff0000）、wg-quick（0xca6c）、Cilium（0xf00）。

| 标记 | 默认值 | 设置者 | 含义 |
|---|---|---|---|
| MarkProxy | `0x2000000` | gost 节点 `so_mark` | gost 连接上游代理的套接字 |
| MarkDirect | `0x1000000` | gost 服务 `so_mark` | gost 的直连拨号（域名绕过） |
| MarkSelf | `0x8000000` | egp 自身（`SO_MARK`） | 代理测试、健康检查、元数据、直连 IP 检测 |
| MarkTProxy | `0x4000000` | iptables mangle | 被导向 TPROXY 的 UDP |

所有拦截链的前三条规则都是“带 Proxy/Direct/Self 标记 → RETURN”，从根本上避免回环。策略路由使用表 7893，优先级 9000（在 main 表 32766 之前）。

### 3.3 绕过（直连）判定

按顺序检查：

1. 引擎/自身标记；
2. `addrtype LOCAL`（本机地址，包括 Docker 发布的端口）；
3. 网段：
   - 内置：`0/8 10/8 100.64/10 127/8 169.254/16 172.16/12 192.168/16 224/4 240/4`；
   - 自动探测：直连子网（`/proc/net/route`）、VPC 网段（元数据 `vpc-cidr-block`）、系统 DNS 服务器；
   - 用户配置的网段；
   - 以上网段合并去重，被其他网段包含的会去掉；
4. 用户组：`--gid-owner egp-direct`。**禁止绕过 uid/gid 0**：大多数守护进程以 root 运行，绕过 root 会让代理形同虚设；
5. 目标端口：TCP/UDP 分别配置，默认 UDP 123（NTP）。`multiport` 每条规则最多 15 个端口，自动拆分；
6. 域名后缀：只在 gost 内生效。gost 嗅探 TLS SNI / HTTP Host，命中 hop 级 bypass 后直连（打 MarkDirect 标记）。只有存在域名规则时才开启嗅探：嗅探会让 SSH、SMTP 这类服务端先发言的协议多等待一个超时（300ms）。

### 3.4 kill switch：多层防护

单靠 REDIRECT/TPROXY **不是** kill switch。ICMP、其他 IP 协议、绑定网卡的套接字、在应用规则之前已建立的直连连接都会绕过它们。开启 kill switch 后有四层防护：

1. **filter OUTPUT → `EGP_GUARD` 防护链**，按顺序判断：
   - 放行：回环、TPROXY 标记、REPLY 方向、自身标记；
   - 代理标记 → `EGP_GUARD_PX`：只允许去往已配置的代理 IP:端口（以域名配置的代理只能按端口放行）和 UDP 中继；
   - 放行：管理端口（默认 22 与 WebUI 端口）的回包、绕过项；
   - **其余一律 REJECT**（TCP 回 RST，其他协议回 icmp-admin-prohibited）。
2. **gost 黑洞节点**。从源码确认：当 hop 中所有节点都被标记为失败时，gost 的 hop 选不出节点，路由会**退化为直连**（`chain/route.go`：没有节点的路由直接走 `DefaultRoute.Dial`）。egp 在 hop 末尾追加一个连不上的黑洞节点 `127.0.0.1:1`，它的单节点 `maxFails` 设为 2³⁰，永远不会被过滤掉。这样“全部失败”就变成连接直接失败。此外，没有域名规则时，防护链还会拒绝所有带直连标记的流量，构成第二道保险。
3. **引擎崩溃时**：规则保留。TCP 被重定向到没有监听的端口，直接收到 RST；UDP TPROXY 找不到套接字就被丢弃，失败即断网。
4. **开机阶段**：`egp-guard.service` 在 `network-pre.target` 之前运行，按上一次确认的配置先下发规则（不含 UDP 透明代理，UDP 由防护链直接拒绝）。之后 `egp.service` 启动并补全规则。

另外，**IPv6 一律阻断**（`EGP6_GUARD`），除非在策略中关闭。egp 只代理 IPv4，阻断 IPv6 可以防止应用优先走 IPv6 暴露真实地址。主机没有全局 IPv6 地址时，IPv6 规则下发失败只告警，不中断。

关闭 kill switch 时：代理全部不可用后，egp 会临时撤掉拦截规则（“降级直连”），代理恢复后自动重新下发。

### 3.5 实现中发现并解决的坑

以下问题都已在端到端测试中复现，并用测试覆盖：

| 问题 | 现象 | 解决方式 |
|---|---|---|
| gost 读取 metadata 中的整数时只识别 `int` 和 `string`，JSON 中的数字是 `float64`，会被静默忽略 | `so_mark` 失效，gost 连接代理的流量被重定向回 gost，无限回环，直到文件描述符耗尽 | 所有整数 metadata 写成字符串（`gost.mdInt`） |
| gost 的 SOCKS5 客户端默认使用私有的 UDP-over-TCP 扩展 | 普通 SOCKS5 代理收不到 UDP | 节点设置 `relay=udp`，使用标准 UDP ASSOCIATE |
| gost 的 hop 全部失败时退化为直连 | kill switch 失效，真实 IP 泄露 | 黑洞节点 + 防护链 |
| iptables 子链中的 `RETURN` 只回到调用链 | 被 `EGP_GUARD_PX` 放行的流量继续落到后面的 REJECT | 跳转之后紧跟同条件的 RETURN，并加入不变式测试 |
| 同一个 OUTPUT 钩子内 mangle 改标记重新选路后，filter 表的 `-o` 仍是原出接口 | 被 TPROXY 的 UDP 无法用 `-o lo` 识别，被防护链拒绝 | 防护链按 TPROXY 标记放行（REDIRECT 后的 TCP 目标为 127.0.0.1，由回环网段放行） |
| SOCKS5 代理在 UDP 握手中返回 `0.0.0.0` 或内网地址作为中继地址，gost 会原样使用 | 该代理的 UDP 全部失败 | 测试时用与 gost 相同的严格模式检测；不可用时该节点设置 `network: tcp`，UDP 不会选中它 |

### 3.6 规则的幂等下发

- **后端选择**：自动选择 iptables-nft 或 iptables-legacy，参考 Kubernetes iptables-wrapper 的做法，哪套里已有的规则多就用哪套。save、restore 和主命令始终使用同一个变体。
- **链**：先判断是否已存在，生成 `-N`（新建）或 `-F`（清空），再用 `iptables-restore -w --noflush` 按表一次性写入。nft 后端对整个提交是原子的。
- **跳转**：带 `-m comment --comment egp`，保证在父链中只有一条且位于第 1 位，排在 ufw、firewalld 的 ACCEPT 之前。按排序后的参数比较规则，因为 `iptables -S` 会调整参数顺序。
- **清理**：删除跳转 → 清空链 → 删除链 → 删除策略路由。可以重复执行；`egp cleanup` 会在两套 iptables 上都清理。
- **漂移修复**：每 30 秒检查跳转是否仍在首位、链的规则数是否一致。被 firewalld 重载、Docker 重启或手工删除后会自动补回，并写审计日志。

## 4. 控制面

### 4.1 事务式应用

```
校验配置 ─► 计算节点顺序 ─► 写 gost 配置（/run/egp/gost.json，0600）
        ─► 检查版本与端口占用 ─► （重新）启动 gost ─► 等待 API 和端口就绪（10 秒）
        ─► 下发 iptables 规则 ─► 出口校验 ─► 进入“待确认”（默认 60 秒）
                                    │失败                   │超时 / 手动回滚 / 进程重启
                                    └──────► 回滚到上一次确认的配置 ◄──┘
```

- **出口校验**：请求不打标记、不复用连接，与普通进程走同一路径。查询多个 IP 回显服务，结果必须与 ECS 自身 IP（元数据 `eipv4` / `public-ipv4`，或打标记直连测得的 IP）不同。
- **待确认**：WebUI 弹出倒计时，用户点击“确认保留”后才写入 `applied.json`。浏览器断开、未确认或 egp 在待确认期间重启（磁盘上留有 `pending.json`），都会回到上一次确认的配置。
- **停用**：立即生效，不需要确认，因为恢复直连不存在锁死风险。

### 4.2 健康检查与主备切换

- 每个启用的代理按间隔（默认 30 秒）做一次端到端检查：带自身标记直连代理，SOCKS5 CONNECT 后发起 HTTP 请求，默认 `http://cp.cloudflare.com/generate_204`。
- 状态机带迟滞：连续失败 N 次（默认 3）判定故障，连续成功 M 次（默认 2）判定恢复，避免抖动导致出口 IP 来回切换。
- **主备模式**：hop 中的节点为健康代理按优先级排列（fifo 总是使用第一个）。关闭“自动回切”时，当前出口只要仍健康就保持在首位，高优先级代理恢复也不切换。**固定模式**：只使用指定代理。
- 节点顺序变化时，通过 `PUT /config/hops/egp-egress` 在运行时替换 hop，不需要重启 gost。gost 自身的被动失败标记（`maxFails: 3`、`failTimeout: 30s`）能在两次健康检查之间更快地跳过已经连不上的节点。
- 不使用 gost 内置的节点探测：它只检查代理端口能否连通，无法发现认证失败或代理无法出网。

### 4.3 引擎监管

- gost 是 egp 的子进程。启动它的 goroutine 锁定在一个专用系统线程上，并设置 `Pdeathsig=SIGKILL`：Pdeathsig 绑定的是线程而不是整个进程，所以 egp 异常退出时 gost 会随之被杀掉。systemd 侧使用 `KillMode=control-group` 兜底。
- gost 意外退出时：kill switch 关闭则先撤掉规则，避免断网；然后按指数退避（2 秒起，最长 64 秒）重启，重启后重新下发规则。
- gost 的 API 和指标只监听 127.0.0.1，API 使用每次启动随机生成的密码。

## 5. 持久化

| 文件 | 内容 | 权限 |
|---|---|---|
| `/etc/egp/state.json` | 编辑中的状态：代理（含密码）、策略、绕过、设置 | 0600 |
| `/etc/egp/applied.json` | 最近一次确认生效的状态（回滚和开机守护的依据） | 0600 |
| `/etc/egp/pending.json` | 待确认标记 | 0600 |
| `/etc/egp/audit.log` | 审计日志（JSONL） | 0600 |
| `/etc/egp/initial-password` | 初始密码（登录后可删除） | 0600 |
| `/etc/egp/tls.crt`、`tls.key` | 自签证书（WebUI 监听非回环地址时生成） | 0644 / 0600 |
| `/run/egp/gost.json` | 渲染后的 gost 配置 | 0600 |

所有写入都是原子的：写临时文件 → fsync → rename → 对目录 fsync。

## 6. WebUI 与 API

页面包括：仪表盘、代理、出口策略、绕过规则、日志、设置（含配置预览）。前端使用原生 JS，无构建步骤，通过 `go:embed` 打包进二进制。CSP 只允许同源资源。

| 方法与路径 | 作用 |
|---|---|
| `POST /api/login`、`POST /api/logout`、`GET /api/session` | 登录、退出、会话 |
| `GET /api/status` | 运行状态：生效配置、当前出口、引擎、防火墙、健康、ECS 信息、流量、conntrack |
| `POST /api/egress-check` | 立即测量真实出口 IP 与直连出口 IP |
| `GET /api/state` | 编辑中的状态（代理密码只写不读） |
| `POST /api/proxies`、`POST /api/proxies/import`、`POST /api/proxies/reorder` | 添加、批量导入、调整优先级 |
| `PUT /api/proxies/{id}`、`DELETE /api/proxies/{id}`、`POST /api/proxies/{id}/test` | 修改、删除、测试 |
| `PUT /api/policy`、`PUT /api/bypass`、`PUT /api/settings`、`PUT /api/enabled` | 修改策略、绕过、设置、启用开关（应用后生效） |
| `POST /api/apply`、`POST /api/apply/confirm`、`POST /api/apply/revert` | 应用、确认、回滚 |
| `GET /api/preview` | 预览 gost 配置（已脱敏）、iptables 规则、生效的绕过网段 |
| `GET /api/logs` | 审计日志与 gost 日志 |
| `POST /api/password` | 修改管理员密码（会使所有会话失效） |

**代理测试**内容：

- 分阶段延迟：TCP 连接、SOCKS5 握手、HTTP 请求；
- 出口 IP 和地理位置（ip-api.com，带自身标记查询，只暴露被查询的 IP）；
- UDP 能力：先按 gost 的严格模式做 UDP ASSOCIATE 和 STUN；中继地址不可用时，再试“替换为服务器 IP 后是否可用”，结果仅供参考。

## 7. 安全设计

- **监听地址**：默认 `127.0.0.1:8088`，推荐通过 SSH 隧道访问。监听非回环地址时自动生成自签 ECDSA 证书并启用 HTTPS，Cookie 带 `Secure`。
- **管理员密码**：bcrypt（cost 12），用并发信号量限制同时计算的数量，防止有人用登录请求耗尽 CPU。同一来源 5 分钟内失败 5 次即锁定。初始密码写入 0600 文件，不写进 journal。
- **会话**：Cookie 为 `HttpOnly`、`SameSite=Strict`，有效期 12 小时；修改密码后所有会话失效。
- **CSRF**：写请求必须是 `application/json`，并且 `Sec-Fetch-Site` 为 `same-origin`/`none`，或 `Origin` 与 `Host` 一致。Go 1.24 没有 `http.CrossOriginProtection`，所以自己实现。
- **密码不外泄**：API 不返回代理密码；预览中的 gost 配置已脱敏；gost 日志中的 API 密码会被替换掉。
- **响应头**：`X-Frame-Options: DENY`、`nosniff`、`no-referrer`、严格 CSP；前端插入的所有动态内容都经过转义。

## 8. 部署与运维

一键安装：`sudo ./install.sh`，即 `egp install`。安装过程会：

- 安装依赖（apt）；
- 复制 egp 和 gost（校验 gost 版本 ≥ 3.3.0）；
- 创建 `/etc/egp`（0700）和 `egp-direct` 用户组；
- 写入 `/etc/modules-load.d/egp.conf` 并加载内核模块；
- 注册并启用 `egp.service` 与 `egp-guard.service`，启动服务；
- 生成初始密码，并打印访问方式。

`egp.service` 的关键配置：

- `After=network-online.target`；
- `ExecStopPost=egp cleanup -respect-killswitch`：异常退出后清理规则，但开启 kill switch 时保留；
- `Restart=on-failure`；
- `LimitNOFILE=1048576`：每个被代理的流至少占用 2 个文件描述符；
- `RuntimeDirectory=egp`。

停止语义：

| 操作 | 结果 |
|---|---|
| `egp stop` | 用户明确要停止，**总是恢复直连** |
| `systemctl stop egp`、systemd 重启、关机 | 开启 kill switch 时保留阻断规则，避免出现泄露窗口 |
| `egp cleanup` | 应急恢复直连 |

## 9. 测试

| 层次 | 内容 |
|---|---|
| 单元测试 | 规则集 golden 测试（kill switch × UDP 模式 × IPv6 × 各类绕过）；安全不变式：放行规则先于动作、引用的链已声明、子链跳转后紧跟 RETURN、TCP 只重定向 SYN；gost 配置 golden 测试与不变式（黑洞节点、`relay=udp`、标记、脱敏）；代理行解析（含模糊测试）；SOCKS5 客户端对接假服务器（认证失败、连接被拒、UDP 不支持、中继地址为 0.0.0.0）；STUN；状态校验；健康状态机；Web 鉴权、CSRF、限速、密码不外泄、待确认超时回滚 |
| netns 规则测试 | 在 `unshare -n` 中用真实 iptables（nft 与 legacy 两套）验证：重复应用结果不变、第三方规则（Docker/ufw）不受影响、规则减少时多余的链被删除、漂移能被发现、清理后完全恢复原状 |
| 端到端测试 | 在独立命名空间中搭建“ECS + 互联网”，使用真实 gost 3.3.1，依次验证：① TCP/UDP 出口均为代理 IP，入站连接正常；② 故障切换与自动回切；③ kill switch 下全部代理故障时零泄露；④ 超时未确认自动回滚；⑤ 关闭 kill switch 时降级直连并自动恢复；⑥ gost 被杀后自动重启；⑦ 规则被删除后自动修复；⑧ 停用后恢复直连且无残留规则 |
| WebUI | 演示模式（`-dry-run`）下用 Playwright 走完登录、导入、配置、应用、确认流程，并检查手机宽度下的布局 |

## 10. 限制与后续计划

1. **Docker 桥接网络中的容器**：流量走 PREROUTING → FORWARD，不经过本机 OUTPUT，目前不会被代理。后续计划：
   - 在 PREROUTING 中对 `docker0`/`br-*` 做 TPROXY；
   - 开启 kill switch 时，在 `DOCKER-USER` 中拒绝未绕过的目标。
2. **DNS 走代理**：通过 hijack-dns，把查询经代理以 TCP DNS 发出，`aliyuncs.com` 仍走内网 DNS。这样 CDN 会按出口地域返回结果。
3. **原生 nftables 后端**：使用独立的 `table inet egp`，用集合承载大量网段，清理时只需删除整张表。
4. **IPv6 代理**：当上游代理支持时，增加 ip6tables nat/TPROXY 路径。
5. **多机集中管理**：控制台 + Agent，复用现有的 controller，Agent 通过 API 上报状态、接收配置。

## 附录：默认端口

| 用途 | 地址 |
|---|---|
| WebUI | `127.0.0.1:8088` |
| gost TCP 重定向（red） | `127.0.0.1:7892` |
| gost UDP 透明代理（redu） | `127.0.0.1:7893` |
| gost API | `127.0.0.1:17890` |
| gost 指标 | `127.0.0.1:17891` |

以上端口均可在“设置”中修改。启动 gost 前会检查端口是否被其他程序占用（9090 与 Cockpit、Prometheus 冲突，所以没有用它）。
