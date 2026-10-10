# egp —— ECS 出口代理

在阿里云 ECS（或任意 Ubuntu 服务器）上，通过一个 WebUI 配置上游 **SOCKS5 代理 IP**，让本机**所有出站流量**以代理 IP 访问互联网，而不是 ECS 自身绑定的公网 IP / EIP。

- **整机透明代理**：无需修改任何程序。TCP 用 `REDIRECT`、UDP 用 `TPROXY` 导入 [gost](https://github.com/go-gost/gost)，再经 SOCKS5（含 UDP ASSOCIATE）转发。
- **不会把自己锁在门外**：SSH、WebUI 等入站连接的回包不受影响。阿里云元数据、内网 DNS、内网镜像源和 VPC 网段自动直连。
- **防泄露（kill switch）**：代理全部不可用时直接断网，绝不回落到 ECS 自身 IP。同时阻断 IPv6 出网，开机阶段在网络就绪前先下发阻断规则。
- **主备切换**：健康检查发现主代理故障时自动切到备用代理，恢复后可自动切回，正常情况下出口 IP 保持不变。
- **安全的应用流程**：每次应用后都会校验真实出口 IP，然后进入 60 秒待确认，超时未确认自动回滚。
- **一键安装 / 启动 / 停止**：作为 systemd 服务运行。

> 详细设计见 [docs/DESIGN.md](docs/DESIGN.md)。

## 快速开始

### 1. 安装

在 ECS 上执行一条命令即可（Ubuntu 20.04 / 22.04 / 24.04，amd64 / arm64，需要 root）：

```bash
curl -fsSL https://github.com/ipest-info/EgressProxyIp/releases/latest/download/install.sh | sudo bash
```

脚本会从 [GitHub Release](https://github.com/ipest-info/EgressProxyIp/releases) 下载最新的安装包，然后依次完成：

- 校验 SHA256；
- 自动安装依赖（`iptables`、`iproute2`、`curl`、`ca-certificates`）；
- 把 `egp` 和经过验证的 `gost` 3.3.1 安装到 `/usr/local/bin`；
- 注册并启动 `egp.service` 和 `egp-guard.service`；
- 生成初始管理员密码，打印在终端，同时保存到 `/etc/egp/initial-password`。

常用变体：

| 场景 | 命令 |
|---|---|
| 安装指定版本 | `curl -fsSL https://github.com/ipest-info/EgressProxyIp/releases/latest/download/install.sh \| sudo EGP_VERSION=v0.1.0 bash` |
| WebUI 对外监听 | `curl -fsSL …/install.sh \| sudo bash -s -- --listen 0.0.0.0:8088` |
| 升级 | 重新执行安装命令，`/etc/egp` 下的配置和密码保留 |
| 卸载 | `sudo egp uninstall`（加 `--purge` 同时删除配置） |
| 访问 GitHub 慢 | 把 Release 资产放到镜像或内网地址，再执行 `curl -fsSL <镜像>/install.sh \| sudo EGP_BASE_URL=<镜像目录> bash`，目录下需要有 `egp-linux-<架构>.tar.gz` 和 `SHA256SUMS` |

**离线安装**：从 Release 页面下载 `egp-linux-amd64.tar.gz`（或 arm64 版）和 `SHA256SUMS`，上传到服务器后执行：

```bash
sha256sum -c SHA256SUMS --ignore-missing
tar -xzf egp-linux-amd64.tar.gz && sudo ./egp/install.sh
```

### 2. 打开 WebUI

默认只监听 `127.0.0.1:8088`。先在自己的电脑上建立 SSH 隧道：

```bash
ssh -L 8088:127.0.0.1:8088 root@<ECS 公网 IP>
```

然后打开 <http://127.0.0.1:8088>，用初始密码登录。

如果想直接从公网访问，安装时加上 `--listen 0.0.0.0:8088`（见上表），此时会自动启用 HTTPS（自签证书）。请务必在阿里云安全组中**只放行你自己的 IP**。

### 3. 配置并启用

1. 在 **代理** 页添加或批量导入 SOCKS5 代理，支持以下格式：
   - `socks5://user:pass@host:port#名称`
   - `host:port:user:pass`
   - `user:pass@host:port`
   - `host:port`
2. 点击 **测试**，查看代理的出口 IP、地理位置、延迟，以及是否支持 UDP。
3. 在 **出口策略** 页选择主备或固定模式、kill switch、UDP 处理方式。
4. 回到 **仪表盘**，点击 **启用出口代理**，在倒计时内点击 **确认保留**。

此后可以在 ECS 上验证出口 IP，应显示代理 IP：

```bash
curl ifconfig.me
```

## 常用命令

| 命令 | 作用 |
|---|---|
| `sudo egp start` | 启动服务（并设为开机自启） |
| `sudo egp stop` | 停止服务，**并恢复直连**（即使开启了 kill switch） |
| `sudo egp restart` | 重启服务 |
| `egp status` | 查看服务状态 |
| `egp logs [-f]` | 查看日志 |
| `sudo egp cleanup` | 立即删除全部防火墙规则，恢复直连（应急用） |
| `sudo egp reset-password` | 重置管理员密码 |
| `sudo egp plan` | 预览将要下发的 iptables 规则和 gost 配置 |
| `sudo egp uninstall [--purge]` | 卸载（`--purge` 同时删除配置） |

> 注意：直接执行 `systemctl stop egp` 时，如果开启了 kill switch，会**保留阻断规则**（断网而不是泄露真实 IP）。要恢复上网，请执行 `sudo egp stop` 或 `sudo egp cleanup`。

## 哪些流量不走代理

| 类别 | 说明 |
|---|---|
| 入站连接的回包 | SSH、WebUI、对外提供的服务，回包不受影响 |
| 本机与私网 | `127.0.0.0/8`、`10.0.0.0/8`、`172.16.0.0/12`、`192.168.0.0/16`、直连子网、VPC 网段 |
| 阿里云内网服务 | `100.64.0.0/10`：元数据 `100.100.100.200`、内网 DNS `100.100.2.136/138`、内网镜像源 |
| 系统 DNS 服务器 | 防止 gost 解析域名时形成回环 |
| NTP（UDP 123） | 默认绕过，避免时钟漂移 |
| 自定义 | 网段、域名后缀（按 TLS SNI / HTTP Host 匹配）、端口、`egp-direct` 用户组 |

想让某个程序临时直连：`sg egp-direct -c "curl ifconfig.me"`。

## 已知限制

- **Docker 桥接网络中的容器**不经过本机 OUTPUT 链，**不会走代理**；使用 `--network host` 的容器不受此限制。详见设计文档“后续计划”。
- **DNS** 默认仍使用阿里云内网 DNS。这不会暴露 ECS IP，但 CDN 会按 ECS 所在地域返回解析结果。
- **IPv6** 只做阻断，不做代理。
- 代理商的 SOCKS5 如果在 UDP 握手中返回 `0.0.0.0` 或内网地址作为中继地址，gost 无法使用该代理转发 UDP。测试时会标注出来，该代理只用于 TCP。

## 开发与测试

```bash
make test        # gofmt、go vet、单元测试
make demo        # 演示模式启动 WebUI（不启动 gost、不修改防火墙），默认 http://127.0.0.1:8088
sudo make e2e    # 端到端测试：在独立网络命名空间中用真实 gost + iptables 验证
make release     # 在本地构建发布产物到 dist/（amd64 / arm64）
```

运行端到端测试需要 root、`iproute2`、`curl` 和 gost（用 `EGP_GOST_BIN` 指定路径）。测试在 `unshare -n` 创建的独立网络命名空间中进行，不会修改宿主机防火墙。

## 发布新版本

发布由 GitHub Actions（`.github/workflows/release.yml`）完成。依次执行单元测试、构建 amd64/arm64 安装包，然后创建 Release 并上传以下资产：

- `egp-linux-amd64.tar.gz`、`egp-linux-arm64.tar.gz`
- `install.sh`
- `SHA256SUMS`

触发方式任选其一：

- 推送版本标签：`git tag v0.2.0 && git push origin v0.2.0`；
- 在 GitHub 的 Actions 页面选择 **release** 工作流，点击 **Run workflow** 并填写标签（标签不存在时会自动创建）。

资产文件名不带版本号，因此 `releases/latest/download/install.sh` 始终指向最新版。
