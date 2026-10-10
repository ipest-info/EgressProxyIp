#!/usr/bin/env bash
# egp 一键安装脚本（Ubuntu 20.04 / 22.04 / 24.04，其他 systemd 发行版也可使用）
#
# 用法（在发布包解压后的目录中执行）：
#   sudo ./install.sh                         # 安装并启动，WebUI 只监听 127.0.0.1:8088
#   sudo ./install.sh --listen 0.0.0.0:8088   # WebUI 对外监听（自动启用 HTTPS 自签证书）
#   sudo ./install.sh --uninstall [--purge]   # 卸载（--purge 同时删除配置）
#
# 环境变量：
#   GOST_VERSION  要下载的 gost 版本（默认 3.3.1，仅在发布包中没有 gost 时下载）
#   GOST_URL      自定义 gost 下载地址（例如国内镜像）
#   EGP_URL       自定义 egp 发布包下载地址（目录中没有 egp 时使用）
set -euo pipefail

GOST_VERSION="${GOST_VERSION:-3.3.1}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

info() { echo -e "\033[32m·\033[0m $*"; }
warn() { echo -e "\033[33m⚠\033[0m $*" >&2; }
die()  { echo -e "\033[31m✘\033[0m $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "请使用 root 运行：sudo $0 $*"
command -v systemctl >/dev/null || die "未找到 systemctl：egp 需要 systemd"

if [[ "${1:-}" == "--uninstall" ]]; then
  shift
  [[ -x /usr/local/bin/egp ]] || die "egp 未安装"
  exec /usr/local/bin/egp uninstall "$@"
fi

case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) die "不支持的 CPU 架构：$(uname -m)" ;;
esac

# 安装依赖。
missing=()
command -v iptables >/dev/null || missing+=(iptables)
command -v ip >/dev/null || missing+=(iproute2)
command -v curl >/dev/null || missing+=(curl)
[[ -f /etc/ssl/certs/ca-certificates.crt ]] || missing+=(ca-certificates)
if ((${#missing[@]})); then
  command -v apt-get >/dev/null || die "缺少依赖：${missing[*]}，请手动安装"
  info "安装依赖：${missing[*]}"
  DEBIAN_FRONTEND=noninteractive apt-get update -qq
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${missing[@]}"
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

download() { # download <url> <dest>
  info "下载 $1"
  curl -fL --retry 3 --connect-timeout 15 -o "$2" "$1" || die "下载失败：$1（可通过环境变量指定镜像地址）"
}

# egp 可执行文件。
EGP="$HERE/egp"
if [[ ! -x "$EGP" ]]; then
  [[ -n "${EGP_URL:-}" ]] || die "当前目录没有 egp 可执行文件，请使用发布包安装，或设置 EGP_URL"
  download "$EGP_URL" "$TMP/egp.tar.gz"
  tar -xzf "$TMP/egp.tar.gz" -C "$TMP"
  EGP="$(find "$TMP" -type f -name egp -perm -u+x | head -1)"
  [[ -n "$EGP" ]] || die "发布包中没有 egp"
fi

# gost 可执行文件：优先使用发布包自带的，其次已安装的，最后从 GitHub 下载。
GOST="$HERE/gost"
if [[ ! -x "$GOST" ]]; then
  if [[ -x /usr/local/bin/gost ]] && /usr/local/bin/gost -V 2>/dev/null | grep -Eq 'gost v?3\.([3-9]|[1-9][0-9])'; then
    GOST=/usr/local/bin/gost
  else
    url="${GOST_URL:-https://github.com/go-gost/gost/releases/download/v${GOST_VERSION}/gost_${GOST_VERSION}_linux_${ARCH}.tar.gz}"
    download "$url" "$TMP/gost.tar.gz"
    tar -xzf "$TMP/gost.tar.gz" -C "$TMP"
    GOST="$(find "$TMP" -type f -name gost | head -1)"
    [[ -n "$GOST" ]] || die "gost 压缩包中没有可执行文件"
    chmod +x "$GOST"
  fi
fi

"$EGP" install --gost "$GOST" "$@"
