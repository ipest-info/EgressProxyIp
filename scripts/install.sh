#!/usr/bin/env bash
# egp 一键安装脚本（Ubuntu 20.04 / 22.04 / 24.04，其他 systemd 发行版也可使用）
#
# 在线安装（从 GitHub Release 下载最新版）：
#   curl -fsSL https://github.com/ipest-info/EgressProxyIp/releases/latest/download/install.sh | sudo bash
#   curl -fsSL https://github.com/ipest-info/EgressProxyIp/releases/latest/download/install.sh | sudo bash -s -- --listen 0.0.0.0:8088
#
# 离线安装（已下载并解压 egp-linux-<架构>.tar.gz）：
#   sudo ./egp/install.sh
#
# 卸载：
#   sudo egp uninstall [--purge]   或   sudo ./install.sh --uninstall [--purge]
#
# 升级：重新执行安装命令即可，/etc/egp 下的配置会保留。
#
# 环境变量：
#   EGP_VERSION   安装指定版本，如 v0.1.0（默认最新版）
#   EGP_REPO      GitHub 仓库（默认 ipest-info/EgressProxyIp）
#   EGP_BASE_URL  自定义下载地址前缀（镜像或内网分发），其下需有 egp-linux-<架构>.tar.gz 与 SHA256SUMS
set -euo pipefail

EGP_REPO="${EGP_REPO:-ipest-info/EgressProxyIp}"
EGP_VERSION="${EGP_VERSION:-latest}"

info() { echo -e "\033[32m·\033[0m $*"; }
warn() { echo -e "\033[33m⚠\033[0m $*" >&2; }
die()  { echo -e "\033[31m✘\033[0m $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "请使用 root 运行（例如：curl -fsSL <地址> | sudo bash）"
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

# 安装运行依赖。
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

# 本地模式：脚本与 egp、gost 位于同一目录（解压后的安装包）。通过管道执行时没有脚本文件，直接走在线模式。
HERE=""
if [[ -n "${BASH_SOURCE[0]:-}" && -f "${BASH_SOURCE[0]}" ]]; then
  HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fi
if [[ -n "$HERE" && -x "$HERE/egp" && -x "$HERE/gost" ]]; then
  info "从本地安装包安装：$HERE（版本 $(cat "$HERE/VERSION" 2>/dev/null || echo 未知)）"
  exec "$HERE/egp" install --gost "$HERE/gost" "$@"
fi

# 在线模式：从 GitHub Release 下载。
if [[ -n "${EGP_BASE_URL:-}" ]]; then
  BASE="${EGP_BASE_URL%/}"
elif [[ "$EGP_VERSION" == "latest" ]]; then
  BASE="https://github.com/$EGP_REPO/releases/latest/download"
else
  BASE="https://github.com/$EGP_REPO/releases/download/$EGP_VERSION"
fi
PKG="egp-linux-$ARCH.tar.gz"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

download() { # download <文件名>
  info "下载 $BASE/$1"
  curl -fL --retry 3 --connect-timeout 15 --progress-bar -o "$TMP/$1" "$BASE/$1" \
    || die "下载失败：$BASE/$1（网络不通时可设置 EGP_BASE_URL 使用镜像，或下载安装包后离线安装）"
}

download SHA256SUMS
download "$PKG"
info "校验 SHA256"
(cd "$TMP" && grep " $PKG\$" SHA256SUMS | sha256sum -c --quiet -) || die "安装包校验失败：文件可能损坏或被篡改"

tar -xzf "$TMP/$PKG" -C "$TMP"
[[ -x "$TMP/egp/egp" && -x "$TMP/egp/gost" ]] || die "安装包内容不完整"
info "安装 egp $(cat "$TMP/egp/VERSION" 2>/dev/null || echo)"
"$TMP/egp/egp" install --gost "$TMP/egp/gost" "$@"
