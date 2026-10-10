#!/usr/bin/env bash
# 构建发布产物（dist/）：
#   egp-linux-amd64.tar.gz、egp-linux-arm64.tar.gz  内含 egp/{egp,gost,install.sh,README.md,VERSION}
#   install.sh                                      在线安装脚本（单独作为 Release 资产）
#   SHA256SUMS                                      以上全部文件的校验和
# 文件名不带版本号，便于用 releases/latest/download/<文件名> 下载最新版。
# gost 从源码构建并固定到经过验证的版本（需要能访问 proxy.golang.org）。
#
# 用法：./scripts/build-release.sh [版本号]
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION="${1:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
# gost 3.3.1（go-gost/gost 主分支 0793f47，依赖 go-gost/x v0.19.5），已通过端到端测试验证。
GOST_MODULE="github.com/go-gost/gost/cmd/gost@v0.0.0-20261007023108-0793f4730f8d"
GOST_GO="${GOST_GO:-go1.26.3}"
ARCHS="${ARCHS:-amd64 arm64}"

rm -rf dist && mkdir -p dist
work="$(mktemp -d)"
trap 'chmod -R u+w "$work" 2>/dev/null; rm -rf "$work"' EXIT

for arch in $ARCHS; do
  echo "· 构建 linux/$arch"
  pkg="$work/$arch/egp"
  mkdir -p "$pkg"
  GOTOOLCHAIN=local CGO_ENABLED=0 GOOS=linux GOARCH="$arch" \
    go build -trimpath -ldflags "-s -w -X main.version=$VERSION" -o "$pkg/egp" ./cmd/egp

  gobin="$work/gobin-$arch"
  mkdir -p "$gobin"
  if [[ "$arch" == "$(go env GOARCH)" ]]; then
    GOTOOLCHAIN="$GOST_GO" CGO_ENABLED=0 GOBIN="$gobin" go install -trimpath -ldflags "-s -w" "$GOST_MODULE"
    cp "$gobin/gost" "$pkg/gost"
  else
    # 交叉编译时 go install 不允许设置 GOBIN，产物位于 GOPATH/bin/linux_<arch>/。
    GOTOOLCHAIN="$GOST_GO" CGO_ENABLED=0 GOOS=linux GOARCH="$arch" GOPATH="$gobin" GOMODCACHE="$(go env GOMODCACHE)" \
      go install -trimpath -ldflags "-s -w" "$GOST_MODULE"
    cp "$gobin/bin/linux_$arch/gost" "$pkg/gost"
  fi

  cp scripts/install.sh README.md "$pkg/"
  echo "$VERSION" > "$pkg/VERSION"
  chmod 755 "$pkg/egp" "$pkg/gost" "$pkg/install.sh"
  tar -C "$work/$arch" --owner=0 --group=0 -czf "dist/egp-linux-$arch.tar.gz" egp
done

cp scripts/install.sh dist/install.sh
(cd dist && sha256sum egp-linux-*.tar.gz install.sh > SHA256SUMS)
echo "· 版本 $VERSION"
ls -lh dist
cat dist/SHA256SUMS
