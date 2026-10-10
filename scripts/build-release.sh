#!/usr/bin/env bash
# 构建发布包：dist/egp-<版本>-linux-<架构>.tar.gz，内含 egp、gost、install.sh、README.md。
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
for arch in $ARCHS; do
  echo "· 构建 linux/$arch"
  pkg="dist/egp-$VERSION-linux-$arch/egp"
  mkdir -p "$pkg"
  GOTOOLCHAIN=local CGO_ENABLED=0 GOOS=linux GOARCH="$arch" \
    go build -trimpath -ldflags "-s -w -X main.version=$VERSION" -o "$pkg/egp" ./cmd/egp

  gobin="$(mktemp -d)"
  if [[ "$arch" == "$(go env GOARCH)" ]]; then
    GOTOOLCHAIN="$GOST_GO" CGO_ENABLED=0 GOBIN="$gobin" go install -trimpath -ldflags "-s -w" "$GOST_MODULE"
    cp "$gobin/gost" "$pkg/gost"
  else
    # 交叉编译时 go install 不允许设置 GOBIN，产物位于 GOPATH/bin/linux_<arch>/。
    GOTOOLCHAIN="$GOST_GO" CGO_ENABLED=0 GOOS=linux GOARCH="$arch" GOPATH="$gobin" go install -trimpath -ldflags "-s -w" "$GOST_MODULE"
    cp "$gobin/bin/linux_$arch/gost" "$pkg/gost"
  fi
  chmod -R u+w "$gobin" && rm -rf "$gobin"

  cp scripts/install.sh README.md "$pkg/"
  chmod +x "$pkg/install.sh"
  tar -C "dist/egp-$VERSION-linux-$arch" -czf "dist/egp-$VERSION-linux-$arch.tar.gz" egp
  rm -rf "dist/egp-$VERSION-linux-$arch"
done
(cd dist && sha256sum ./*.tar.gz > SHA256SUMS)
ls -lh dist
