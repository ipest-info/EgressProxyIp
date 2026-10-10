#!/usr/bin/env bash
# 在独立的网络命名空间中运行端到端测试（需要 root、iproute2、curl、gost）。
# 用法：EGP_GOST_BIN=/path/to/gost ./test/e2e/run.sh
set -euo pipefail
cd "$(dirname "$0")/../.."

: "${EGP_GOST_BIN:=$PWD/.bin/gost}"
if [[ ! -x "$EGP_GOST_BIN" ]]; then
  echo "找不到 gost：请设置 EGP_GOST_BIN" >&2
  exit 1
fi
out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT

echo "· 编译 egp、fakenet 和测试程序"
go build -o "$out/egp" ./cmd/egp
go build -o "$out/fakenet" ./test/e2e/fakenet
go test -tags e2e -c -o "$out/e2e.test" ./test/e2e

echo "· 在新的网络命名空间中运行"
EGP_BIN="$out/egp" FAKENET_BIN="$out/fakenet" EGP_GOST_BIN="$EGP_GOST_BIN" \
  unshare -n "$out/e2e.test" -test.v -test.timeout 10m "$@"
