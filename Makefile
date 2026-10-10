# egp 构建与测试
export GOTOOLCHAIN := local
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

.PHONY: build test e2e release demo clean

# 构建本机可执行文件
build:
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o bin/egp ./cmd/egp

# 静态检查与单元测试（含 netns 规则测试；非 root 时自动跳过）
test:
	gofmt -l cmd internal test | (! grep .)
	go vet ./...
	go vet -tags e2e ./test/e2e
	go test ./...

# 端到端测试：需要 root、iproute2、curl 和 gost（EGP_GOST_BIN 指定路径）
e2e:
	./test/e2e/run.sh

# 构建发布包（dist/）
release:
	./scripts/build-release.sh $(VERSION)

# 演示模式启动 WebUI（不启动 gost、不修改防火墙）
demo: build
	./bin/egp serve -dry-run -dir ./demo-data -listen 127.0.0.1:8088

clean:
	rm -rf bin dist demo-data
