.PHONY: all build build-all cross-compile bundle-macos dist install uninstall build-darwin build-linux build-windows run up down stop restart status test scan agent report clean

BINARY_NAME=cyberspring
BUILD_DIR=bin
DIST_DIR=dist
LDFLAGS=-s -w

all: build

build:
	@echo "🌿 Compiling CyberSpring (Native Darwin ARM64)..."
	go build -ldflags="$(LDFLAGS)" -o $(BINARY_NAME) cmd/cyberspring/main.go
	@echo "✅ Build complete. Binary size: $$(ls -lh $(BINARY_NAME) | awk '{print $$5}')"

cross-compile: build-all bundle-macos

build-all: build-darwin build-linux build-windows
	@echo "🎉 Cross-platform build complete! Binaries located in $(BUILD_DIR)/"
	@ls -lh $(BUILD_DIR)

bundle-macos:
	@chmod +x scripts/build-macos-app.sh
	@./scripts/build-macos-app.sh

dist:
	@chmod +x scripts/package-dist.sh
	@./scripts/package-dist.sh

install:
	@chmod +x install.sh
	@./install.sh

uninstall:
	@chmod +x uninstall.sh
	@./uninstall.sh

build-darwin:
	@mkdir -p $(BUILD_DIR)
	@echo "🍎 Compiling for macOS (Darwin ARM64 + AMD64)..."
	GOOS=darwin GOARCH=arm64 go build -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 cmd/cyberspring/main.go
	GOOS=darwin GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 cmd/cyberspring/main.go

build-linux:
	@mkdir -p $(BUILD_DIR)
	@echo "🐧 Compiling for Linux (AMD64 + ARM64)..."
	GOOS=linux GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 cmd/cyberspring/main.go
	GOOS=linux GOARCH=arm64 go build -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 cmd/cyberspring/main.go

build-windows:
	@mkdir -p $(BUILD_DIR)
	@echo "🪟 Compiling for Windows (AMD64)..."
	GOOS=windows GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe cmd/cyberspring/main.go

run: build
	@./$(BINARY_NAME) -gui -port 8787

up:
	@./up.sh

down: stop

stop:
	@./down.sh

restart:
	@./down.sh
	@sleep 1
	@./up.sh

status:
	@echo "🔍 Checking CyberSpring server status..."
	@if lsof -ti tcp:8787 -sTCP:LISTEN >/dev/null 2>&1; then \
		echo "✅ CyberSpring is RUNNING on port 8787 (PID: $$(lsof -ti tcp:8787 -sTCP:LISTEN))"; \
		echo "🌐 URL: http://127.0.0.1:8787"; \
	else \
		echo "🛑 CyberSpring is DOWN (no process listening on port 8787)"; \
	fi

test:
	@echo "🧪 Running CyberSpring test suite..."
	go test -v ./pkg/...

scan: build
	@./$(BINARY_NAME) -scan test_samples/vulnerable_app

agent: build
	@./$(BINARY_NAME) -agent "Write a detection for password spraying against our VPN"

report: build
	@./$(BINARY_NAME) -report test_samples/vulnerable_app

clean:
	@rm -rf $(BINARY_NAME) $(BUILD_DIR) cyberspring_report.sarif cyberspring_report.md test_samples/vulnerable_app/*.bak
	@echo "🧹 Clean complete."
