# Golang-dnssec-validator Makefile
# Web-based DNSSEC troubleshooting and validation tool

BINARY := dnssec-validator
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS := -ldflags "-X main.Version=$(VERSION) -X main.BuildTime=$(BUILD_TIME)"

.PHONY: all build build-linux build-linux-arm64 build-darwin build-darwin-arm64 \
        build-freebsd build-all test clean fmt vet check help

# Default target
all: build

# Build for current platform
build:
	go build $(LDFLAGS) -o $(BINARY) .

# Build for Linux amd64
build-linux:
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BINARY)-linux-amd64 .

# Build for Linux arm64
build-linux-arm64:
	GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o $(BINARY)-linux-arm64 .

# Build for macOS amd64
build-darwin:
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o $(BINARY)-darwin-amd64 .

# Build for macOS arm64 (Apple Silicon)
build-darwin-arm64:
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o $(BINARY)-darwin-arm64 .

# Build for FreeBSD amd64
build-freebsd:
	GOOS=freebsd GOARCH=amd64 go build $(LDFLAGS) -o $(BINARY)-freebsd-amd64 .

# Build for all platforms
build-all: build-linux build-linux-arm64 build-darwin build-darwin-arm64 build-freebsd

# Run tests
test:
	go test -v -race ./...

# Format code
fmt:
	gofmt -s -w .

# Run go vet
vet:
	go vet ./...

# Run fmt and vet
check: fmt vet

# Clean build artifacts
clean:
	rm -f $(BINARY) $(BINARY)-*

# Show help
help:
	@echo "Golang-dnssec-validator Build System"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  build              Build for current platform"
	@echo "  build-linux        Build for Linux amd64"
	@echo "  build-linux-arm64  Build for Linux arm64"
	@echo "  build-darwin       Build for macOS amd64"
	@echo "  build-darwin-arm64 Build for macOS arm64 (Apple Silicon)"
	@echo "  build-freebsd      Build for FreeBSD amd64"
	@echo "  build-all          Build for all platforms"
	@echo "  test               Run tests with race detector"
	@echo "  fmt                Format code with gofmt"
	@echo "  vet                Run go vet"
	@echo "  check              Run fmt and vet"
	@echo "  clean              Remove build artifacts"
	@echo "  help               Show this help"
