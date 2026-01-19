# dnssec-tudor Makefile

BINARY := dnssec-tudor
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS := -ldflags "-X main.Version=$(VERSION) -X main.BuildTime=$(BUILD_TIME)"

.PHONY: all build build-linux build-linux-arm64 build-darwin build-darwin-arm64 build-freebsd build-all test clean

all: build

build:
	go build $(LDFLAGS) -o $(BINARY) .

build-linux:
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BINARY)-linux-amd64 .

build-linux-arm64:
	GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o $(BINARY)-linux-arm64 .

build-darwin:
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o $(BINARY)-darwin-amd64 .

build-darwin-arm64:
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o $(BINARY)-darwin-arm64 .

build-freebsd:
	GOOS=freebsd GOARCH=amd64 go build $(LDFLAGS) -o $(BINARY)-freebsd-amd64 .

build-all: build-linux build-linux-arm64 build-darwin build-darwin-arm64 build-freebsd

test:
	go test -v ./...

clean:
	rm -f $(BINARY) $(BINARY)-*
