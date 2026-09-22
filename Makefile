BINARY     := twagentneo
VERSION    := $(shell git describe --tags --always --dirty 2>/dev/null || echo "v0.1.0")
LDFLAGS    := -s -w -X main.version=$(VERSION)
BUILD_OPTS := CGO_ENABLED=0

.PHONY: all build linux windows darwin clean tidy

all: linux windows darwin

build:
	$(BUILD_OPTS) go build -ldflags="$(LDFLAGS)" -o $(BINARY) ./cmd/twagentneo

linux:
	$(BUILD_OPTS) GOOS=linux   GOARCH=amd64  go build -ldflags="$(LDFLAGS)" -o dist/$(BINARY)-linux-amd64   ./cmd/twagentneo
	$(BUILD_OPTS) GOOS=linux   GOARCH=arm64  go build -ldflags="$(LDFLAGS)" -o dist/$(BINARY)-linux-arm64   ./cmd/twagentneo

windows:
	$(BUILD_OPTS) GOOS=windows GOARCH=amd64  go build -ldflags="$(LDFLAGS)" -o dist/$(BINARY)-windows-amd64.exe ./cmd/twagentneo

darwin:
	$(BUILD_OPTS) GOOS=darwin  GOARCH=arm64  go build -ldflags="$(LDFLAGS)" -o dist/$(BINARY)-darwin-arm64  ./cmd/twagentneo
	$(BUILD_OPTS) GOOS=darwin  GOARCH=amd64  go build -ldflags="$(LDFLAGS)" -o dist/$(BINARY)-darwin-amd64  ./cmd/twagentneo

tidy:
	go mod tidy

clean:
	rm -rf dist/ $(BINARY)

dist/:
	mkdir -p dist
