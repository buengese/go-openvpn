NDK_VERSION      := 30.0.14904198
ANDROID_API      := 31
ANDROID_SDK_HOME ?= $(HOME)/Android/Sdk
MODULE           := github.com/openlawsvpn/go-openlawsvpn
VERSION          ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
GOPATH           ?= $(shell go env GOPATH)

# Prefer the go-installed gomobile over any system package.
export PATH := $(GOPATH)/bin:$(PATH)

# Resolve NDK home: honour explicit override, then try common locations.
ifndef ANDROID_NDK_HOME
  ifdef ANDROID_SDK_ROOT
    ANDROID_NDK_HOME := $(ANDROID_SDK_ROOT)/ndk/$(NDK_VERSION)
  else ifdef ANDROID_HOME
    ANDROID_NDK_HOME := $(ANDROID_HOME)/ndk/$(NDK_VERSION)
  else
    ANDROID_NDK_HOME := $(ANDROID_SDK_HOME)/ndk/$(NDK_VERSION)
  endif
endif

.PHONY: all aar aar-sha256 cli build-macos-cli relay-server run-local-relay check-platforms test lint clean \
        build-bins test-integration-cli

all: aar

## Build the Android .aar
aar: go-openlawsvpn.aar

go-openlawsvpn.aar:
	@command -v gomobile >/dev/null 2>&1 || { \
	  echo "gomobile not found — run: go install golang.org/x/mobile/cmd/gomobile@latest && gomobile init"; \
	  exit 1; \
	}
	@test -n "$(ANDROID_NDK_HOME)" || { \
	  echo "ANDROID_NDK_HOME is not set and could not be derived from ANDROID_SDK_ROOT/ANDROID_HOME."; \
	  echo "Set it explicitly: make aar ANDROID_NDK_HOME=/path/to/ndk/$(NDK_VERSION)"; \
	  exit 1; \
	}
	ANDROID_NDK_HOME=$(ANDROID_NDK_HOME) gomobile bind -v \
	  -o go-openlawsvpn.aar \
	  -target android \
	  -androidapi $(ANDROID_API) \
	  -ldflags "-X $(MODULE).Version=$(VERSION)" \
	  $(MODULE)

## Compute SHA-256 checksum alongside the .aar
aar-sha256: go-openlawsvpn.aar
	sha256sum go-openlawsvpn.aar > go-openlawsvpn.aar.sha256

## Build the Linux CLI binary (CGO_ENABLED=0 → fully static)
cli:
	CGO_ENABLED=0 go build -o openlawsvpn-cli ./cmd/cli

## Build macOS CLI binaries (arm64 + amd64; requires sudo to run — utun needs root).
build-macos-cli:
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build \
		-o openlawsvpn-cli-macos-arm64 ./cmd/cli
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build \
		-o openlawsvpn-cli-macos-amd64 ./cmd/cli

## Build the local relay-server test binary
relay-server:
	CGO_ENABLED=0 go build -o relay-server ./cmd/relay-server

## Start the local relay server for testing (default port 18080, override with RELAY_ADDR)
## Agent:  openlawsvpn-cli -config tunnel.ovpn -relay <token> -relay-endpoint ws://localhost:18080/ws
## App:    set endpoint to http://<host>:18080/api/v1
RELAY_ADDR ?= :18080
run-local-relay:
	CGO_ENABLED=0 go run ./cmd/relay-server -addr $(RELAY_ADDR)

## Verify builds cleanly for all four supported platforms (used by pre-commit).
check-platforms:
	GOOS=linux   GOARCH=amd64  go build ./...
	GOOS=android GOARCH=arm64  go build ./...
	GOOS=darwin  GOARCH=arm64  go build ./...
	GOOS=darwin  GOARCH=arm64  go build -tags ios ./...

## Run unit tests
test:
	go test -race ./...

## Run integration tests (starts local mock server, no Docker needed)
integration-test:
	go test -v -tags=integration -timeout 120s .

## Build CLI + mock-server binaries into bin/
build-bins:
	mkdir -p bin
	go build -o bin/mock-server ./mock/mockserver
	CGO_ENABLED=0 go build -o bin/openlawsvpn-cli ./cmd/cli

## CLI binary integration test: starts mock server, connects CLI in daemon mode, asserts tunnel up.
## Requires sudo (TUN device creation). Binaries are built automatically if missing.
test-integration-cli: build-bins
	bash scripts/cli-integration.sh

## Run go vet (both build configurations) and golangci-lint
## golangci-lint must be v2.x; the config uses the v2 schema. A binary built
## with an older Go than go.mod's target refuses to start, so keep it current:
##   go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest
lint:
	go vet ./...
	go vet -tags=mockserver ./...
	go vet -tags=docker ./...
	go vet -tags=privileged ./...
	go vet -tags=soak ./...
	go vet -tags=mobileapi ./...
	# The ios-tagged files are reachable only under a darwin GOOS, so vetting
	# them needs the same spelling check-platforms builds them with. Without
	# this, dns/dns_ios.go, routing/netlink_ios.go and tun/tun_ios.go were
	# linted by nothing at all.
	GOOS=darwin GOARCH=arm64 go vet -tags=ios ./...
	@command -v golangci-lint >/dev/null 2>&1 || { \
	  echo "golangci-lint not found — run:"; \
	  echo "  go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest"; \
	  exit 1; \
	}
	golangci-lint run ./...

## Remove build artefacts
clean:
	rm -f go-openlawsvpn.aar go-openlawsvpn.aar.sha256 go-openlawsvpn-sources.jar openlawsvpn-cli relay-server cli
	rm -rf bin/
