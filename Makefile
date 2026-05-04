GO_FILES=$(shell find . -type f -name '*.go' -not -path "./vendor/*")
godeps=$(shell 2>/dev/null go list -mod vendor -deps -f '{{if not .Standard}}{{ $dep := . }}{{range .GoFiles}}{{$dep.Dir}}/{{.}} {{end}}{{end}}' $(1) | sed "s%$(shell pwd)/%%g")

# Install parameters
PREFIX ?= /usr
DESTDIR ?=
BINDIR ?= $(PREFIX)/bin
SBINDIR ?= $(PREFIX)/sbin
DATADIR ?= $(PREFIX)/share
SYSTEMDDIR ?= $(PREFIX)/lib/systemd/system
DBUSDIR ?= $(DATADIR)/dbus-1/system.d
POLKITDIR ?= $(DATADIR)/polkit-1/actions

GO = go
GOFLAGS = -buildmode=pie

.PHONY: all build test-client vendor test format lint clean dist install version

all: build test-client

build: version $(godeps)
	mkdir -p bin
	$(GO) build $(GOFLAGS) -o bin/systemd-mcp -mod=vendor .
	$(GO) build $(GOFLAGS) -o bin/gatekeeper  -mod=vendor ./gatekeeper

test-client: version $(godeps)
	go build -o test-client -mod=vendor ./testClient

version:
	@if git rev-parse --git-dir > /dev/null 2>&1; then \
		if git show HEAD:VERSION >/dev/null 2>&1; then \
			BASE_VERSION=$$(git show HEAD:VERSION); \
		elif git show :VERSION >/dev/null 2>&1; then \
			BASE_VERSION=$$(git show :VERSION); \
		else \
			BASE_VERSION=$$(cat VERSION | sed 's/-[0-9a-f]\{7\}.*//'); \
		fi; \
		GIT_HASH=$$(git rev-parse --short HEAD); \
		if ! git diff --quiet -- . ':!VERSION'; then \
			GIT_DIRTY="-dirty"; \
		fi; \
		echo "$${BASE_VERSION}-$${GIT_HASH}$${GIT_DIRTY}" > VERSION; \
	fi

vendor:
	go mod tidy
	go mod vendor

test:
	go test ./...

format:
	go fmt $(GO_FILES)

lint:
	@if ! command -v golangci-lint &> /dev/null; then \
		echo "golangci-lint is not installed. Please install it: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"; \
		exit 1; \
	fi
	golangci-lint run ./...

clean:
	rm -rf ./bin ./vendor server.crt server.key
	go clean -modcache

certs:
	openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes -subj "/CN=localhost"

dist: version vendor
	tar -czf systemd-mcp.tar.gz --transform 's,^,systemd-mcp/,' $(shell git ls-files) vendor/

install: build policyinstall
	install -D -m 0755 bin/systemd-mcp $(DESTDIR)$(BINDIR)/systemd-mcp
	install -D -m 0755 bin/gatekeeper $(DESTDIR)$(SBINDIR)/gatekeeper

policyinstall:
	install -D -m 0644 configs/gatekeeper.service $(DESTDIR)$(SYSTEMDDIR)/gatekeeper.service
	install -D -m 0644 configs/gatekeeper.socket $(DESTDIR)$(SYSTEMDDIR)/gatekeeper.socket
	install -D -m 0644 configs/com.suse.gatekeeper.policy $(DESTDIR)$(POLKITDIR)/com.suse.gatekeeper.policy

