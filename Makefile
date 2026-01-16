GO_BIN=systemd-mcp
GO_FILES=$(shell find . -type f -name '*.go' -not -path "./vendor/*")
godeps=$(shell 2>/dev/null go list -mod vendor -deps -f '{{if not .Standard}}{{ $dep := . }}{{range .GoFiles}}{{$dep.Dir}}/{{.}} {{end}}{{end}}' $(1) | sed "s%$(shell pwd)/%%g")

# Install parameters
PREFIX ?= /usr
DESTDIR ?=
POLICYDIR ?= $(DESTDIR)$(PREFIX)/share

.PHONY: all build vendor test format lint clean dist install version

all: build

build: version $(godeps)
	go build -o $(GO_BIN) -mod=vendor .

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
	rm -f $(GO_BIN) ./vendor
	go clean -modcache

dist: build vendor
	tar -czvf $(GO_BIN).tar.gz $(GO_BIN) vendor

install: build policyinstall
	install -D -m 0755 $(GO_BIN) $(DESTDIR)$(PREFIX)/bin/$(GO_BIN)

policyinstall:
	install -D -m 0644 configs/org.opensuse.systemdmcp.policy $(POLICYDIR)/polkit-1/actions/org.opensuse.systemdmcp.policy
	install -D -m 0644 configs/org.opensuse.systemdmcp.conf   $(POLICYDIR)/dbus-1/system.d/org.opensuse.systemdmcp.conf

