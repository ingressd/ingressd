GO      ?= go
BIN     ?= bin
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
PKG     := github.com/ingressd/ingressd
LDFLAGS := -s -w -X $(PKG)/internal/version.Version=$(VERSION) -X $(PKG)/internal/version.Commit=$(COMMIT)
TESTFLAGS ?=

export CGO_ENABLED ?= 0

.PHONY: all build build-control build-connector build-edge build-e2e test test-control test-edge \
	tidy lint vuln check-edge-modules validate-example spike-netmap e2e \
	e2e-changed check check-all affected \
	build-connectors release-local docker-connector docker-node actionlint clean

all: build

build: build-control build-connector build-edge

build-control:
	$(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN)/ingressd ./cmd/ingressd

build-connector:
	$(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN)/ingressd-connector ./cmd/ingressd-connector

build-edge:
	cd edge && $(GO) build -trimpath -ldflags '-s -w' -o ../$(BIN)/ingressd-edge ./cmd/ingressd-edge

# Everything the netns e2e suites run: the binaries plus the test-only fake
# panel (managed-node) and Smart DNS helper (smartdns).
build-e2e: build
	$(GO) build -o $(BIN)/fakepanel ./test/fakepanel/cmd/fakepanel
	$(GO) build -o $(BIN)/ingressd-sdtool ./test/netns/sdtool
	$(GO) build -o $(BIN)/fakeidp ./test/fakeidp/cmd/fakeidp
	$(GO) build -tags idptest -o $(BIN)/ingressd-idptest ./cmd/ingressd

# The connector for every client platform CI builds:
# bin/ingressd-connector_<os>_<arch>[.exe] (release asset names).
CONNECTOR_PLATFORMS ?= linux/amd64 linux/arm64 windows/amd64 darwin/arm64
build-connectors:
	@for p in $(CONNECTOR_PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; ext=; [ $$os = windows ] && ext=.exe; \
		echo "==> ingressd-connector $$os/$$arch"; \
		GOOS=$$os GOARCH=$$arch $(GO) build -trimpath -ldflags '$(LDFLAGS)' \
			-o $(BIN)/ingressd-connector_$${os}_$$arch$$ext ./cmd/ingressd-connector || exit 1; \
	done

test: test-control test-edge

test-control:
	$(GO) test $(TESTFLAGS) ./...

test-edge:
	cd edge && $(GO) test $(TESTFLAGS) ./...

tidy:
	$(GO) mod tidy
	cd edge && $(GO) mod tidy

lint:
	golangci-lint run ./...
	cd edge && golangci-lint run ./...

vuln:
	$(GO) run golang.org/x/vuln/cmd/govulncheck@latest ./...
	cd edge && $(GO) run golang.org/x/vuln/cmd/govulncheck@latest ./...

check-edge-modules: build-edge
	./scripts/check-edge-modules.sh $(BIN)/ingressd-edge

validate-example: build-control
	$(BIN)/ingressd validate -f examples/config.yaml

# Needs root and Linux (iproute2, wireguard-tools, nftables, python3, curl).
spike-netmap:
	sudo ./test/netns/netmap-spike.sh

# End-to-end tests in network namespaces (Linux; the suites run as root via
# sudo). scripts/e2e.sh builds once (Go build cache) and runs the suites in
# parallel (E2E_JOBS, default nproc). Narrow the set by name, e.g.
#   make e2e E2E_TESTS="l4-forwarding managed-node"
# See docs/TESTING.md.
E2E_TESTS ?=
e2e:
	./scripts/e2e.sh $(E2E_TESTS)

# Only the suites the current change affects (test/netns/affected.map).
e2e-changed:
	./scripts/e2e.sh --changed $(BASE)


# gofmt + vet + unit tests of the affected packages (and their reverse
# dependencies) in both modules, then the affected e2e suites. BASE=<ref>
# picks the diff base (default origin/main).
check:
	./scripts/check.sh $(if $(BASE),--base $(BASE))

check-all:
	./scripts/check.sh --all

# What the current change affects (suites and packages).
affected:
	@echo "suites:"; ./scripts/affected.sh $(if $(BASE),--base $(BASE)) suites | sed 's/^/  /'
	@echo "packages:"; ./scripts/affected.sh $(if $(BASE),--base $(BASE)) packages . | sed 's/^/  /'
	@echo "edge packages:"; ./scripts/affected.sh $(if $(BASE),--base $(BASE)) packages edge | sed 's/^/  /'

# All release binaries, install-connector.sh and SHA256SUMS in dist/: the
# same layout as a GitHub release (scripts/build-release.sh).
release-local:
	VERSION=$(VERSION) COMMIT=$(COMMIT) GO=$(GO) ./scripts/build-release.sh dist

IMAGE_PREFIX ?= ingressd
docker-connector:
	docker build -f Dockerfile.connector --build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) \
		-t $(IMAGE_PREFIX)-connector:$(VERSION) .

docker-node:
	docker build -f Dockerfile.node --build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) \
		-t $(IMAGE_PREFIX)-node:$(VERSION) .

# Lints .github/workflows (go install github.com/rhysd/actionlint/cmd/actionlint@latest).
actionlint:
	actionlint

clean:
	rm -rf $(BIN) dist
