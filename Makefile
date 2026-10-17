GO      ?= go
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -X main.version=$(VERSION)
export GOWORK := off

.PHONY: all build test test-race vet lint fmt clean rpm rpm-build \
	demo demo-build demo-status demo-revoke demo-renew demo-request demo-approve demo-advertise demo-clean

all: build

build:
	$(GO) build -ldflags "$(LDFLAGS)" -o bin/htc-registrationd ./cmd/htc-registrationd
	ln -sf htc-registrationd bin/htc-registration

test:
	$(GO) test ./...

test-race:
	$(GO) test -race ./...

vet:
	$(GO) vet ./...

lint:
	golangci-lint run ./...

fmt:
	gofmt -w cmd internal

clean:
	rm -rf bin dist packaging/staging

# --- Laptop demo -----------------------------------------------------------
# `make demo` runs a registrar, a mock OpenID provider, two CEs and, when
# HTCondor is installed (condor_collector on PATH, or CONDOR_BIN), a
# CE-Collector, all on loopback. State lives in $(DEMO_DIR).

DEMO_DIR ?= .demo
DEMO      = bin/htc-registrationd-demo -dir $(DEMO_DIR) -daemon bin/htc-registrationd

demo-build: build
	$(GO) build -o bin/htc-registrationd-demo ./cmd/htc-registrationd-demo

demo: demo-build
	@$(DEMO) run

demo-status: demo-build
	@$(DEMO) status

demo-revoke: demo-build
	@test -n "$(NAME)" || { echo "usage: make demo-revoke NAME=ce1.localhost"; exit 2; }
	@$(DEMO) cli registrar revoke $(NAME)

demo-renew: demo-build
	@test -n "$(CE)" || { echo "usage: make demo-renew CE=ce1"; exit 2; }
	@$(DEMO) cli $(CE) renew

demo-request: demo-build
	@test -n "$(CE)" || { echo "usage: make demo-request CE=ce1"; exit 2; }
	@$(DEMO) cli $(CE) request --approval

demo-approve: demo-build
	@test -n "$(CODE)" || { echo "usage: make demo-approve CODE=XXXX-XXXX"; exit 2; }
	@$(DEMO) cli registrar approve $(CODE)

demo-advertise: demo-build
	@test -n "$(CE)" -a -n "$(NAME)" || { echo "usage: make demo-advertise CE=ce1 NAME=ce2.localhost"; exit 2; }
	@$(DEMO) advertise $(CE) $(NAME)

demo-clean:
	rm -rf $(DEMO_DIR)

# --- RPM packaging -------------------------------------------------------

NFPM     ?= nfpm
PKG_ARCH ?= $(shell $(GO) env GOARCH)
PKG_DIR  ?= dist
# Where the payload is assembled for nfpm. Not overridable: nfpm globs
# contents.src literally, so this path is spelled out in packaging/nfpm.yaml
# and the two must agree.
PKG_STAGE := packaging/staging
PKG_MAINTAINER ?= Brian Bockelman <bbockelman@morgridge.org>
PKG_VENDOR     ?= HTCondor / PATh

rpm-build: ## Cross-build the daemon into $(PKG_STAGE) for linux/$(PKG_ARCH)
	@rm -rf $(PKG_STAGE) && mkdir -p $(PKG_STAGE)
	GOOS=linux GOARCH=$(PKG_ARCH) CGO_ENABLED=0 $(GO) build -trimpath \
		-ldflags '-s -w $(LDFLAGS)' -o $(PKG_STAGE)/htc-registrationd ./cmd/htc-registrationd

rpm: rpm-build ## Build an RPM for linux/$(PKG_ARCH) (PKG_ARCH=amd64|arm64)
	@command -v $(NFPM) >/dev/null 2>&1 || { \
		echo "nfpm not found: go install github.com/goreleaser/nfpm/v2/cmd/nfpm@v2.43.1"; \
		echo "or point NFPM at one you already have: make rpm NFPM=/path/to/nfpm"; \
		exit 1; }
	@mkdir -p $(PKG_DIR)
	@set -e; \
	set -- $$(packaging/rpm-version.sh "$(VERSION)"); \
	echo "Packaging htc-registrationd $$1-$$2 ($(PKG_ARCH))..."; \
	PKG_VERSION=$$1 PKG_RELEASE=$$2 PKG_ARCH=$(PKG_ARCH) \
	PKG_MAINTAINER="$(PKG_MAINTAINER)" PKG_VENDOR="$(PKG_VENDOR)" \
		$(NFPM) package --config packaging/nfpm.yaml --packager rpm --target $(PKG_DIR)
	@ls -1 $(PKG_DIR)/*.rpm
