GO      ?= go
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -X main.version=$(VERSION)
export GOWORK := off

.PHONY: all build test test-race vet lint fmt clean rpm rpm-build

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
