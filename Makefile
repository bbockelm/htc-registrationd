GO      ?= go
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -X main.version=$(VERSION)
export GOWORK := off

.PHONY: all build test test-race vet lint fmt clean

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
	rm -rf bin
