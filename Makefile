BINARY      := adblockerpro
VERSION     ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS     := -s -w -X main.version=$(VERSION) -X github.com/ahardkore/adblockerpro/internal/api.Version=$(VERSION)
GOFLAGS     := -trimpath
DIST        := dist

.PHONY: all build test vet fmt run clean pi pi32 pi64 release install

all: build

## build: compile for the host
build:
	go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/adblockerpro

## test: run the unit tests
test:
	go test ./... -count=1

## vet: static analysis
vet:
	go vet ./...

fmt:
	gofmt -l -w .

## run: run locally on unprivileged ports (DNS 5353, dashboard 8080)
run: build
	./$(BINARY) -config ./dev-config.json -data-dir ./dev-data -dns-port 5353 -web-port 8080 -log-level debug

## pi64: Raspberry Pi 3/4/5 and Zero 2 W running 64-bit Raspberry Pi OS
pi64:
	mkdir -p $(DIST)
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(DIST)/$(BINARY)-linux-arm64 ./cmd/adblockerpro

## pi32: Raspberry Pi 2/3/4 running 32-bit Raspberry Pi OS
pi32:
	mkdir -p $(DIST)
	GOOS=linux GOARCH=arm GOARM=7 CGO_ENABLED=0 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(DIST)/$(BINARY)-linux-armv7 ./cmd/adblockerpro

## pi: Pi 1 / Zero / Zero W (ARMv6)
pi:
	mkdir -p $(DIST)
	GOOS=linux GOARCH=arm GOARM=6 CGO_ENABLED=0 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(DIST)/$(BINARY)-linux-armv6 ./cmd/adblockerpro

## release: build every Raspberry Pi target plus amd64
release: pi pi32 pi64
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(DIST)/$(BINARY)-linux-amd64 ./cmd/adblockerpro
	cd $(DIST) && sha256sum $(BINARY)-* > SHA256SUMS

## install: install the host build as a systemd service (run with sudo)
install: build
	./deploy/install.sh --local

clean:
	rm -rf $(BINARY) $(DIST) dev-data dev-config.json
