BINARY := gofence
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
LDFLAGS := -s -w -X github.com/nixteg/gofence/cmd.version=$(VERSION) -X github.com/nixteg/gofence/cmd.commit=$(COMMIT)

.PHONY: build static test vet tidy clean

build:
	go build -ldflags '$(LDFLAGS)' -o $(BINARY) .

# Binário estático portátil, sem CGO (modernc.org/sqlite é pure Go).
static:
	CGO_ENABLED=0 go build -ldflags '$(LDFLAGS)' -o $(BINARY) .

test:
	go test -race ./...

vet:
	go vet ./...

tidy:
	go mod tidy

clean:
	rm -f $(BINARY)
