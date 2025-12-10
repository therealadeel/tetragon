.PHONY: build clean test run install fmt vet

BINARY_NAME=control-plane-client
GO=go
GOFLAGS=-v

all: build

build:
	$(GO) build $(GOFLAGS) -o $(BINARY_NAME) -tags exclude_test_server .

clean:
	rm -f $(BINARY_NAME)

test:
	$(GO) test -v ./...

run: build
	./$(BINARY_NAME) --config config-example.yaml

install: build
	sudo mkdir -p /usr/local/bin
	sudo cp $(BINARY_NAME) /usr/local/bin/

fmt:
	$(GO) fmt ./...

vet:
	$(GO) vet ./...

deps:
	$(GO) mod download
	$(GO) mod tidy

help:
	@echo "Available targets:"
	@echo "  build   - Build the control plane client"
	@echo "  clean   - Remove built binaries and cache"
	@echo "  test    - Run tests"
	@echo "  run     - Build and run with example config"
	@echo "  install - Install binary to /usr/local/bin"
	@echo "  fmt     - Format code"
	@echo "  vet     - Run go vet"
	@echo "  deps    - Download and tidy dependencies"
