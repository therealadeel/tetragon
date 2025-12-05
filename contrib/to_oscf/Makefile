.PHONY: build clean test run run-config validate-output

# Binary name
BINARY_NAME = to_oscf

# Go parameters
GOCMD = go
GOBUILD = $(GOCMD) build
GOCLEAN = $(GOCMD) clean
GOTEST = $(GOCMD) test
GOGET = $(GOCMD) get
GOMOD = $(GOCMD) mod

# Default target
all: build

# Build the binary
build:
	$(GOBUILD) -o $(BINARY_NAME) main.go

# Clean build artifacts
clean:
	$(GOCLEAN)
	rm -f $(BINARY_NAME)

# Download dependencies
deps:
	$(GOMOD) download
	$(GOMOD) tidy

# Run tests
test:
	$(GOTEST) -v ./...

# Run with default configuration
run: build
	./$(BINARY_NAME)

# Run with sample configuration
run-config: build
	./$(BINARY_NAME) -config config.yaml

# Run with output to file
run-file: build
	OCSF_OUTPUT_FILE=./tetragon-ocsf.json ./$(BINARY_NAME) -config config.yaml

# Run with export directory
run-export: build
	TETRAGON_EXPORT_DIR=./output ./$(BINARY_NAME) -config config.yaml

# Validate OCSF output format (requires jq)
validate-output: build
	@echo "Running converter and validating OCSF format..."
	timeout 10s ./$(BINARY_NAME) -config config.yaml 2>/dev/null | head -1 | jq . || echo "No events received or invalid JSON"

# Development targets
dev: deps build

# Check for required tools
check-tools:
	@which jq >/dev/null || (echo "jq is required for validation. Install with: brew install jq" && exit 1)
	@which timeout >/dev/null || (echo "timeout is required for testing" && exit 1)

# Install the binary to system PATH
install: build
	cp $(BINARY_NAME) /usr/local/bin/

# Create output directory
output:
	mkdir -p output

# Format Go code
fmt:
	$(GOCMD) fmt ./...

# Lint Go code (requires golangci-lint)
lint:
	golangci-lint run

# Help target
help:
	@echo "Available targets:"
	@echo "  build         - Build the to_oscf binary"
	@echo "  clean         - Clean build artifacts"
	@echo "  deps          - Download and tidy Go dependencies"
	@echo "  test          - Run tests"
	@echo "  run           - Run with default configuration"
	@echo "  run-config    - Run with config.yaml"
	@echo "  run-file      - Run with output to file"
	@echo "  run-export    - Run with export directory"
	@echo "  validate-output - Validate OCSF output format"
	@echo "  dev           - Development build (deps + build)"
	@echo "  check-tools   - Check for required tools"
	@echo "  install       - Install binary to /usr/local/bin"
	@echo "  fmt           - Format Go code"
	@echo "  lint          - Lint Go code"
	@echo "  help          - Show this help message"