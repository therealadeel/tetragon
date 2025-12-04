.PHONY: build run clean test

# Build the file mod enricher
build:
	go build -o file-mod-enricher .

# Run with default configuration 
run: build
	./file-mod-enricher

# Run with custom config file
run-config: build
	./file-mod-enricher -config config.yaml

# Run with file output
run-file: build
	ENRICHER_OUTPUT_FILE=/tmp/file-modifications.json ./file-mod-enricher -config config.yaml

# Run tests
test:
	go test ./...

# Clean build artifacts
clean:
	rm -f file-mod-enricher

# Install dependencies
deps:
	go mod tidy
	go mod download

# Format code
fmt:
	go fmt ./...

# Vet code
vet:
	go vet ./...

# Run all checks
check: fmt vet test

# Development workflow
dev: clean check build

# Example: Run Tetragon and enricher together in separate terminals
demo:
	@echo "Terminal 1: sudo tetragon --export-filename=/tmp/tetragon-raw.json --server-address=localhost:54321"
	@echo "Terminal 2: TETRAGON_EXPORT_DIR=/tmp ./file-mod-enricher -config config.yaml"
	@echo "Terminal 3: echo 'test:x:1001:1001:Test User:/home/test:/bin/bash' | sudo tee -a /etc/passwd"

.DEFAULT_GOAL := build