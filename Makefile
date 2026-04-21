# Makefile for Lynx Network Rule Processor

# Variables
CARGO := cargo

# Default target
.PHONY: all
all: build

# Build the project
.PHONY: build
build:
	@echo "Building..."
	$(CARGO) build --release

# Build npm package
npm_build:
	@echo "Building npm..."
	@cargo generate-rpm -p lynx

# Run tests
.PHONY: test
test:
	@echo "Running tests..."
	$(CARGO) test

# Run tests with output
.PHONY: test-verbose
test-verbose:
	@echo "Running tests (verbose)..."
	$(CARGO) test -- --nocapture

# Run linter
.PHONY: clippy
clippy:
	@echo "Running clippy..."
	$(CARGO) clippy -- -D warnings

# Format code
.PHONY: fmt
fmt:
	@echo "Formatting code..."
	$(CARGO) fmt

# Check formatting
.PHONY: fmt-check
fmt-check:
	@echo "Checking formatting..."
	$(CARGO) fmt -- --check


# Clean build artifacts
.PHONY: clean
clean:
	@echo "Cleaning build artifacts..."
	$(CARGO) clean

# Show help
.PHONY: help
help:
	@echo "Lynx Network Rule Processor - Makefile targets:"
	@echo ""
	@echo "  all          - Build the project (default)"
	@echo "  build        - Build the release binary"
	@echo "  test         - Run tests"
	@echo "  test-verbose - Run tests with output"
	@echo "  clippy       - Run linter"
	@echo "  fmt          - Format code"
	@echo "  fmt-check    - Check formatting"
	@echo "  clean        - Clean build artifacts"
	@echo "  help         - Show this help message"
