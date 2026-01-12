# sscheck - Security Headers Check
# Makefile for building, testing, and releasing

# Application name
APP_NAME := sscheck
MODULE := github.com/statoon54/sscheck

# Directories
BUILD_DIR := bin
DIST_DIR := dist

# Version information
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
DATE := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

# Build flags
LDFLAGS := -s -w \
	-X '$(MODULE)/internal/version.Version=$(VERSION)' \
	-X '$(MODULE)/internal/version.Commit=$(COMMIT)' \
	-X '$(MODULE)/internal/version.Date=$(DATE)'

# Go commands
GO := go
GOBUILD := $(GO) build -trimpath -ldflags "$(LDFLAGS)"
GOTEST := $(GO) test
GOVET := $(GO) vet
GOFMT := gofmt
GOLINT := golangci-lint

# Platforms for cross-compilation
PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64

# Colors for terminal output
GREEN := \033[0;32m
YELLOW := \033[0;33m
RED := \033[0;31m
NC := \033[0m # No Color

.PHONY: all build clean test lint fmt vet deps help version release release-dry-run install uninstall

# Default target
all: clean lint test build

## Build targets

# Build for current platform
build:
	@echo "$(GREEN)Building $(APP_NAME)...$(NC)"
	@mkdir -p $(BUILD_DIR)
	$(GOBUILD) -o $(BUILD_DIR)/$(APP_NAME) .
	@echo "$(GREEN)✓ Build complete: $(BUILD_DIR)/$(APP_NAME)$(NC)"

# Build for all platforms
build-all: clean
	@echo "$(GREEN)Building for all platforms...$(NC)"
	@mkdir -p $(DIST_DIR)
	@for platform in $(PLATFORMS); do \
		os=$$(echo $$platform | cut -d'/' -f1); \
		arch=$$(echo $$platform | cut -d'/' -f2); \
		output=$(DIST_DIR)/$(APP_NAME)-$$os-$$arch; \
		if [ "$$os" = "windows" ]; then output=$$output.exe; fi; \
		echo "  Building $$os/$$arch..."; \
		GOOS=$$os GOARCH=$$arch $(GOBUILD) -o $$output . || exit 1; \
	done
	@echo "$(GREEN)✓ All builds complete$(NC)"

# Install to GOPATH/bin
install: build
	@echo "$(GREEN)Installing $(APP_NAME)...$(NC)"
	@cp $(BUILD_DIR)/$(APP_NAME) $(GOPATH)/bin/$(APP_NAME)
	@echo "$(GREEN)✓ Installed to $(GOPATH)/bin/$(APP_NAME)$(NC)"

# Uninstall from GOPATH/bin
uninstall:
	@echo "$(YELLOW)Removing $(APP_NAME) from $(GOPATH)/bin...$(NC)"
	@rm -f $(GOPATH)/bin/$(APP_NAME)
	@echo "$(GREEN)✓ Uninstalled$(NC)"

## Quality targets

# Run tests
test:
	@echo "$(GREEN)Running tests...$(NC)"
	$(GOTEST) -v -race -cover ./...

# Run tests with coverage report
test-coverage:
	@echo "$(GREEN)Running tests with coverage...$(NC)"
	@mkdir -p $(BUILD_DIR)
	$(GOTEST) -v -race -coverprofile=$(BUILD_DIR)/coverage.out ./...
	$(GO) tool cover -html=$(BUILD_DIR)/coverage.out -o $(BUILD_DIR)/coverage.html
	@echo "$(GREEN)✓ Coverage report: $(BUILD_DIR)/coverage.html$(NC)"

# Run linter
lint:
	@echo "$(GREEN)Running linter...$(NC)"
	@if command -v $(GOLINT) >/dev/null 2>&1; then \
		$(GOLINT) run ./...; \
	else \
		echo "$(YELLOW)golangci-lint not installed, skipping...$(NC)"; \
	fi

# Format code
fmt:
	@echo "$(GREEN)Formatting code...$(NC)"
	$(GOFMT) -s -w .
	@echo "$(GREEN)✓ Code formatted$(NC)"

# Check formatting
fmt-check:
	@echo "$(GREEN)Checking code format...$(NC)"
	@if [ -n "$$($(GOFMT) -l .)" ]; then \
		echo "$(RED)The following files need formatting:$(NC)"; \
		$(GOFMT) -l .; \
		exit 1; \
	fi
	@echo "$(GREEN)✓ All files properly formatted$(NC)"

# Run go vet
vet:
	@echo "$(GREEN)Running go vet...$(NC)"
	$(GOVET) ./...
	@echo "$(GREEN)✓ Vet complete$(NC)"

## Dependency targets

# Download dependencies
deps:
	@echo "$(GREEN)Downloading dependencies...$(NC)"
	$(GO) mod download
	$(GO) mod tidy
	@echo "$(GREEN)✓ Dependencies ready$(NC)"

# Update dependencies
deps-update:
	@echo "$(GREEN)Updating dependencies...$(NC)"
	$(GO) get -u ./...
	$(GO) mod tidy
	@echo "$(GREEN)✓ Dependencies updated$(NC)"

## Release targets

# Create release archives
release: build-all
	@echo "$(GREEN)Creating release archives...$(NC)"
	@mkdir -p $(DIST_DIR)/archives
	@for platform in $(PLATFORMS); do \
		os=$$(echo $$platform | cut -d'/' -f1); \
		arch=$$(echo $$platform | cut -d'/' -f2); \
		binary=$(DIST_DIR)/$(APP_NAME)-$$os-$$arch; \
		if [ "$$os" = "windows" ]; then binary=$$binary.exe; fi; \
		archive=$(DIST_DIR)/archives/$(APP_NAME)-$(VERSION)-$$os-$$arch; \
		if [ "$$os" = "windows" ]; then \
			zip -j $$archive.zip $$binary README.md LICENSE; \
		else \
			tar -czvf $$archive.tar.gz -C $(DIST_DIR) $$(basename $$binary) -C .. README.md LICENSE; \
		fi; \
	done
	@echo "$(GREEN)✓ Release archives created in $(DIST_DIR)/archives$(NC)"

# Dry run for release (builds without creating archives)
release-dry-run: build-all
	@echo "$(GREEN)Release dry run complete$(NC)"
	@echo "Version: $(VERSION)"
	@echo "Commit: $(COMMIT)"
	@echo "Date: $(DATE)"
	@ls -la $(DIST_DIR)/

# Create checksums for release files
checksums:
	@echo "$(GREEN)Creating checksums...$(NC)"
	@cd $(DIST_DIR)/archives && sha256sum * > checksums.txt
	@echo "$(GREEN)✓ Checksums created$(NC)"

## Utility targets

# Show version info
version:
	@echo "Version: $(VERSION)"
	@echo "Commit: $(COMMIT)"
	@echo "Date: $(DATE)"

# Clean build artifacts
clean:
	@echo "$(YELLOW)Cleaning build artifacts...$(NC)"
	@rm -rf $(BUILD_DIR) $(DIST_DIR)
	@echo "$(GREEN)✓ Clean complete$(NC)"

# Run the application
run: build
	@./$(BUILD_DIR)/$(APP_NAME)

# Show help
help:
	@echo "$(GREEN)$(APP_NAME) - Security Headers Check$(NC)"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Build targets:"
	@echo "  build         Build for current platform"
	@echo "  build-all     Build for all platforms"
	@echo "  install       Install to GOPATH/bin"
	@echo "  uninstall     Remove from GOPATH/bin"
	@echo ""
	@echo "Quality targets:"
	@echo "  test          Run tests"
	@echo "  test-coverage Run tests with coverage report"
	@echo "  lint          Run linter (golangci-lint)"
	@echo "  fmt           Format code"
	@echo "  fmt-check     Check code formatting"
	@echo "  vet           Run go vet"
	@echo ""
	@echo "Dependency targets:"
	@echo "  deps          Download dependencies"
	@echo "  deps-update   Update dependencies"
	@echo ""
	@echo "Release targets:"
	@echo "  release       Create release archives for all platforms"
	@echo "  release-dry-run  Build all platforms without archiving"
	@echo "  checksums     Create SHA256 checksums for releases"
	@echo ""
	@echo "Utility targets:"
	@echo "  version       Show version information"
	@echo "  clean         Clean build artifacts"
	@echo "  run           Build and run the application"
	@echo "  help          Show this help message"
