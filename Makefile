.PHONY: help build clean test fmt clippy qlty ci check-clean install-hooks

# Default target
help:
	@echo "Available commands:"
	@echo "  make build         - Build the release binary"
	@echo "  make clean         - Remove build artifacts"
	@echo "  make test          - Run tests"
	@echo "  make fmt           - Format code with rustfmt"
	@echo "  make clippy        - Run clippy linter"
	@echo "  make qlty          - Run qlty check (clippy + security scan)"
	@echo "  make ci            - Run all CI checks (qlty, test, build)"
	@echo "  make check-clean   - Check if working directory is clean"
	@echo "  make install-hooks - Install qlty git hooks"

# Build the release binary
build:
	@cargo build --release
	@echo "Build complete: target/release/pgwire-supabase-proxy"

# Clean build artifacts
clean:
	@cargo clean
	@echo "Cleaned build artifacts"

# Run tests
test:
	@cargo test

# Format code
fmt:
	@cargo fmt

# Run clippy linter
clippy:
	@cargo clippy --all-targets -- -D warnings

# Run qlty check (clippy + trufflehog + hadolint + osv-scanner)
qlty:
	@echo "Running qlty check..."
	@qlty check --all --no-progress
	@echo "✓ Qlty check complete"

# Run all checks and build
ci: clippy test build
	@echo "✓ CI checks complete"

# Check if working directory is clean (for CI)
check-clean:
	@if [ -n "$$(git status --porcelain)" ]; then \
		echo "❌ Working directory is not clean"; \
		git status --short; \
		exit 1; \
	else \
		echo "✓ Working directory is clean"; \
	fi

# Install qlty git hooks (pre-commit: fmt, pre-push: lint + security)
install-hooks:
	@qlty githooks install
	@echo "✓ Qlty hooks installed"
