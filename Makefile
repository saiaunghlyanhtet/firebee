# Firebee Makefile

.PHONY: all build clean test run_bpf_tests help

# Default target
all: build

# Build the project
build:
	@echo "Building Firebee..."
	cargo build --release
	cargo libbpf build

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	cargo clean
	rm -f src/bpf/*.skel.rs

# Run userspace tests
test:
	@echo "Running userspace tests..."
	cargo test --bins

# Run BPF helper function tests (kernel-side, Cilium-style)
run_bpf_tests:
	@echo "Firebee BPF Kernel-Side Test Suite"
	@echo "========================================================================"
	@echo "Test framework: Cilium-style CHECK/TEST macros"
	@echo "Location: src/bpf/firebee_test.bpf.c"
	@echo ""
	@echo "Executing kernel-side BPF tests (requires root/CAP_BPF)..."
	@echo ""
	@sudo -E cargo test --test bpf_tests -- --ignored --nocapture || \
		(echo "" && \
		 echo "Note: Tests require root privileges to load BPF programs" && \
		 echo "Run with: sudo make run_bpf_tests" && \
		 exit 1)
	@echo ""
	@echo "========================================================================"

# Run all tests (userspace + BPF helper tests)
test_all:
	@echo "========================================================================"
	@echo "Running all tests (userspace + BPF kernel tests)"
	@echo "========================================================================"
	@echo ""
	@echo "[1/2] Running userspace tests..."
	@cargo test
	@echo ""
	@echo "========================================================================"
	@echo "[2/2] Running BPF kernel-side tests..."
	@echo "========================================================================"
	@echo ""
	@sudo -E cargo test --test bpf_tests -- --ignored --nocapture || \
		(echo "" && \
		 echo "Note: BPF tests require root privileges to load BPF programs" && \
		 echo "Run with: sudo make test_all" && \
		 exit 1)
	@echo ""
	@echo "========================================================================"
	@echo "All tests completed successfully!"
	@echo "========================================================================"

# Check code formatting
fmt:
	@echo "Checking code formatting..."
	cargo fmt -- --check

# Format code
fmt_fix:
	@echo "Formatting code..."
	cargo fmt

# Run clippy lints
clippy:
	@echo "Running clippy..."
	cargo clippy -- -D warnings


# Display help
help:
	@echo "Firebee Makefile targets:"
	@echo ""
	@echo "  make build              - Build the project in release mode"
	@echo "  make clean              - Clean build artifacts"
	@echo "  make test               - Run userspace tests (lib + bins)"
	@echo "  make run_bpf_tests      - Run BPF helper function tests (requires sudo)"
	@echo "  make test_all           - Run all tests: userspace + BPF (requires sudo)"
	@echo "  make fmt                - Check code formatting"
	@echo "  make fmt_fix            - Format code"
	@echo "  make clippy             - Run clippy lints"
	@echo "  make help               - Display this help message"
	@echo ""
	@echo "Test categories:"
	@echo "  - userspace tests: Regular Rust library and binary tests"
	@echo "  - BPF tests: Tests for BPF helper functions (IP/port matching, etc.)"