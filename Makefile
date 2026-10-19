.PHONY: help fmt content-policy test-content-policy test-content-policy-git typecheck lint test build smoke all clean

help:
	@printf '%s\n' \
	  'NSCB development targets:' \
	  '  make content-policy          Check fixture provenance and repository content' \
	  '  make test-content-policy     Run Git-free policy tests' \
	  '  make test-content-policy-git Run genuine Git integration tests' \
	  '  make typecheck               Type-check all targets and features' \
	  '  make lint                    Check formatting and Clippy warnings' \
	  '  make test                    Run routine policy and Rust tests' \
	  '  make build                   Build the CLI and library' \
	  '  make smoke                   Run real-CLI subprocess integration tests' \
	  '  make fmt                     Apply Rust formatting (mutates source)' \
	  '  make all                     Run every routine validation profile' \
	  '  make clean                   Remove Cargo-generated build artifacts'

fmt:
	cargo fmt --all

content-policy:
	PYTHONDONTWRITEBYTECODE=1 python3 -B scripts/check_content_policy.py

test-content-policy:
	PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover -s tests -p 'test_content_policy.py'

test-content-policy-git:
	PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover -s tests -p 'test_content_policy_git.py'

typecheck:
	cargo check --locked --all-targets --all-features

lint:
	cargo fmt --all -- --check
	cargo clippy --locked --all-targets --all-features -- -D warnings

test:
	PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover -s tests -p 'test_content_policy.py'
	cargo test --locked

build:
	cargo build --locked

smoke:
	cargo test --locked --test cli_subprocess

all: content-policy typecheck lint test build smoke

clean:
	cargo clean
