.PHONY: help fmt content-policy test-content-policy test-content-policy-git test-cleanup test-cleanup-git typecheck lint test build smoke all clean

help:
	@printf '%s\n' \
	  'NSCB development targets:' \
	  '  make content-policy          Check fixture provenance and repository content' \
	  '  make test-content-policy     Run Git-free policy tests' \
	  '  make test-content-policy-git Run genuine Git integration tests' \
	  '  make test-cleanup            Run Git-free disposable cleanup tests' \
	  '  make test-cleanup-git        Run genuine Git worktree cleanup tests' \
	  '  make typecheck               Type-check all targets and features' \
	  '  make lint                    Check formatting and Clippy warnings' \
	  '  make test                    Run routine policy and Rust tests' \
	  '  make build                   Build the CLI and library' \
	  '  make smoke                   Run real-CLI subprocess integration tests' \
	  '  make fmt                     Apply Rust formatting (mutates source)' \
	  '  make all                     Run every routine validation profile' \
	  '  make clean                   Remove local target and Python bytecode (idle workspace)'

fmt:
	cargo fmt --all

content-policy:
	PYTHONDONTWRITEBYTECODE=1 python3 -B scripts/check_content_policy.py

test-content-policy:
	PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover -s tests -p 'test_content_policy.py'

test-content-policy-git:
	PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover -s tests -p 'test_content_policy_git.py'

test-cleanup:
	PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover -s tests -p 'test_cleanup.py'

test-cleanup-git:
	PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover -s tests -p 'test_cleanup_git.py'

typecheck:
	cargo check --locked --all-targets --all-features

lint:
	cargo fmt --all -- --check
	cargo clippy --locked --all-targets --all-features -- -D warnings

test: test-content-policy test-cleanup
	cargo test --locked

build:
	cargo build --locked

smoke:
	cargo test --locked --test cli_subprocess

all: content-policy typecheck lint test build smoke

clean:
	PYTHONDONTWRITEBYTECODE=1 python3 -B scripts/clean.py
