.PHONY: help fmt content-policy typecheck lint test test-git-ai-paused build smoke all all-git-ai-paused clean

help:
	@printf '%s\n' \
		'NSCB development targets:' \
		'  make all        Run every validation profile' \
		'  make all-git-ai-paused Run every profile with Git AI paused for policy tests' \
		'  make content-policy Check fixture provenance and repository content' \
		'  make typecheck  Type-check all targets and features' \
		'  make lint       Check formatting and Clippy warnings' \
		'  make test       Run Python policy/lifecycle tests and the Rust test suite' \
		'  make build      Build the CLI and library' \
		'  make smoke      Run real-CLI subprocess integration tests' \
		'  make fmt        Apply Rust formatting (mutates source)' \
		'  make clean      Remove Cargo-generated build artifacts'

fmt:
	cargo fmt --all

content-policy:
	PYTHONDONTWRITEBYTECODE=1 python3 -B scripts/check_content_policy.py

typecheck:
	cargo check --locked --all-targets --all-features

lint:
	cargo fmt --all -- --check
	cargo clippy --locked --all-targets --all-features -- -D warnings

test:
	PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover -s tests -p 'test_content_policy.py'
	PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover -s tests -p 'test_git_ai_isolation.py'
	cargo test --locked

test-git-ai-paused:
	PYTHONDONTWRITEBYTECODE=1 python3 -B scripts/git_ai_isolation.py
	PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover -s tests -p 'test_git_ai_isolation.py'
	cargo test --locked

build:
	cargo build --locked

smoke:
	cargo test --locked --test cli_subprocess

all: content-policy typecheck lint test build smoke

# Recursive makes keep the `all` profile order even when this target is invoked
# with -j, while replacing only the Python content-policy suite with its pause wrapper.
all-git-ai-paused:
	$(MAKE) content-policy
	$(MAKE) typecheck
	$(MAKE) lint
	$(MAKE) test-git-ai-paused
	$(MAKE) build
	$(MAKE) smoke

clean:
	cargo clean
