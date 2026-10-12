.PHONY: help fmt typecheck lint test build smoke all

help:
	@printf '%s\n' \
		'NSCB development targets:' \
		'  make all        Run every validation profile' \
		'  make typecheck  Type-check all targets and features' \
		'  make lint       Check formatting and Clippy warnings' \
		'  make test       Run the complete Rust test suite' \
		'  make build      Build the CLI and library' \
		'  make smoke      Run real-CLI subprocess integration tests' \
		'  make fmt        Apply Rust formatting (mutates source)'

fmt:
	cargo fmt --all

typecheck:
	cargo check --locked --all-targets --all-features

lint:
	cargo fmt --all -- --check
	cargo clippy --locked --all-targets --all-features -- -D warnings

test:
	cargo test --locked

build:
	cargo build --locked

smoke:
	cargo test --locked --test cli_subprocess

all: typecheck lint test build smoke
