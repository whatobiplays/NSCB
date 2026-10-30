override RUST_TOOLCHAIN := 1.98.1
RUSTUP ?= rustup
override RUST_TOOLCHAIN_BIN := $(patsubst %/,%,$(dir $(shell $(RUSTUP) which --toolchain $(RUST_TOOLCHAIN) cargo 2>/dev/null)))
override CARGO_BIN := $(shell $(RUSTUP) which --toolchain $(RUST_TOOLCHAIN) cargo 2>/dev/null)
override RUSTC_BIN := $(shell $(RUSTUP) which --toolchain $(RUST_TOOLCHAIN) rustc 2>/dev/null)
override RUSTFMT_BIN := $(shell $(RUSTUP) which --toolchain $(RUST_TOOLCHAIN) rustfmt 2>/dev/null)
TOOLCHAIN_ENV = env -u RUSTC_WRAPPER -u RUSTC_WORKSPACE_WRAPPER \
	RUSTUP_TOOLCHAIN=$(RUST_TOOLCHAIN) \
	RUSTC=$(RUSTC_BIN) \
	RUSTFMT=$(RUSTFMT_BIN) \
	PATH="$(RUST_TOOLCHAIN_BIN):$$PATH"
override CARGO := $(TOOLCHAIN_ENV) $(CARGO_BIN)
STANDALONE_FEATURES ?= standalone-job-history
RUST_TEST_THREADS ?= 1

.PHONY: help fmt content-policy test-content-policy test-content-policy-git test-cleanup test-cleanup-git typecheck embedded-boundary check-embedded-tests check-standalone-tests lint test build smoke all clean

help:
	@printf '%s\n' \
	  'NSCB development targets:' \
	  '  make content-policy          Check fixture provenance and repository content' \
	  '  make test-content-policy     Run Git-free policy tests' \
	  '  make test-content-policy-git Run genuine Git integration tests' \
	  '  make test-cleanup            Run Git-free disposable cleanup tests' \
	  '  make test-cleanup-git        Run genuine Git worktree cleanup tests' \
	  '  make typecheck               Type-check all targets and features' \
	  '  make embedded-boundary       Verify the no-default dependency graph has no SQLite' \
	  '  make check-embedded-tests   Require tests in the no-default library suite' \
	  '  make check-standalone-tests Require history and CLI subprocess tests' \
	  '  make lint                    Check formatting and Clippy warnings' \
	  '  make test                    Run policy and all feature-enabled Rust tests' \
	  '  make build                   Build the standalone nscb executable' \
	  '  make smoke                   Run real Job history and CLI subprocess tests' \
	  '  make fmt                     Apply Rust formatting (mutates source)' \
	  '  make all                     Run every routine validation profile' \
	  '  make clean                   Remove local target and Python bytecode (idle workspace)'

fmt:
	$(CARGO) fmt --all

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
	$(CARGO) check --locked --all-targets --all-features
	$(CARGO) check --locked --lib --no-default-features

embedded-boundary:
	@set -eu; \
		tree="$$($(CARGO) tree --locked --no-default-features --edges normal)" || { \
			echo 'error: cargo tree failed for the no-default dependency graph' >&2; exit 1; \
		}; \
		if printf '%s\n' "$$tree" | awk 'index($$0, "rusqlite ") > 0 { found = 1 } END { exit !found }'; then \
		echo 'error: rusqlite is present in the embedded library graph' >&2; \
		exit 1; \
	fi

check-embedded-tests:
	@set -eu; \
		listing="$$($(CARGO) test --locked --lib --no-default-features -- --list)"; \
		count="$$(printf '%s\n' "$$listing" | awk '/: test$$/ { count += 1 } END { print count + 0 }')"; \
		printf '%s\n' "embedded library tests: $$count"; \
		test "$$count" -gt 0 || { echo 'error: no embedded library tests were selected' >&2; exit 1; }

check-standalone-tests:
	@set -eu; \
		for target in job_history_cli cli_subprocess; do \
			listing="$$($(CARGO) test --locked --features $(STANDALONE_FEATURES) --test "$$target" -- --list)"; \
			count="$$(printf '%s\n' "$$listing" | awk '/: test$$/ { count += 1 } END { print count + 0 }')"; \
			printf '%s\n' "standalone $$target tests: $$count"; \
			test "$$count" -gt 0 || { echo "error: no tests selected for $$target" >&2; exit 1; }; \
		done

lint:
	$(CARGO) fmt --all -- --check
	$(CARGO) clippy --locked --all-targets --all-features -- -D warnings


test: test-content-policy test-cleanup build check-embedded-tests check-standalone-tests embedded-boundary
	RUST_TEST_THREADS=$(RUST_TEST_THREADS) $(CARGO) test --locked --lib --no-default-features
	RUST_TEST_THREADS=$(RUST_TEST_THREADS) $(CARGO) test --locked --features $(STANDALONE_FEATURES)

build:
	$(CARGO) build --locked --features $(STANDALONE_FEATURES)
	@set -eu; \
		target_dir="$${CARGO_TARGET_DIR:-target}"; \
		if [ -n "$${CARGO_BUILD_TARGET:-}" ]; then target_dir="$$target_dir/$${CARGO_BUILD_TARGET}"; fi; \
		binary="$$target_dir/debug/nscb"; \
		test -f "$$binary" && test -x "$$binary" && test ! -L "$$binary" || { \
			echo 'error: standalone nscb binary is missing or is not a regular executable' >&2; exit 1; \
		}; \
		"$$binary" --version >/dev/null

smoke: build check-standalone-tests
	RUST_TEST_THREADS=$(RUST_TEST_THREADS) $(CARGO) test --locked --features $(STANDALONE_FEATURES) --test job_history_cli --test cli_subprocess

all: content-policy typecheck embedded-boundary lint test build smoke

clean:
	PYTHONDONTWRITEBYTECODE=1 python3 -B scripts/clean.py
