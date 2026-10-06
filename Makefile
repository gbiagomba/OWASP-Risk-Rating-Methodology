# Makefile (PRO)
# Satisfies RULE 2 - maintain Makefile
# Satisfies RULE 1 - test before delivery
#
# `make ci` runs the same gate as RULE 1 and as the GitHub Actions workflow.

APP_NAME     := riskforge
CARGO        := cargo
BUILD_DIR    := target/release
INSTALL_PATH := /usr/local/bin
DOCKER       := docker

.PHONY: all build release install uninstall run run-release test check fmt fmt-check \
        clippy audit ci docker docker-run clean help

all: release

## build: compile an optimized binary
build:
	$(CARGO) build --release

release: build

## install: install the binary with cargo
install:
	$(CARGO) install --path .

## uninstall: remove a cargo-installed binary
uninstall:
	$(CARGO) uninstall $(APP_NAME)

## run: run a debug build, pass arguments with ARGS="..."
run:
	$(CARGO) run -- $(ARGS)

## run-release: run the optimized build
run-release: build
	$(BUILD_DIR)/$(APP_NAME) $(ARGS)

## test: run the whole test suite
test:
	$(CARGO) test --all --no-fail-fast

## check: type-check without producing a binary
check:
	$(CARGO) check --all-targets

## fmt: format the source tree
fmt:
	$(CARGO) fmt --all

## fmt-check: fail when the source tree is not formatted
fmt-check:
	$(CARGO) fmt --all -- --check

## clippy: lint, treating every warning as an error
clippy:
	$(CARGO) clippy --all-targets -- -D warnings

## audit: check dependencies for known vulnerabilities (needs cargo-audit)
audit:
	$(CARGO) audit

## ci: the full pre-delivery gate
ci: fmt-check clippy test build

## docker: build the container image
docker:
	$(DOCKER) build -t $(APP_NAME):latest .

## docker-run: run the image, pass arguments with ARGS="..."
docker-run:
	$(DOCKER) run --rm $(APP_NAME):latest $(ARGS)

## clean: remove build artifacts
clean:
	$(CARGO) clean

## help: list the available targets
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed -e 's/## //' | awk -F': ' '{printf "  %-14s %s\n", $$1, $$2}'
