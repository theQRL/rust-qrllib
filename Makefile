# rust-qrllib developer tasks.
#
# Coverage mirrors go-qrllib: lines that are genuinely untestable carry a
# `//coverage:ignore reason=...` directive and are stripped from the lcov report
# (via jplomas/ignore-cov) before it is reported/gated, so coverage measures
# 100% of *testable* code. CI runs the pinned GitHub Action; locally install:
#   cargo install --git https://github.com/jplomas/ignore-cov --rev b866fc4861b843343c7c03f326faa56dbc0be585
#
# The in-crate ML-KEM ACVP tests are vector-gated: export MLKEM_ACVP_VECTORS_DIR
# (see .github/workflows/acvp.yml for the sparse clone) before `make coverage`,
# or the acvp:: module reports as uncovered.
.PHONY: test coverage coverage-html lint

test:
	cargo test --workspace --locked

coverage:
	cargo llvm-cov --locked --package qrllib --lcov --output-path lcov.info
	@ignore-cov --file lcov.info --require-reason || { echo ">>> install ignore-cov: cargo install --git https://github.com/jplomas/ignore-cov --rev b866fc4861b843343c7c03f326faa56dbc0be585"; exit 1; }
	@u=$$(awk -F, '/^DA:/&&$$2==0' lcov.info | wc -l | tr -d ' '); \
	[ "$$u" -eq 0 ] && echo "✓ testable coverage: 100%" || echo "✗ $$u uncovered testable line(s) — run: make coverage-html"

coverage-html:
	cargo llvm-cov --locked --package qrllib --html
	@echo "HTML report: target/llvm-cov/html/index.html"

lint:
	cargo clippy --workspace --all-targets --locked -- -D warnings
	cargo fmt --all --check
