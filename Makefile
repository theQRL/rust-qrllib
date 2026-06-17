# rust-qrllib developer tasks.
#
# Coverage mirrors go-qrllib: lines that are genuinely untestable carry a
# `//coverage:ignore reason=...` directive and are stripped from the lcov report
# (via jplomas/ignore-cov) before it is reported/gated, so coverage measures
# 100% of *testable* code. CI runs the pinned GitHub Action; locally install:
#   cargo install --git https://github.com/jplomas/ignore-cov --rev b866fc4861b843343c7c03f326faa56dbc0be585
.PHONY: test coverage coverage-html lint

test:
	cargo test --workspace --locked

coverage:
	cargo llvm-cov --locked --package qrllib --lcov --output-path lcov.info
	@ignore-cov --file lcov.info --require-reason || { echo ">>> install ignore-cov: cargo install --git https://github.com/jplomas/ignore-cov --rev b866fc4861b843343c7c03f326faa56dbc0be585"; exit 1; }
	@python3 -c "import sys; d=open('lcov.info').read().splitlines(); \
	lf=sum(int(l[3:]) for l in d if l.startswith('LF:')); \
	lh=sum(int(l[3:]) for l in d if l.startswith('LH:')); \
	brf=sum(int(l[4:]) for l in d if l.startswith('BRF:')); \
	brh=sum(int(l[4:]) for l in d if l.startswith('BRH:')); \
	print(f'testable lines:    {lh}/{lf} = {100*lh/lf:.2f}%'); \
	print(f'testable branches: {brh}/{brf} = {100*brh/brf:.2f}%' if brf else 'testable branches: n/a')"

coverage-html:
	cargo llvm-cov --locked --package qrllib --html
	@echo "HTML report: target/llvm-cov/html/index.html"

lint:
	cargo clippy --workspace --all-targets --locked -- -D warnings
	cargo fmt --all --check
