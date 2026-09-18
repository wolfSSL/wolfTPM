.PHONY: all
all:
	cargo build --locked
	cargo clippy --locked
	cargo doc --locked --no-deps

.PHONY: test
test:
	cargo test --locked --features swtpm-tests -- --test-threads=1

.PHONY: clean
clean:
	cargo clean
