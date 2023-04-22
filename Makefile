setup:
	cargo install cargo-tarpaulin cargo-outdated cargo-audit

clean:
	cargo clean

fix:
	cargo fix
	cargo fmt

clippy:
	cargo clippy --all-targets -- -D warnings

preflight:
	cargo fmt --check
	cargo outdated -R --exit-code 1
	cargo audit
	cargo check
	cargo clippy -- -D warnings
	cargo build --release
	cargo test --release
	cargo tarpaulin
