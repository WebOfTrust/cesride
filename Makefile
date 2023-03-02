clean:
	cargo clean

fix:
	cargo fix
	cargo fmt

preflight:
	cargo audit
	cargo fmt --check
	cargo clippy -- -D warnings
	cargo build --release
	cargo test --release
	cargo tarpaulin
