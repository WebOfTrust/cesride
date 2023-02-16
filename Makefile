clean:
	cargo clean

fix:
	cargo fix
	cargo fmt

preflight:
	cargo fmt --check
	cargo clippy -- -D warnings
	cargo build --release
	cargo test --release
	cargo audit
	cargo tarpaulin
