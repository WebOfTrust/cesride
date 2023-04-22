clean:
	cargo clean

fix:
	cargo fix
	cargo fmt

preflight:
	cargo audit
	cargo fmt --check
	cargo outdated -R --exit-code 1
	cargo clippy -- -D warnings
	cargo build --release
	cargo test --release
	cargo tarpaulin
