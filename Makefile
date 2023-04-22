clean:
	cargo clean

fix:
	cargo fix
	cargo fmt

preflight:
	cargo fmt --check
	cargo outdated -R --exit-code 1
	cargo audit
	cargo check
	cargo clippy --all-targets -- -D warnings
	cargo build --release
	cargo test --release
	cargo tarpaulin
