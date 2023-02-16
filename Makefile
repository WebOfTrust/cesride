uniffi-build:
	@cd uniffi && cargo build --release

swift: uniffi-build
	@cd uniffi && cargo run --release --bin cesride-bindgen generate src/cesride.udl --out-dir generated --language $@

kotlin: uniffi-build
	@cd uniffi && cargo run --release --bin cesride-bindgen generate src/cesride.udl --out-dir generated --language $@

ruby: uniffi-build
	@cd uniffi && cargo run --release --bin cesride-bindgen generate src/cesride.udl --out-dir generated --language $@

python: uniffi-build
	@cd uniffi && cargo run --release --bin cesride-bindgen generate src/cesride.udl --out-dir generated --language $@

bindings: swift kotlin ruby python

python-shell: python
	@cp uniffi/target/release/libcesride_uniffi.dylib uniffi/generated/libuniffi_cesride.dylib
	@cd uniffi/generated/ && python3

rust:
	@cargo build --release

libs: rust python

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
