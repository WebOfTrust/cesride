setup:
	cargo install cargo-tarpaulin cargo-outdated cargo-audit wasm-pack

clean:
	cargo clean
	rm wasm/pkg/*

fix:
	cargo fix
	cargo fmt

clippy:
	cargo clippy --all-targets -- -D warnings

wasm: .
	cd wasm && wasm-pack build && wasm-pack build --target=nodejs # sanity builds
	cd wasm && wasm-pack test --node # Node tests (only ones that signify-ts uses right now)

base-cesride-crate: 
	cargo generate-lockfile
	cargo fmt --check
	cargo outdated -R --exit-code 1
	cargo audit
	cargo check
	cargo clippy -- -D warnings
	cargo build --release
	cargo test --release
	cargo tarpaulin

preflight: base-cesride-crate wasm
	printf "Preflight check complete"
