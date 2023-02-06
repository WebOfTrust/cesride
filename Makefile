DEV_DEPENDENCIES_LINE = $(shell cat Cargo.toml | grep -n "\[dev-dependencies\]" | cut -d : -f 1)
DELIMITING_LINE = $(shell echo $$(( $(DEV_DEPENDENCIES_LINE) - 2 )))
TOTAL_LINES = $(shell cat Cargo.toml | wc -l)
TAIL_LINES = $(shell echo $$(( $(TOTAL_LINES) - $(DELIMITING_LINE) )))

python:
	@head -n $(DELIMITING_LINE) Cargo.toml > cargo/$@/Cargo.toml
	@echo "pyo3 = { version = \"~0.18\", features = [\"abi3\", \"extension-module\"] }" >> cargo/$@/Cargo.toml
	@tail -n $(TAIL_LINES) Cargo.toml >> cargo/$@/Cargo.toml
	@echo >> cargo/$@/Cargo.toml
	@cat cargo/$@/Cargo.toml.tail >> cargo/$@/Cargo.toml
	@cd cargo/$@ && cargo build --release --target-dir ../../target/$@
	@mv target/$@/release/libcesride.dylib target/$@/release/cesride.so

python-shell:
	@cd target/python/release/ && python3

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
