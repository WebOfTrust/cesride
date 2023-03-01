fn main() {
    #[cfg(feature = "ffi")]
    uniffi::generate_scaffolding("./src/cesride.udl").unwrap();
}
