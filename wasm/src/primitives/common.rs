use cesride_core::common::Version;
use wasm_bindgen::prelude::wasm_bindgen;

#[wasm_bindgen(js_name=Version)]
pub struct VersionWrapper(pub(crate) Version);
