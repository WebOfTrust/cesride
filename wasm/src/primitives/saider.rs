use crate::error::*;
use cesride_core::{Matter, Saider};
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = Saider)]
pub struct SaiderWrapper(pub(crate) Saider);

#[wasm_bindgen(js_class = Saider)]
impl SaiderWrapper {
    // TODO: new_with_sad

    #[wasm_bindgen(constructor)]
    pub fn new_with_raw(raw: &[u8], code: Option<String>) -> Result<SaiderWrapper, JsValue> {
        Ok(SaiderWrapper(Saider::new_with_raw(raw, code.as_deref()).as_js()?))
    }

    #[wasm_bindgen(constructor)]
    pub fn new_with_qb64(qb64: &str) -> Result<SaiderWrapper, JsValue> {
        Ok(SaiderWrapper(Saider::new_with_qb64(qb64).as_js()?))
    }

    #[wasm_bindgen(constructor)]
    pub fn new_with_qb64b(qb64b: &[u8]) -> Result<SaiderWrapper, JsValue> {
        Ok(SaiderWrapper(Saider::new_with_qb64b(qb64b).as_js()?))
    }

    #[wasm_bindgen(constructor)]
    pub fn new_with_qb2(qb2: &[u8]) -> Result<SaiderWrapper, JsValue> {
        Ok(SaiderWrapper(Saider::new_with_qb2(qb2).as_js()?))
    }

    pub fn code(&self) -> String {
        self.0.code()
    }

    pub fn size(&self) -> u32 {
        self.0.size()
    }

    pub fn raw(&self) -> Vec<u8> {
        self.0.raw()
    }

    pub fn qb64(&self) -> Result<String, JsValue> {
        Ok(self.0.qb64().as_js()?)
    }

    pub fn qb64b(&self) -> Result<Vec<u8>, JsValue> {
        Ok(self.0.qb64b().as_js()?)
    }

    pub fn qb2(&self) -> Result<Vec<u8>, JsValue> {
        Ok(self.0.qb2().as_js()?)
    }
}