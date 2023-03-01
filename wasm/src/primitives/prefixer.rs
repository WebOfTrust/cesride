use crate::error::*;
use cesride_core::{Matter, Prefixer};
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = Prefixer)]
pub struct PrefixerWrapper(pub(crate) Prefixer);

#[wasm_bindgen(js_class = Prefixer)]
impl PrefixerWrapper {
    // TODO:
    // #[wasm_bindgen(constructor)]
    // pub fn new_with_ked(ked: &Value, allows: Option<&[&str]>, code: Option<String>) -> Result<PrefixerWrapper, JsValue> {
    //     Ok(PrefixerWrapper(Prefixer::new_with_ked(ked, allows, code.as_deref()).as_js()?))
    // }

    #[wasm_bindgen(constructor)]
    pub fn new_with_raw(raw: &[u8], code: Option<String>) -> Result<PrefixerWrapper, JsValue> {
        Ok(PrefixerWrapper(Prefixer::new_with_raw(raw, code.as_deref()).as_js()?))
    }

    #[wasm_bindgen(constructor)]
    pub fn new_with_qb64(qb64: &str) -> Result<PrefixerWrapper, JsValue> {
        Ok(PrefixerWrapper(Prefixer::new_with_qb64(qb64).as_js()?))
    }

    #[wasm_bindgen(constructor)]
    pub fn new_with_qb64b(qb64b: &[u8]) -> Result<PrefixerWrapper, JsValue> {
        Ok(PrefixerWrapper(Prefixer::new_with_qb64b(qb64b).as_js()?))
    }

    #[wasm_bindgen(constructor)]
    pub fn new_with_qb2(qb2: &[u8]) -> Result<PrefixerWrapper, JsValue> {
        Ok(PrefixerWrapper(Prefixer::new_with_qb2(qb2).as_js()?))
    }

    // TODO:
    // pub fn verify(&self, ked: &Value, prefixed: Option<bool>) -> Result<bool, JsValue> {
    //     Ok(self.0.verify(ked, prefixed).as_js()?)
    // }

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
