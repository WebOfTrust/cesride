use crate::error::*;
use cesride_core::{Matter, Signer};
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = Signer)]
pub struct SignerWrapper(Signer);

#[wasm_bindgen(js_class = Signer)]
impl SignerWrapper {
    #[wasm_bindgen(constructor)]
    pub fn signer_new_with_raw(
        raw: &[u8],
        transferable: Option<bool>,
        code: Option<String>,
    ) -> Result<SignerWrapper, JsValue> {
        Ok(SignerWrapper(Signer::new_with_raw(raw, transferable, code.as_deref()).as_js()?))
    }

    #[wasm_bindgen(constructor)]
    pub fn signer_new_with_qb64(qb64: &str) -> Result<SignerWrapper, JsValue> {
        Ok(SignerWrapper(Signer::new_with_qb64(qb64).as_js()?))
    }

    #[wasm_bindgen(constructor)]
    pub fn signer_new_with_qb64b(qb64b: &[u8]) -> Result<SignerWrapper, JsValue> {
        Ok(SignerWrapper(Signer::new_with_qb64b(qb64b).as_js()?))
    }

    #[wasm_bindgen(constructor)]
    pub fn signer_new_with_qb2(qb2: &[u8]) -> Result<SignerWrapper, JsValue> {
        Ok(SignerWrapper(Signer::new_with_qb2(qb2).as_js()?))
    }

    pub fn signer_code(&self) -> String {
        self.0.code()
    }

    pub fn signer_size(&self) -> u32 {
        self.0.size()
    }

    pub fn signer_raw(&self) -> Vec<u8> {
        self.0.raw()
    }

    pub fn signer_qb64(&self) -> Result<String, JsValue> {
        Ok(self.0.qb64().as_js()?)
    }

    pub fn signer_qb64b(&self) -> Result<Vec<u8>, JsValue> {
        Ok(self.0.qb64b().as_js()?)
    }

    pub fn signer_qb2(&self) -> Result<Vec<u8>, JsValue> {
        Ok(self.0.qb2().as_js()?)
    }
}
