use crate::error::JsResult;
use crate::util::U128Wrapper;
use cesride_core::{Matter, Seqner};
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = Seqner)]
pub struct SeqnerWrapper(pub(crate) Seqner);

#[wasm_bindgen(js_class = Seqner)]
impl SeqnerWrapper {
    #[wasm_bindgen(constructor)]
    pub fn new_with_sn(sn: U128Wrapper) -> Result<SeqnerWrapper, JsValue> {
        Ok(SeqnerWrapper(Seqner::new_with_sn(sn.into()).as_js()?))
    }

    #[wasm_bindgen(constructor)]
    pub fn new_with_snh(snh: &str) -> Result<SeqnerWrapper, JsValue> {
        Ok(SeqnerWrapper(Seqner::new_with_snh(snh).as_js()?))
    }

    #[wasm_bindgen(constructor)]
    pub fn new_with_raw(raw: &[u8], code: Option<String>) -> Result<SeqnerWrapper, JsValue> {
        Ok(SeqnerWrapper(Seqner::new_with_raw(raw, code.as_deref()).as_js()?))
    }

    #[wasm_bindgen(constructor)]
    pub fn new_with_qb64(qb64: &str) -> Result<SeqnerWrapper, JsValue> {
        Ok(SeqnerWrapper(Seqner::new_with_qb64(qb64).as_js()?))
    }

    #[wasm_bindgen(constructor)]
    pub fn new_with_qb64b(qb64b: &[u8]) -> Result<SeqnerWrapper, JsValue> {
        Ok(SeqnerWrapper(Seqner::new_with_qb64b(qb64b).as_js()?))
    }

    #[wasm_bindgen(constructor)]
    pub fn new_with_qb2(qb2: &[u8]) -> Result<SeqnerWrapper, JsValue> {
        Ok(SeqnerWrapper(Seqner::new_with_qb2(qb2).as_js()?))
    }

    pub fn sn(&self) -> Result<U128Wrapper, JsValue> {
        Ok(self.0.sn().as_js()?.into())
    }

    pub fn snh(&self) -> Result<String, JsValue> {
        Ok(self.0.snh().as_js()?)
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
