use crate::error::*;
use cesride_core::{Diger, Matter};
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = Diger)]
pub struct DigerWrapper(pub(crate) Diger);

#[wasm_bindgen(js_class = Diger)]
impl DigerWrapper {
    #[wasm_bindgen(constructor)]
    pub fn new_with_ser(ser: &[u8], code: Option<String>) -> Result<DigerWrapper, JsValue> {
        let diger = Diger::new_with_ser(ser, code.as_deref()).as_js()?;
        Ok(DigerWrapper(diger))
    }

    #[wasm_bindgen(constructor)]
    pub fn new_with_raw(raw: &[u8], code: Option<String>) -> Result<DigerWrapper, JsValue> {
        let diger = Diger::new_with_raw(raw, code.as_deref()).as_js()?;
        Ok(DigerWrapper(diger))
    }

    #[wasm_bindgen(constructor)]
    pub fn new_with_qb64(qb64: &str) -> Result<DigerWrapper, JsValue> {
        let diger = Diger::new_with_qb64(qb64).as_js()?;
        Ok(DigerWrapper(diger))
    }

    #[wasm_bindgen(constructor)]
    pub fn new_with_qb64b(qb64b: &[u8]) -> Result<DigerWrapper, JsValue> {
        let diger = Diger::new_with_qb64b(qb64b).as_js()?;
        Ok(DigerWrapper(diger))
    }

    #[wasm_bindgen(constructor)]
    pub fn new_with_qb2(qb2: &[u8]) -> Result<DigerWrapper, JsValue> {
        let diger = Diger::new_with_qb2(qb2).as_js()?;
        Ok(DigerWrapper(diger))
    }

    pub fn verify(&self, ser: &[u8]) -> Result<bool, JsValue> {
        self.0.verify(ser).as_js().map_err(JsValue::from)
    }

    pub fn compare_dig(&self, ser: &[u8], dig: &[u8]) -> Result<bool, JsValue> {
        self.0.compare(ser, Some(dig), None).as_js().map_err(JsValue::from)
    }

    pub fn compare_diger(&self, ser: &[u8], diger: &DigerWrapper) -> Result<bool, JsValue> {
        self.0.compare(ser, None, Some(&diger.0)).as_js().map_err(JsValue::from)
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
        self.0.qb64().as_js().map_err(JsValue::from)
    }

    pub fn qb64b(&self) -> Result<Vec<u8>, JsValue> {
        self.0.qb64b().as_js().map_err(JsValue::from)
    }

    pub fn qb2(&self) -> Result<Vec<u8>, JsValue> {
        self.0.qb2().as_js().map_err(JsValue::from)
    }
}
