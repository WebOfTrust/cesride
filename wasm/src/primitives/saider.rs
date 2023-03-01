use crate::error::*;
use cesride_core::{Matter, Saider};
use js_sys::Array;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = Saider)]
pub struct SaiderWrapper(pub(crate) Saider);

#[wasm_bindgen(js_class = Saider)]
impl SaiderWrapper {
    // TODO: Value for sad, string array for ignore
    #[wasm_bindgen(constructor)]
    pub fn new(
        _sad: Option<String>,
        label: Option<String>,
        kind: Option<String>,
        _ignore: Option<Array>,
        code: Option<String>,
        raw: Option<Vec<u8>>,
        qb64b: Option<Vec<u8>>,
        qb64: Option<String>,
        qb2: Option<Vec<u8>>,
    ) -> Result<SaiderWrapper, JsValue> {
        let saider = Saider::new(
            None, //sad.as_deref(),
            label.as_deref(),
            kind.as_deref(),
            None, //ignore.as_deref(),
            code.as_deref(),
            raw.as_deref(),
            qb64b.as_deref(),
            qb64.as_deref(),
            qb2.as_deref(),
        )
        .as_js()?;
        Ok(SaiderWrapper(saider))
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
