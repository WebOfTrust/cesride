use crate::error::*;
use cesride_core::{Dater, Matter};
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = Dater)]
pub struct DaterWrapper(pub(crate) Dater);

#[wasm_bindgen(js_class = Dater)]
impl DaterWrapper {
    #[wasm_bindgen(constructor)]
    pub fn new(
        dts: Option<String>,
        code: Option<String>,
        raw: Option<Vec<u8>>,
        qb64b: Option<Vec<u8>>,
        qb64: Option<String>,
        qb2: Option<Vec<u8>>,
    ) -> Result<DaterWrapper, JsValue> {
        let dater = Dater::new(
            dts.as_deref(),
            code.as_deref(),
            raw.as_deref(),
            qb64b.as_deref(),
            qb64.as_deref(),
            qb2.as_deref(),
        )
        .as_js()?;
        Ok(DaterWrapper(dater))
    }

    pub fn dts(&self) -> Result<String, JsValue> {
        self.0.dts().as_js().map_err(JsValue::from)
    }

    pub fn dtsb(&self) -> Result<Vec<u8>, JsValue> {
        self.0.dtsb().as_js().map_err(JsValue::from)
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
