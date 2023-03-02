use crate::error::JsResult;
use crate::util::U128Wrapper;
use cesride_core::{Matter, Seqner};
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = Seqner)]
pub struct SeqnerWrapper(pub(crate) Seqner);

#[wasm_bindgen(js_class = Seqner)]
impl SeqnerWrapper {
    #[wasm_bindgen(constructor)]
    pub fn new_with_raw(
        sn: Option<U128Wrapper>,
        snh: Option<String>,
        code: Option<String>,
        raw: Option<Vec<u8>>,
        qb64b: Option<Vec<u8>>,
        qb64: Option<String>,
        qb2: Option<Vec<u8>>,
    ) -> Result<SeqnerWrapper, JsValue> {
        let seqner = Seqner::new(
            sn.map(Into::into),
            snh.as_deref(),
            code.as_deref(),
            raw.as_deref(),
            qb64b.as_deref(),
            qb64.as_deref(),
            qb2.as_deref(),
        )
        .as_js()?;
        Ok(SeqnerWrapper(seqner))
    }

    pub fn sn(&self) -> Result<U128Wrapper, JsValue> {
        let sn = self.0.sn().as_js()?;
        Ok(sn.into())
    }

    pub fn snh(&self) -> Result<String, JsValue> {
        self.0.snh().as_js().map_err(JsValue::from)
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
