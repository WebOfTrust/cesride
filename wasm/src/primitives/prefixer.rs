use crate::error::*;
use cesride_core::{Matter, Prefixer};
use js_sys::Array;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = Prefixer)]
pub struct PrefixerWrapper(pub(crate) Prefixer);

#[wasm_bindgen(js_class = Prefixer)]
impl PrefixerWrapper {
    // TODO: Value for ked and array of strings for allows
    #[wasm_bindgen(constructor)]
    pub fn new(
        _ked: Option<String>,
        _allows: Option<Array>,
        code: Option<String>,
        raw: Option<Vec<u8>>,
        qb64b: Option<Vec<u8>>,
        qb64: Option<String>,
        qb2: Option<Vec<u8>>,
    ) -> Result<PrefixerWrapper, JsValue> {
        let prefixer = Prefixer::new(
            None, //ked.as_deref(),
            None, //allows.as_deref(),
            code.as_deref(),
            raw.as_deref(),
            qb64b.as_deref(),
            qb64.as_deref(),
            qb2.as_deref(),
        )
        .as_js()?;
        Ok(PrefixerWrapper(prefixer))
    }

    // TODO:
    // pub fn verify(&self, ked: &Value, prefixed: Option<bool>) -> Result<bool, JsValue> {
    //     self.0.verify(ked, prefixed).as_js().map_err(JsValue::from)
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
        self.0.qb64().as_js().map_err(JsValue::from)
    }

    pub fn qb64b(&self) -> Result<Vec<u8>, JsValue> {
        self.0.qb64b().as_js().map_err(JsValue::from)
    }

    pub fn qb2(&self) -> Result<Vec<u8>, JsValue> {
        self.0.qb2().as_js().map_err(JsValue::from)
    }
}
