use std::ops::Deref;

use crate::{error::*, Wrap};
use cesride_core::{Diger, Matter};
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = Diger)]
#[derive(Clone)]
pub struct DigerWrapper(pub(crate) Diger);

#[wasm_bindgen(js_class = Diger)]
impl DigerWrapper {
    #[wasm_bindgen(constructor)]
    pub fn new(
        ser: Option<Vec<u8>>,
        code: Option<String>,
        raw: Option<Vec<u8>>,
        qb64b: Option<Vec<u8>>,
        qb64: Option<String>,
        qb2: Option<Vec<u8>>,
    ) -> Result<DigerWrapper> {
        let diger = Diger::new(
            ser.as_deref(),
            code.as_deref(),
            raw.as_deref(),
            qb64b.as_deref(),
            qb64.as_deref(),
            qb2.as_deref(),
        )
        .as_js()?;
        Ok(DigerWrapper(diger))
    }

    pub fn new_with_ser(ser: &[u8], code: Option<String>) -> Result<DigerWrapper> {
        let diger = Diger::new_with_ser(ser, code.as_deref()).as_js()?;
        Ok(DigerWrapper(diger))
    }

    pub fn new_with_raw(raw: &[u8], code: Option<String>) -> Result<DigerWrapper> {
        let diger = Diger::new_with_raw(raw, code.as_deref()).as_js()?;
        Ok(DigerWrapper(diger))
    }

    pub fn new_with_qb64b(qb64b: &[u8]) -> Result<DigerWrapper> {
        let diger = Diger::new_with_qb64b(qb64b).as_js()?;
        Ok(DigerWrapper(diger))
    }

    pub fn new_with_qb64(qb64: &str) -> Result<DigerWrapper> {
        let diger = Diger::new_with_qb64(qb64).as_js()?;
        Ok(DigerWrapper(diger))
    }

    pub fn new_with_qb2(qb2: &[u8]) -> Result<DigerWrapper> {
        let diger = Diger::new_with_qb2(qb2).as_js()?;
        Ok(DigerWrapper(diger))
    }

    pub fn verify(&self, ser: &[u8]) -> Result<bool> {
        self.0.verify(ser).as_js().map_err(JsValue::from)
    }

    pub fn compare_dig(&self, ser: &[u8], dig: &[u8]) -> Result<bool> {
        self.0.compare(ser, Some(dig), None).as_js().map_err(JsValue::from)
    }

    pub fn compare_diger(&self, ser: &[u8], diger: &DigerWrapper) -> Result<bool> {
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

    pub fn qb64(&self) -> Result<String> {
        self.0.qb64().as_js().map_err(JsValue::from)
    }

    pub fn qb64b(&self) -> Result<Vec<u8>> {
        self.0.qb64b().as_js().map_err(JsValue::from)
    }

    pub fn qb2(&self) -> Result<Vec<u8>> {
        self.0.qb2().as_js().map_err(JsValue::from)
    }
}

impl Deref for DigerWrapper {
    type Target = Diger;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Wrap<Diger> for DigerWrapper {
    type Wrapper = DigerWrapper;

    fn wrap(diger: &Diger) -> Self::Wrapper {
        DigerWrapper(diger.clone())
    }
}
