use std::ops::Deref;

use crate::{error::*, ValueWrapper, Wrap};
use cesride_core::{data::Value, Matter, Prefixer};
use js_sys::Array;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = Prefixer)]
pub struct PrefixerWrapper(pub(crate) Prefixer);

#[wasm_bindgen(js_class = Prefixer)]
impl PrefixerWrapper {
    #[wasm_bindgen(constructor)]
    pub fn new(
        ked: Option<ValueWrapper>,
        allows: Option<Array>,
        code: Option<String>,
        raw: Option<Vec<u8>>,
        qb64b: Option<Vec<u8>>,
        qb64: Option<String>,
        qb2: Option<Vec<u8>>,
    ) -> Result<PrefixerWrapper> {
        let allows = allows
            .map(|a| a.iter().map(|v| v.as_string().unwrap_or_default()).collect::<Vec<String>>());
        let allows = allows.as_deref().map(|a| a.iter().map(String::as_str).collect::<Vec<&str>>());
        let allows = allows.as_deref();
        let prefixer = Prefixer::new(
            ked.map(Value::from).as_ref(),
            allows,
            code.as_deref(),
            raw.as_deref(),
            qb64b.as_deref(),
            qb64.as_deref(),
            qb2.as_deref(),
        )
        .as_js()?;
        Ok(PrefixerWrapper(prefixer))
    }

    pub fn new_with_ked(
        ked: ValueWrapper,
        allows: Option<Array>,
        code: Option<String>,
    ) -> Result<PrefixerWrapper> {
        let allows = allows
            .map(|a| a.iter().map(|v| v.as_string().unwrap_or_default()).collect::<Vec<String>>());
        let allows = allows.as_deref().map(|a| a.iter().map(String::as_str).collect::<Vec<&str>>());
        let allows = allows.as_deref();
        let prefixer =
            Prefixer::new_with_ked(&Value::from(ked), allows, code.as_deref()).as_js()?;
        Ok(PrefixerWrapper(prefixer))
    }

    pub fn new_with_raw(raw: &[u8], code: Option<String>) -> Result<PrefixerWrapper> {
        let prefixer = Prefixer::new_with_raw(raw, code.as_deref()).as_js()?;
        Ok(PrefixerWrapper(prefixer))
    }

    pub fn new_with_qb64b(qb64b: &[u8]) -> Result<PrefixerWrapper> {
        let prefixer = Prefixer::new_with_qb64b(qb64b).as_js()?;
        Ok(PrefixerWrapper(prefixer))
    }

    pub fn new_with_qb64(qb64: &str) -> Result<PrefixerWrapper> {
        let prefixer = Prefixer::new_with_qb64(qb64).as_js()?;
        Ok(PrefixerWrapper(prefixer))
    }

    pub fn new_with_qb2(qb2: &[u8]) -> Result<PrefixerWrapper> {
        let prefixer = Prefixer::new_with_qb2(qb2).as_js()?;
        Ok(PrefixerWrapper(prefixer))
    }

    pub fn verify(&self, ked: ValueWrapper, prefixed: Option<bool>) -> Result<bool> {
        self.0.verify(&Value::from(ked), prefixed).as_js().map_err(JsValue::from)
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

impl Deref for PrefixerWrapper {
    type Target = Prefixer;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Wrap<Prefixer> for PrefixerWrapper {
    type Wrapper = PrefixerWrapper;

    fn wrap(prefixer: &Prefixer) -> Self::Wrapper {
        PrefixerWrapper(prefixer.clone())
    }
}
