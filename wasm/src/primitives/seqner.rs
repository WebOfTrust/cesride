use std::ops::Deref;

use crate::util::U128Wrapper;
use crate::{error::*, Wrap};
use cesride_core::{Matter, Seqner};
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = Seqner)]
pub struct SeqnerWrapper(pub(crate) Seqner);

#[wasm_bindgen(js_class = Seqner)]
impl SeqnerWrapper {
    #[wasm_bindgen(constructor)]
    pub fn new(
        sn: Option<U128Wrapper>,
        snh: Option<String>,
        code: Option<String>,
        raw: Option<Vec<u8>>,
        qb64b: Option<Vec<u8>>,
        qb64: Option<String>,
        qb2: Option<Vec<u8>>,
    ) -> Result<SeqnerWrapper> {
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

    pub fn new_with_sn(sn: U128Wrapper) -> Result<SeqnerWrapper> {
        let seqner = Seqner::new_with_sn(sn.into()).as_js()?;
        Ok(SeqnerWrapper(seqner))
    }

    pub fn new_with_snh(snh: &str) -> Result<SeqnerWrapper> {
        let seqner = Seqner::new_with_snh(snh).as_js()?;
        Ok(SeqnerWrapper(seqner))
    }

    pub fn new_with_raw(raw: &[u8], code: Option<String>) -> Result<SeqnerWrapper> {
        let seqner = Seqner::new_with_raw(raw, code.as_deref()).as_js()?;
        Ok(SeqnerWrapper(seqner))
    }

    pub fn new_with_qb64b(qb64b: &[u8]) -> Result<SeqnerWrapper> {
        let seqner = Seqner::new_with_qb64b(qb64b).as_js()?;
        Ok(SeqnerWrapper(seqner))
    }

    pub fn new_with_qb64(qb64: &str) -> Result<SeqnerWrapper> {
        let seqner = Seqner::new_with_qb64(qb64).as_js()?;
        Ok(SeqnerWrapper(seqner))
    }

    pub fn new_with_qb2(qb2: &[u8]) -> Result<SeqnerWrapper> {
        let seqner = Seqner::new_with_qb2(qb2).as_js()?;
        Ok(SeqnerWrapper(seqner))
    }

    pub fn sn(&self) -> Result<U128Wrapper> {
        let sn = self.0.sn().as_js()?;
        Ok(sn.into())
    }

    pub fn snh(&self) -> Result<String> {
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

impl Deref for SeqnerWrapper {
    type Target = Seqner;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Wrap<Seqner> for SeqnerWrapper {
    type Wrapper = SeqnerWrapper;

    fn wrap(seqner: &Seqner) -> Self::Wrapper {
        SeqnerWrapper(seqner.clone())
    }
}
