use std::ops::Deref;

use crate::{error::*, VerferWrapper, Wrap};
use cesride_core::{Indexer, Siger};
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = Siger)]
pub struct SigerWrapper(pub(crate) Siger);

#[wasm_bindgen(js_class = Siger)]
impl SigerWrapper {
    #[wasm_bindgen(constructor)]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        verfer: Option<VerferWrapper>,
        index: Option<u32>,
        ondex: Option<u32>,
        code: Option<String>,
        raw: Option<Vec<u8>>,
        qb64b: Option<Vec<u8>>,
        qb64: Option<String>,
        qb2: Option<Vec<u8>>,
    ) -> Result<SigerWrapper> {
        let siger = Siger::new(
            verfer.as_deref(),
            index,
            ondex,
            code.as_deref(),
            raw.as_deref(),
            qb64b.as_deref(),
            qb64.as_deref(),
            qb2.as_deref(),
        )
        .as_js()?;
        Ok(SigerWrapper(siger))
    }

    pub fn new_with_raw(
        raw: &[u8],
        verfer: Option<VerferWrapper>,
        index: Option<u32>,
        ondex: Option<u32>,
        code: Option<String>,
    ) -> Result<SigerWrapper> {
        let siger =
            Siger::new_with_raw(raw, verfer.as_deref(), index, ondex, code.as_deref()).as_js()?;
        Ok(SigerWrapper(siger))
    }

    pub fn new_with_qb64b(qb64b: &[u8], verfer: Option<VerferWrapper>) -> Result<SigerWrapper> {
        let siger = Siger::new_with_qb64b(qb64b, verfer.as_deref()).as_js()?;
        Ok(SigerWrapper(siger))
    }

    pub fn new_with_qb64(qb64: &str, verfer: Option<VerferWrapper>) -> Result<SigerWrapper> {
        let siger = Siger::new_with_qb64(qb64, verfer.as_deref()).as_js()?;
        Ok(SigerWrapper(siger))
    }

    pub fn new_with_qb2(qb2: &[u8], verfer: Option<VerferWrapper>) -> Result<SigerWrapper> {
        let siger = Siger::new_with_qb2(qb2, verfer.as_deref()).as_js()?;
        Ok(SigerWrapper(siger))
    }

    pub fn verfer(&self) -> VerferWrapper {
        VerferWrapper(self.0.verfer())
    }

    pub fn code(&self) -> String {
        self.0.code()
    }

    pub fn raw(&self) -> Vec<u8> {
        self.0.raw()
    }

    pub fn index(&self) -> u32 {
        self.0.index()
    }

    pub fn ondex(&self) -> u32 {
        self.0.ondex()
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

impl Deref for SigerWrapper {
    type Target = Siger;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Wrap<Siger> for SigerWrapper {
    type Wrapper = SigerWrapper;

    fn wrap(siger: &Siger) -> Self::Wrapper {
        SigerWrapper(siger.clone())
    }
}
