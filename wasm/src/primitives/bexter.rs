use std::ops::Deref;

use crate::{error::*, Wrap};
use cesride_core::{Bext, Bexter, Matter};
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = Bexter)]
pub struct BexterWrapper(pub(crate) Bexter);

#[wasm_bindgen(js_class = Bexter)]
impl BexterWrapper {
    #[wasm_bindgen(constructor)]
    pub fn new(
        bext: Option<String>,
        code: Option<String>,
        raw: Option<Vec<u8>>,
        qb64b: Option<Vec<u8>>,
        qb64: Option<String>,
        qb2: Option<Vec<u8>>,
    ) -> Result<BexterWrapper> {
        let bexter = Bexter::new(
            bext.as_deref(),
            code.as_deref(),
            raw.as_deref(),
            qb64b.as_deref(),
            qb64.as_deref(),
            qb2.as_deref(),
        )
        .as_js()?;
        Ok(BexterWrapper(bexter))
    }

    pub fn new_with_bext(bext: &str) -> Result<BexterWrapper> {
        let bexter = Bexter::new_with_bext(bext).as_js()?;
        Ok(BexterWrapper(bexter))
    }

    pub fn new_with_raw(raw: &[u8], code: Option<String>) -> Result<BexterWrapper> {
        let bexter = Bexter::new_with_raw(raw, code.as_deref()).as_js()?;
        Ok(BexterWrapper(bexter))
    }

    pub fn new_with_qb64b(qb64b: &[u8]) -> Result<BexterWrapper> {
        let bexter = Bexter::new_with_qb64b(qb64b).as_js()?;
        Ok(BexterWrapper(bexter))
    }

    pub fn new_with_qb64(qb64: &str) -> Result<BexterWrapper> {
        let bexter = Bexter::new_with_qb64(qb64).as_js()?;
        Ok(BexterWrapper(bexter))
    }

    pub fn new_with_qb2(qb2: &[u8]) -> Result<BexterWrapper> {
        let bexter = Bexter::new_with_qb2(qb2).as_js()?;
        Ok(BexterWrapper(bexter))
    }

    pub fn bext(&self) -> Result<String> {
        self.0.bext().as_js().map_err(JsValue::from)
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

impl Deref for BexterWrapper {
    type Target = Bexter;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Wrap<Bexter> for BexterWrapper {
    type Wrapper = BexterWrapper;

    fn wrap(bexter: &Bexter) -> Self::Wrapper {
        BexterWrapper(bexter.clone())
    }
}
