use std::ops::Deref;

use wasm_bindgen::prelude::*;

use crate::{error::*, Wrap};
use cesride_core::{Matter, Verfer};

#[wasm_bindgen(js_name = Verfer)]
#[derive(Debug, Clone, PartialEq)]
pub struct VerferWrapper(pub(crate) Verfer);

#[wasm_bindgen(js_class = Verfer)]
impl VerferWrapper {
    #[wasm_bindgen(constructor)]
    pub fn new(
        code: Option<String>,
        raw: Option<Vec<u8>>,
        qb64b: Option<Vec<u8>>,
        qb64: Option<String>,
        qb2: Option<Vec<u8>>,
    ) -> Result<VerferWrapper> {
        let verfer = Verfer::new(
            code.as_deref(),
            raw.as_deref(),
            qb64b.as_deref(),
            qb64.as_deref(),
            qb2.as_deref(),
        )
        .as_js()?;
        Ok(VerferWrapper(verfer))
    }

    pub fn verify(&self, sig: &[u8], ser: &[u8]) -> Result<bool> {
        self.0.verify(sig, ser).as_js().map_err(JsValue::from)
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

/// A default Verfer for our VerferWrapper
impl Default for VerferWrapper {
    fn default() -> Self {
        VerferWrapper{ 0: Verfer::default() }
    }
}

impl Deref for VerferWrapper {
    type Target = Verfer;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Wrap<Verfer> for VerferWrapper {
    type Wrapper = VerferWrapper;

    fn wrap(verfer: &Verfer) -> Self::Wrapper {
        VerferWrapper(verfer.clone())
    }
}
