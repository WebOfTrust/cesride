use std::ops::Deref;

use crate::{error::*, VerferWrapper, Wrap};
use cesride_core::{Cigar, Matter};
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = Cigar)]
pub struct CigarWrapper(pub(crate) Cigar);

#[wasm_bindgen(js_class = Cigar)]
impl CigarWrapper {
    #[wasm_bindgen(constructor)]
    pub fn new(
        verfer: Option<VerferWrapper>,
        code: Option<String>,
        raw: Option<Vec<u8>>,
        qb64b: Option<Vec<u8>>,
        qb64: Option<String>,
        qb2: Option<Vec<u8>>,
    ) -> Result<CigarWrapper> {
        let cigar = Cigar::new(
            verfer.as_deref(),
            code.as_deref(),
            raw.as_deref(),
            qb64b.as_deref(),
            qb64.as_deref(),
            qb2.as_deref(),
        )
        .as_js()?;
        Ok(CigarWrapper(cigar))
    }

    pub fn new_with_raw(
        raw: &[u8],
        verfer: Option<VerferWrapper>,
        code: Option<String>,
    ) -> Result<CigarWrapper> {
        let cigar = Cigar::new_with_raw(raw, verfer.as_deref(), code.as_deref()).as_js()?;
        Ok(CigarWrapper(cigar))
    }

    pub fn new_with_qb64b(qb64b: &[u8], verfer: Option<VerferWrapper>) -> Result<CigarWrapper> {
        let cigar = Cigar::new_with_qb64b(qb64b, verfer.as_deref()).as_js()?;
        Ok(CigarWrapper(cigar))
    }

    pub fn new_with_qb64(qb64: &str, verfer: Option<VerferWrapper>) -> Result<CigarWrapper> {
        let cigar = Cigar::new_with_qb64(qb64, verfer.as_deref()).as_js()?;
        Ok(CigarWrapper(cigar))
    }

    pub fn new_with_qb2(qb2: &[u8], verfer: Option<VerferWrapper>) -> Result<CigarWrapper> {
        let cigar = Cigar::new_with_qb2(qb2, verfer.as_deref()).as_js()?;
        Ok(CigarWrapper(cigar))
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

    pub fn size(&self) -> u32 {
        self.0.size()
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

impl Deref for CigarWrapper {
    type Target = Cigar;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Wrap<Cigar> for CigarWrapper {
    type Wrapper = CigarWrapper;

    fn wrap(cigar: &Cigar) -> Self::Wrapper {
        CigarWrapper(cigar.clone())
    }
}
