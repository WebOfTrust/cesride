use crate::{error::JsResult, VerferWrapper};
use cesride_core::{Matter, Cigar};
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = Cigar)]
pub struct CigarWrapper(pub(crate) Cigar);

#[wasm_bindgen(js_class = Cigar)]
impl CigarWrapper {
    #[wasm_bindgen(constructor)]
    pub fn new_with_raw(
        raw: &[u8],
        verfer: Option<VerferWrapper>,
        code: Option<String>,
    ) -> Result<CigarWrapper, JsValue> {
        Ok(CigarWrapper(
            Cigar::new_with_raw(raw, verfer.as_deref(), code.as_deref()).as_js()?,
        ))
    }

    #[wasm_bindgen(constructor)]
    pub fn new_with_qb64(
        qb64: &str,
        verfer: Option<VerferWrapper>,
    ) -> Result<CigarWrapper, JsValue> {
        Ok(CigarWrapper(Cigar::new_with_qb64(qb64, verfer.as_deref()).as_js()?))
    }

    #[wasm_bindgen(constructor)]
    pub fn new_with_qb64b(
        qb64b: &[u8],
        verfer: Option<VerferWrapper>,
    ) -> Result<CigarWrapper, JsValue> {
        Ok(CigarWrapper(Cigar::new_with_qb64b(qb64b, verfer.as_deref()).as_js()?))
    }

    #[wasm_bindgen(constructor)]
    pub fn new_with_qb2(
        qb2: &[u8],
        verfer: Option<VerferWrapper>,
    ) -> Result<CigarWrapper, JsValue> {
        Ok(CigarWrapper(Cigar::new_with_qb2(qb2, verfer.as_deref()).as_js()?))
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

    pub fn qb64(&self) -> Result<String, JsValue> {
        Ok(self.0.qb64().as_js()?)
    }

    pub fn qb64b(&self) -> Result<Vec<u8>, JsValue> {
        Ok(self.0.qb64b().as_js()?)
    }

    pub fn qb2(&self) -> Result<Vec<u8>, JsValue> {
        Ok(self.0.qb2().as_js()?)
    }
}
