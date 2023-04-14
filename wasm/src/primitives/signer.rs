use std::ops::Deref;

use crate::{error::*, CigarWrapper, SigerWrapper, VerferWrapper, Wrap};
use cesride_core::{Matter, Signer};
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = Signer)]
#[derive(Clone)]
pub struct SignerWrapper(pub(crate) Signer);

#[wasm_bindgen(js_class = Signer)]
impl SignerWrapper {
    #[wasm_bindgen(constructor)]
    pub fn new(
        transferable: Option<bool>,
        code: Option<String>,
        raw: Option<Vec<u8>>,
        qb64b: Option<Vec<u8>>,
        qb64: Option<String>,
        qb2: Option<Vec<u8>>,
    ) -> Result<SignerWrapper> {
        let signer = Signer::new(
            transferable,
            code.as_deref(),
            raw.as_deref(),
            qb64b.as_deref(),
            qb64.as_deref(),
            qb2.as_deref(),
        )
        .as_js()?;
        Ok(SignerWrapper(signer))
    }

    pub fn new_with_raw(
        raw: &[u8],
        transferable: Option<bool>,
        code: Option<String>,
    ) -> Result<SignerWrapper> {
        let signer = Signer::new_with_raw(raw, transferable, code.as_deref()).as_js()?;
        Ok(SignerWrapper(signer))
    }

    pub fn new_with_qb64b(qb64b: &[u8], transferable: Option<bool>) -> Result<SignerWrapper> {
        let signer = Signer::new_with_qb64b(qb64b, transferable).as_js()?;
        Ok(SignerWrapper(signer))
    }

    pub fn new_with_qb64(qb64: &str, transferable: Option<bool>) -> Result<SignerWrapper> {
        let signer = Signer::new_with_qb64(qb64, transferable).as_js()?;
        Ok(SignerWrapper(signer))
    }

    pub fn new_with_qb2(qb2: &[u8], transferable: Option<bool>) -> Result<SignerWrapper> {
        let signer = Signer::new_with_qb2(qb2, transferable).as_js()?;
        Ok(SignerWrapper(signer))
    }

    pub fn sign_unindexed(&self, ser: &[u8]) -> Result<CigarWrapper> {
        let cigar = self.0.sign_unindexed(ser).as_js()?;
        Ok(CigarWrapper(cigar))
    }

    pub fn sign_indexed(
        &self,
        ser: &[u8],
        only: bool,
        index: u32,
        ondex: Option<u32>,
    ) -> Result<SigerWrapper> {
        let siger = self.0.sign_indexed(ser, only, index, ondex).as_js()?;
        Ok(SigerWrapper(siger))
    }

    pub fn verfer(&self) -> VerferWrapper {
        VerferWrapper(self.0.verfer())
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

#[wasm_bindgen]
pub struct Signers(pub(crate) Vec<SignerWrapper>);

// TODO: Make this iterable in JS
#[wasm_bindgen]
impl Signers {
    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn get(&self, index: usize) -> Option<SignerWrapper> {
        if index < self.0.len() {
            Some(self.0[index].clone())
        } else {
            None
        }
    }
}

impl Deref for SignerWrapper {
    type Target = Signer;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Wrap<Signer> for SignerWrapper {
    type Wrapper = SignerWrapper;

    fn wrap(signer: &Signer) -> Self::Wrapper {
        SignerWrapper(signer.clone())
    }
}
