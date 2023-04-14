use std::ops::Deref;

use crate::{error::*, SignerWrapper, Signers, Wrap};
use cesride_core::{Matter, Salter};
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = Salter)]
pub struct SalterWrapper(Salter);

#[wasm_bindgen(js_class = Salter)]
impl SalterWrapper {
    #[wasm_bindgen(constructor)]
    pub fn new(
        tier: Option<String>,
        code: Option<String>,
        raw: Option<Vec<u8>>,
        qb64b: Option<Vec<u8>>,
        qb64: Option<String>,
        qb2: Option<Vec<u8>>,
    ) -> Result<SalterWrapper> {
        let salter = Salter::new(
            tier.as_deref(),
            code.as_deref(),
            raw.as_deref(),
            qb64b.as_deref(),
            qb64.as_deref(),
            qb2.as_deref(),
        )
        .as_js()?;
        Ok(SalterWrapper(salter))
    }

    pub fn new_with_defaults(tier: Option<String>) -> Result<SalterWrapper> {
        let salter = Salter::new_with_defaults(tier.as_deref()).as_js()?;
        Ok(SalterWrapper(salter))
    }

    pub fn new_with_raw(
        raw: &[u8],
        code: Option<String>,
        tier: Option<String>,
    ) -> Result<SalterWrapper> {
        let salter = Salter::new_with_raw(raw, code.as_deref(), tier.as_deref()).as_js()?;
        Ok(SalterWrapper(salter))
    }

    pub fn new_with_qb64b(qb64b: &[u8], tier: Option<String>) -> Result<SalterWrapper> {
        let salter = Salter::new_with_qb64b(qb64b, tier.as_deref()).as_js()?;
        Ok(SalterWrapper(salter))
    }

    pub fn new_with_qb64(qb64: &str, tier: Option<String>) -> Result<SalterWrapper> {
        let salter = Salter::new_with_qb64(qb64, tier.as_deref()).as_js()?;
        Ok(SalterWrapper(salter))
    }

    pub fn new_with_qb2(qb2: &[u8], tier: Option<String>) -> Result<SalterWrapper> {
        let salter = Salter::new_with_qb2(qb2, tier.as_deref()).as_js()?;
        Ok(SalterWrapper(salter))
    }

    pub fn stretch(
        &self,
        size: Option<usize>,
        path: Option<String>,
        tier: Option<String>,
        temp: Option<bool>,
    ) -> Result<Vec<u8>> {
        let seed = self.0.stretch(size, path.as_deref(), tier.as_deref(), temp).as_js()?;
        Ok(seed)
    }

    pub fn tier(&self) -> String {
        self.0.tier()
    }

    pub fn signer(
        &self,
        code: Option<String>,
        transferable: Option<bool>,
        path: Option<String>,
        tier: Option<String>,
        temp: Option<bool>,
    ) -> Result<SignerWrapper> {
        let signer = self
            .0
            .signer(code.as_deref(), transferable, path.as_deref(), tier.as_deref(), temp)
            .as_js()?;
        Ok(SignerWrapper(signer))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn signers(
        &self,
        count: Option<usize>,
        start: Option<usize>,
        path: Option<String>,
        code: Option<String>,
        transferable: Option<bool>,
        tier: Option<String>,
        temp: Option<bool>,
    ) -> Result<Signers> {
        let signers = self
            .0
            .signers(
                count,
                start,
                path.as_deref(),
                code.as_deref(),
                transferable,
                tier.as_deref(),
                temp,
            )
            .as_js()?;
        let signers = signers.iter().map(|x| SignerWrapper(x.clone())).collect();
        Ok(Signers(signers))
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

impl Deref for SalterWrapper {
    type Target = Salter;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Wrap<Salter> for SalterWrapper {
    type Wrapper = SalterWrapper;

    fn wrap(salter: &Salter) -> Self::Wrapper {
        SalterWrapper(salter.clone())
    }
}
