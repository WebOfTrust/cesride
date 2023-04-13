use std::ops::Deref;

use crate::{error::*, BexterWrapper, NumberWrapper};
use crate::{ValueWrapper, Wrap};
use cesride_core::data::Value;
use cesride_core::Tholder;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = Tholder)]
#[derive(Clone)]
pub struct TholderWrapper(pub(crate) Tholder);

#[wasm_bindgen(js_class = Tholder)]
impl TholderWrapper {
    #[wasm_bindgen(constructor)]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        thold: Option<ValueWrapper>,
        limen: Option<Vec<u8>>,
        sith: Option<ValueWrapper>,
    ) -> Result<TholderWrapper> {
        let tholder = Tholder::new(
            thold.map(Value::from).as_ref(),
            limen.as_deref(),
            sith.map(Value::from).as_ref(),
        )
        .as_js()?;
        Ok(TholderWrapper(tholder))
    }

    pub fn new_with_thold(thold: ValueWrapper) -> Result<TholderWrapper> {
        let tholder = Tholder::new_with_thold(&Value::from(thold)).as_js()?;
        Ok(TholderWrapper(tholder))
    }

    pub fn new_with_limen(limen: &[u8]) -> Result<TholderWrapper> {
        let tholder = Tholder::new_with_limen(limen).as_js()?;
        Ok(TholderWrapper(tholder))
    }

    pub fn new_with_sith(sith: ValueWrapper) -> Result<TholderWrapper> {
        let tholder = Tholder::new_with_sith(&Value::from(sith)).as_js()?;
        Ok(TholderWrapper(tholder))
    }

    pub fn thold(&self) -> ValueWrapper {
        let value = self.0.thold().to_json().expect("unable unwrap value");
        ValueWrapper(value)
    }

    pub fn weighted(&self) -> bool {
        self.0.weighted()
    }

    pub fn size(&self) -> u32 {
        self.0.size()
    }

    pub fn num(&self) -> Result<Option<u32>> {
        self.0.num().as_js().map_err(JsValue::from)
    }

    pub fn number(&self) -> Option<NumberWrapper> {
        self.0.number().map(NumberWrapper)
    }

    pub fn bexter(&self) -> Option<BexterWrapper> {
        self.0.bexter().map(BexterWrapper)
    }

    pub fn limen(&self) -> Result<Vec<u8>> {
        self.0.limen().as_js().map_err(JsValue::from)
    }

    pub fn sith(&self) -> Result<ValueWrapper> {
        let sith = self.0.sith().as_js()?;
        let value = sith.to_json().expect("unable unwrap value");
        Ok(ValueWrapper(value))
    }

    pub fn to_json(&self) -> Result<String> {
        self.0.to_json().as_js().map_err(JsValue::from)
    }

    pub fn satisfy(&self, indices: &[u32]) -> Result<bool> {
        self.0.satisfy(indices).as_js().map_err(JsValue::from)
    }
}

impl Deref for TholderWrapper {
    type Target = Tholder;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Wrap<Tholder> for TholderWrapper {
    type Wrapper = TholderWrapper;

    fn wrap(tholder: &Tholder) -> Self::Wrapper {
        TholderWrapper(tholder.clone())
    }
}
