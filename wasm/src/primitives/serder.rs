use std::ops::Deref;

use crate::{
    error::*, DigerWrapper, NumberWrapper, SaiderWrapper, TholderWrapper, U128Wrapper,
    VerferWrapper, VersionWrapper,
};
use cesride_core::Serder;
use cesride_core::{Sadder, Value};
use js_sys::Array;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = Serder)]
pub struct SerderWrapper(pub(crate) Serder);

#[wasm_bindgen(js_class = Serder)]
impl SerderWrapper {
    #[wasm_bindgen(constructor)]
    pub fn new(
        code: Option<String>,
        raw: Option<Vec<u8>>,
        kind: Option<String>,
        ked: Option<String>,
        sad: Option<SerderWrapper>,
    ) -> Result<SerderWrapper, JsValue> {
        let serder = Serder::new(
            code.as_deref(),
            raw.as_deref(),
            kind.as_deref(),
            ked.as_deref().map(Value::from).as_ref(),
            sad.as_deref(),
        )
        .as_js()?;
        Ok(SerderWrapper(serder))
    }

    pub fn new_with_ked(
        ked: &str,
        code: Option<String>,
        kind: Option<String>,
    ) -> Result<SerderWrapper, JsValue> {
        let serder =
            Serder::new_with_ked(&Value::from(ked), code.as_deref(), kind.as_deref()).as_js()?;
        Ok(SerderWrapper(serder))
    }

    pub fn verfers(&self) -> Result<Array, JsValue> {
        let verfers = self.0.verfers().as_js()?;
        let arr = Array::new_with_length(verfers.len() as u32);
        (0..verfers.len()).for_each(|i| {
            let v = verfers[i].clone();
            arr.set(i as u32, VerferWrapper(v).into());
        });
        Ok(arr)
    }

    pub fn digers(&self) -> Result<Array, JsValue> {
        let digers = self.0.digers().as_js()?;
        let arr = Array::new_with_length(digers.len() as u32);
        (0..digers.len()).for_each(|i| {
            let v = digers[i].clone();
            arr.set(i as u32, DigerWrapper(v).into());
        });
        Ok(arr)
    }

    pub fn werfers(&self) -> Result<Array, JsValue> {
        let werfers = self.0.werfers().as_js()?;
        let arr = Array::new_with_length(werfers.len() as u32);
        (0..werfers.len()).for_each(|i| {
            let v = werfers[i].clone();
            arr.set(i as u32, VerferWrapper(v).into());
        });
        Ok(arr)
    }

    pub fn tholder(&self) -> Result<Option<TholderWrapper>, JsValue> {
        let tholder = self.0.tholder().as_js()?;
        Ok(tholder.map(TholderWrapper))
    }

    pub fn ntholder(&self) -> Result<Option<TholderWrapper>, JsValue> {
        let tholder = self.0.ntholder().as_js()?;
        Ok(tholder.map(TholderWrapper))
    }

    pub fn sner(&self) -> Result<NumberWrapper, JsValue> {
        let sner = self.0.sner().as_js()?;
        Ok(NumberWrapper(sner))
    }

    pub fn sn(&self) -> Result<U128Wrapper, JsValue> {
        let sn = self.0.sn().as_js()?;
        Ok(sn.into())
    }

    pub fn fner(&self) -> Result<Option<NumberWrapper>, JsValue> {
        let sner = self.0.fner().as_js()?;
        Ok(sner.map(NumberWrapper))
    }

    pub fn _fn(&self) -> Result<U128Wrapper, JsValue> {
        let _fn = self.0._fn().as_js()?;
        Ok(_fn.into())
    }

    pub fn code(&self) -> String {
        self.0.code()
    }

    pub fn raw(&self) -> Vec<u8> {
        self.0.raw()
    }

    pub fn ked(&self) -> String {
        self.0.ked().to_string().expect("unable unwrap value")
    }

    pub fn ident(&self) -> String {
        self.0.ident()
    }

    pub fn kind(&self) -> String {
        self.0.kind()
    }

    pub fn size(&self) -> u32 {
        self.0.size()
    }

    pub fn version(&self) -> VersionWrapper {
        VersionWrapper(self.0.version())
    }

    pub fn saider(&self) -> SaiderWrapper {
        SaiderWrapper(self.0.saider())
    }
}

impl Deref for SerderWrapper {
    type Target = Serder;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
