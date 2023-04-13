use std::ops::Deref;

use crate::{
    error::*, DigerWrapper, NumberWrapper, SaiderWrapper, TholderWrapper, U128Wrapper,
    ValueWrapper, VerferWrapper, VersionWrapper, Wrap,
};
use cesride_core::{data::Value, Sadder, Serder};
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
        ked: Option<ValueWrapper>,
        sad: Option<SerderWrapper>,
    ) -> Result<SerderWrapper> {
        let serder = Serder::new(
            code.as_deref(),
            raw.as_deref(),
            kind.as_deref(),
            ked.map(Value::from).as_ref(),
            sad.as_deref(),
        )
        .as_js()?;
        Ok(SerderWrapper(serder))
    }

    pub fn new_with_ked(
        ked: ValueWrapper,
        code: Option<String>,
        kind: Option<String>,
    ) -> Result<SerderWrapper> {
        let serder =
            Serder::new_with_ked(&Value::from(ked), code.as_deref(), kind.as_deref()).as_js()?;
        Ok(SerderWrapper(serder))
    }

    pub fn verfers(&self) -> Result<Array> {
        let verfers = self.0.verfers().as_js()?;
        let arr = Array::new_with_length(verfers.len() as u32);
        (0..verfers.len()).for_each(|i| {
            let v = verfers[i].clone();
            arr.set(i as u32, VerferWrapper(v).into());
        });
        Ok(arr)
    }

    pub fn digers(&self) -> Result<Array> {
        let digers = self.0.digers().as_js()?;
        let arr = Array::new_with_length(digers.len() as u32);
        (0..digers.len()).for_each(|i| {
            let v = digers[i].clone();
            arr.set(i as u32, DigerWrapper(v).into());
        });
        Ok(arr)
    }

    pub fn werfers(&self) -> Result<Array> {
        let werfers = self.0.werfers().as_js()?;
        let arr = Array::new_with_length(werfers.len() as u32);
        (0..werfers.len()).for_each(|i| {
            let v = werfers[i].clone();
            arr.set(i as u32, VerferWrapper(v).into());
        });
        Ok(arr)
    }

    pub fn tholder(&self) -> Result<Option<TholderWrapper>> {
        let tholder = self.0.tholder().as_js()?;
        Ok(tholder.map(TholderWrapper))
    }

    pub fn ntholder(&self) -> Result<Option<TholderWrapper>> {
        let tholder = self.0.ntholder().as_js()?;
        Ok(tholder.map(TholderWrapper))
    }

    pub fn sner(&self) -> Result<NumberWrapper> {
        let sner = self.0.sner().as_js()?;
        Ok(NumberWrapper(sner))
    }

    pub fn sn(&self) -> Result<U128Wrapper> {
        let sn = self.0.sn().as_js()?;
        Ok(sn.into())
    }

    pub fn fner(&self) -> Result<Option<NumberWrapper>> {
        let sner = self.0.fner().as_js()?;
        Ok(sner.map(NumberWrapper))
    }

    pub fn _fn(&self) -> Result<U128Wrapper> {
        let _fn = self.0._fn().as_js()?;
        Ok(_fn.into())
    }

    pub fn code(&self) -> String {
        self.0.code()
    }

    pub fn raw(&self) -> Vec<u8> {
        self.0.raw()
    }

    pub fn ked(&self) -> ValueWrapper {
        let value = self.0.ked().to_string().expect("unable unwrap value");
        ValueWrapper(value)
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

impl Wrap<Serder> for SerderWrapper {
    type Wrapper = SerderWrapper;

    fn wrap(serder: &Serder) -> Self::Wrapper {
        SerderWrapper(serder.clone())
    }
}
