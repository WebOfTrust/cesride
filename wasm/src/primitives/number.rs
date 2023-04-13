use std::ops::Deref;

use crate::util::U128Wrapper;
use crate::{error::*, Wrap};
use cesride_core::{Matter, Number};
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = Number)]
pub struct NumberWrapper(pub(crate) Number);

#[wasm_bindgen(js_class = Number)]
impl NumberWrapper {
    #[wasm_bindgen(constructor)]
    pub fn new(
        num: Option<U128Wrapper>,
        numh: Option<String>,
        code: Option<String>,
        raw: Option<Vec<u8>>,
        qb64b: Option<Vec<u8>>,
        qb64: Option<String>,
        qb2: Option<Vec<u8>>,
    ) -> Result<NumberWrapper> {
        let number = Number::new(
            num.map(Into::into),
            numh.as_deref(),
            code.as_deref(),
            raw.as_deref(),
            qb64b.as_deref(),
            qb64.as_deref(),
            qb2.as_deref(),
        )
        .as_js()?;
        Ok(NumberWrapper(number))
    }

    pub fn new_with_num(num: U128Wrapper) -> Result<NumberWrapper> {
        let number = Number::new_with_num(num.into()).as_js()?;
        Ok(NumberWrapper(number))
    }

    pub fn new_with_numh(numh: &str) -> Result<NumberWrapper> {
        let number = Number::new_with_numh(numh).as_js()?;
        Ok(NumberWrapper(number))
    }

    pub fn new_with_raw(raw: &[u8], code: Option<String>) -> Result<NumberWrapper> {
        let number = Number::new_with_raw(raw, code.as_deref()).as_js()?;
        Ok(NumberWrapper(number))
    }

    pub fn new_with_qb64b(qb64b: &[u8]) -> Result<NumberWrapper> {
        let number = Number::new_with_qb64b(qb64b).as_js()?;
        Ok(NumberWrapper(number))
    }

    pub fn new_with_qb64(qb64: &str) -> Result<NumberWrapper> {
        let number = Number::new_with_qb64(qb64).as_js()?;
        Ok(NumberWrapper(number))
    }

    pub fn new_with_qb2(qb2: &[u8]) -> Result<NumberWrapper> {
        let number = Number::new_with_qb2(qb2).as_js()?;
        Ok(NumberWrapper(number))
    }

    pub fn num(&self) -> Result<U128Wrapper> {
        let num = self.0.num().as_js()?;
        Ok(num.into())
    }

    pub fn numh(&self) -> Result<String> {
        self.0.numh().as_js().map_err(JsValue::from)
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

impl Deref for NumberWrapper {
    type Target = Number;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Wrap<Number> for NumberWrapper {
    type Wrapper = NumberWrapper;

    fn wrap(number: &Number) -> Self::Wrapper {
        NumberWrapper(number.clone())
    }
}
