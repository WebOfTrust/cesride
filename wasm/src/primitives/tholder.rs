use crate::{error::*, BexterWrapper, NumberWrapper};
use cesride_core::Tholder;
use cesride_core::Value;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = Tholder)]
#[derive(Clone)]
pub struct TholderWrapper(pub(crate) Tholder);

#[wasm_bindgen]
pub struct SaidifyRet {
    tholder: TholderWrapper,
    value: String,
}

#[wasm_bindgen]
impl SaidifyRet {
    pub fn tholder(&self) -> TholderWrapper {
        self.tholder.clone()
    }
    pub fn value(&self) -> String {
        self.value.clone()
    }
}

#[wasm_bindgen(js_class = Tholder)]
impl TholderWrapper {
    #[wasm_bindgen(constructor)]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        thold: Option<String>,
        limen: Option<Vec<u8>>,
        sith: Option<String>,
    ) -> Result<TholderWrapper, JsValue> {
        let tholder = Tholder::new(
            thold.as_deref().map(Value::from).as_ref(),
            limen.as_deref(),
            sith.as_deref().map(Value::from).as_ref(),
        )
        .as_js()?;
        Ok(TholderWrapper(tholder))
    }

    pub fn new_with_thold(thold: &str) -> Result<TholderWrapper, JsValue> {
        let tholder = Tholder::new_with_thold(&Value::from(thold)).as_js()?;
        Ok(TholderWrapper(tholder))
    }

    pub fn new_with_limen(limen: &[u8]) -> Result<TholderWrapper, JsValue> {
        let tholder = Tholder::new_with_limen(limen).as_js()?;
        Ok(TholderWrapper(tholder))
    }

    pub fn new_with_sith(sith: &str) -> Result<TholderWrapper, JsValue> {
        let tholder = Tholder::new_with_sith(&Value::from(sith)).as_js()?;
        Ok(TholderWrapper(tholder))
    }

    pub fn thold(&self) -> String {
        self.0.thold().to_string().expect("unable unwrap value")
    }

    pub fn weighted(&self) -> bool {
        self.0.weighted()
    }

    pub fn size(&self) -> u32 {
        self.0.size()
    }

    pub fn num(&self) -> Result<Option<u32>, JsValue> {
        self.0.num().as_js().map_err(JsValue::from)
    }

    pub fn number(&self) -> Option<NumberWrapper> {
        self.0.number().map(NumberWrapper)
    }

    pub fn bexter(&self) -> Option<BexterWrapper> {
        self.0.bexter().map(BexterWrapper)
    }

    pub fn limen(&self) -> Result<Vec<u8>, JsValue> {
        self.0.limen().as_js().map_err(JsValue::from)
    }

    pub fn sith(&self) -> Result<String, JsValue> {
        let sith = self.0.sith().as_js()?;
        Ok(sith.to_string().expect("unable unwrap value"))
    }

    pub fn to_json(&self) -> Result<String, JsValue> {
        self.0.to_json().as_js().map_err(JsValue::from)
    }

    pub fn satisfy(&self, indices: &[u32]) -> Result<bool, JsValue> {
        self.0.satisfy(indices).as_js().map_err(JsValue::from)
    }
}
