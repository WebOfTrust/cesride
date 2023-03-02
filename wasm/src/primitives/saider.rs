use crate::error::*;
use cesride_core::Value;
use cesride_core::{Matter, Saider};
use js_sys::Array;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = Saider)]
#[derive(Clone)]
pub struct SaiderWrapper(pub(crate) Saider);

#[wasm_bindgen]
pub struct SaidifyRet {
    saider: SaiderWrapper,
    value: String,
}

#[wasm_bindgen]
impl SaidifyRet {
    pub fn saider(&self) -> SaiderWrapper {
        self.saider.clone()
    }
    pub fn value(&self) -> String {
        self.value.clone()
    }
}

#[wasm_bindgen(js_class = Saider)]
impl SaiderWrapper {
    // TODO: Value for sad, string array for ignore
    #[wasm_bindgen(constructor)]
    pub fn new(
        sad: Option<String>,
        label: Option<String>,
        kind: Option<String>,
        ignore: Option<Array>,
        code: Option<String>,
        raw: Option<Vec<u8>>,
        qb64b: Option<Vec<u8>>,
        qb64: Option<String>,
        qb2: Option<Vec<u8>>,
    ) -> Result<SaiderWrapper, JsValue> {
        let ignore = ignore
            .map(|a| a.iter().map(|v| v.as_string().unwrap_or_default()).collect::<Vec<String>>());
        let ignore = ignore.as_deref().map(|a| a.iter().map(String::as_str).collect::<Vec<&str>>());
        let ignore = ignore.as_deref();
        let saider = Saider::new(
            sad.as_deref().map(Value::from).as_ref(),
            label.as_deref(),
            kind.as_deref(),
            ignore,
            code.as_deref(),
            raw.as_deref(),
            qb64b.as_deref(),
            qb64.as_deref(),
            qb2.as_deref(),
        )
        .as_js()?;
        Ok(SaiderWrapper(saider))
    }

    pub fn saidify(
        sad: &str,
        code: Option<String>,
        kind: Option<String>,
        label: Option<String>,
        ignore: Option<Array>,
    ) -> Result<SaidifyRet, JsValue> {
        let ignore = ignore
            .map(|a| a.iter().map(|v| v.as_string().unwrap_or_default()).collect::<Vec<String>>());
        let ignore = ignore.as_deref().map(|a| a.iter().map(String::as_str).collect::<Vec<&str>>());
        let ignore = ignore.as_deref();
        let ret = Saider::saidify(
            &Value::from(sad),
            code.as_deref(),
            kind.as_deref(),
            label.as_deref(),
            ignore,
        )
        .as_js()?;
        Ok(SaidifyRet {
            saider: SaiderWrapper(ret.0),
            value: ret.1.to_string().expect("unable unwrap value"),
        })
    }

    pub fn verify(
        &self,
        sad: &str,
        prefixed: Option<bool>,
        versioned: Option<bool>,
        kind: Option<String>,
        label: Option<String>,
        ignore: Option<Array>,
    ) -> Result<bool, JsValue> {
        let ignore = ignore
            .map(|a| a.iter().map(|v| v.as_string().unwrap_or_default()).collect::<Vec<String>>());
        let ignore = ignore.as_deref().map(|a| a.iter().map(String::as_str).collect::<Vec<&str>>());
        let ignore = ignore.as_deref();
        let ret = self
            .0
            .verify(
                &Value::from(sad),
                prefixed,
                versioned,
                kind.as_deref(),
                label.as_deref(),
                ignore,
            )
            .as_js()?;
        Ok(ret)
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

    pub fn qb64(&self) -> Result<String, JsValue> {
        self.0.qb64().as_js().map_err(JsValue::from)
    }

    pub fn qb64b(&self) -> Result<Vec<u8>, JsValue> {
        self.0.qb64b().as_js().map_err(JsValue::from)
    }

    pub fn qb2(&self) -> Result<Vec<u8>, JsValue> {
        self.0.qb2().as_js().map_err(JsValue::from)
    }
}
