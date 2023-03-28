use cesride_core::data::Value;
use wasm_bindgen::prelude::wasm_bindgen;

#[wasm_bindgen(js_name = U128)]
pub struct U128Wrapper {
    low: u64,
    high: u64,
}

impl From<u128> for U128Wrapper {
    fn from(value: u128) -> Self {
        U128Wrapper { low: value as u64, high: (value >> 64) as u64 }
    }
}

impl From<U128Wrapper> for u128 {
    fn from(val: U128Wrapper) -> Self {
        u128::from(val.high) | u128::from(val.low)
    }
}

#[wasm_bindgen(js_name = Value)]
pub struct ValueWrapper(pub(crate) String);

#[wasm_bindgen(js_class = Value)]
impl ValueWrapper {
    #[wasm_bindgen(constructor)]
    pub fn new(value: &str) -> ValueWrapper {
        ValueWrapper(value.to_string())
    }

    pub fn value(&self) -> String {
        self.0.clone()
    }
}

impl From<ValueWrapper> for Value {
    fn from(value: ValueWrapper) -> Self {
        let v: serde_json::Value = serde_json::from_str(&value.0).unwrap();
        Value::from(&v)
    }
}

pub trait Wrap<T> {
    type Wrapper;

    fn wrap(verfer: &T) -> Self::Wrapper;
}
