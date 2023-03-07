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
