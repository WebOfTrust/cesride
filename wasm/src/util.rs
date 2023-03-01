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

impl Into<u128> for U128Wrapper {
    fn into(self) -> u128 {
        u128::from(self.high) | u128::from(self.low)
    }
}