use crate::data::Value;
use crate::error::Result;
use crate::ffi::primitives::CesrideMatterCodex;
use crate::{Matter, Prefixer};

pub fn prefixer_new(
    ked: Option<Value>,
    allows: Option<Vec<String>>,
    code: Option<CesrideMatterCodex>,
    raw: Option<Vec<u8>>,
    qb64b: Option<Vec<u8>>,
    qb64: Option<String>,
    qb2: Option<Vec<u8>>,
) -> Result<Prefixer> {
    Prefixer::new(
        ked.as_ref(),
        allows
            .as_deref()
            .map(|allows| allows.iter().map(String::as_str).collect::<Vec<&str>>())
            .as_deref(),
        code.as_ref().map(|code| code.code()),
        raw.as_deref(),
        qb64b.as_deref(),
        qb64.as_deref(),
        qb2.as_deref(),
    )
}

pub fn prefixer_new_with_code_and_raw(code: &CesrideMatterCodex, raw: &[u8]) -> Result<Prefixer> {
    Prefixer::new_with_code_and_raw(code.code(), raw)
}

pub fn prefixer_new_with_qb64(qb64: &str) -> Result<Prefixer> {
    Prefixer::new_with_qb64(qb64)
}

pub fn prefixer_new_with_qb64b(qb64b: &[u8]) -> Result<Prefixer> {
    Prefixer::new_with_qb64b(qb64b)
}

pub fn prefixer_new_with_qb2(qb2: &[u8]) -> Result<Prefixer> {
    Prefixer::new_with_qb2(qb2)
}

pub fn prefixer_code(prefixer: &Prefixer) -> String {
    prefixer.code()
}

pub fn prefixer_size(prefixer: &Prefixer) -> u32 {
    prefixer.size()
}

pub fn prefixer_raw(prefixer: &Prefixer) -> Vec<u8> {
    prefixer.raw()
}

pub fn prefixer_qb64(prefixer: &Prefixer) -> Result<String> {
    prefixer.qb64()
}

pub fn prefixer_qb64b(prefixer: &Prefixer) -> Result<Vec<u8>> {
    prefixer.qb64b()
}

pub fn prefixer_qb2(prefixer: &Prefixer) -> Result<Vec<u8>> {
    prefixer.qb2()
}

pub fn prefixer_verify(prefixer: &Prefixer, ked: &Value, prefixed: Option<bool>) -> Result<bool> {
    prefixer.verify(ked, prefixed)
}
