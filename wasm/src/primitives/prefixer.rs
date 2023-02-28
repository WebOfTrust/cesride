use crate::error::Result;
use crate::ffi::primitives::CesrideMatterCodex;
use crate::{Matter, Prefixer};

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
