use crate::error::Result;
use crate::ffi::primitives::CesrideMatterCodex;
use crate::{Diger, Matter};

pub fn diger_new_with_code_and_raw(code: &CesrideMatterCodex, raw: &[u8]) -> Result<Diger> {
    Diger::new_with_code_and_raw(code.code(), raw)
}

pub fn diger_new_with_qb64(qb64: &str) -> Result<Diger> {
    Diger::new_with_qb64(qb64)
}

pub fn diger_new_with_qb64b(qb64b: &[u8]) -> Result<Diger> {
    Diger::new_with_qb64b(qb64b)
}

pub fn diger_new_with_qb2(qb2: &[u8]) -> Result<Diger> {
    Diger::new_with_qb2(qb2)
}

pub fn diger_code(diger: &Diger) -> String {
    diger.code()
}

pub fn diger_size(diger: &Diger) -> u32 {
    diger.size()
}

pub fn diger_raw(diger: &Diger) -> Vec<u8> {
    diger.raw()
}

pub fn diger_qb64(diger: &Diger) -> Result<String> {
    diger.qb64()
}

pub fn diger_qb64b(diger: &Diger) -> Result<Vec<u8>> {
    diger.qb64b()
}

pub fn diger_qb2(diger: &Diger) -> Result<Vec<u8>> {
    diger.qb2()
}
