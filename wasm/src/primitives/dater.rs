use crate::error::Result;
use crate::ffi::primitives::CesrideMatterCodex;
use crate::{Dater, Matter};

pub fn dater_new_with_code_and_raw(code: &CesrideMatterCodex, raw: &[u8]) -> Result<Dater> {
    Dater::new_with_code_and_raw(code.code(), raw)
}

pub fn dater_new_with_qb64(qb64: &str) -> Result<Dater> {
    Dater::new_with_qb64(qb64)
}

pub fn dater_new_with_qb64b(qb64b: &[u8]) -> Result<Dater> {
    Dater::new_with_qb64b(qb64b)
}

pub fn dater_new_with_qb2(qb2: &[u8]) -> Result<Dater> {
    Dater::new_with_qb2(qb2)
}

pub fn dater_code(dater: &Dater) -> String {
    dater.code()
}

pub fn dater_size(dater: &Dater) -> u32 {
    dater.size()
}

pub fn dater_raw(dater: &Dater) -> Vec<u8> {
    dater.raw()
}

pub fn dater_qb64(dater: &Dater) -> Result<String> {
    dater.qb64()
}

pub fn dater_qb64b(dater: &Dater) -> Result<Vec<u8>> {
    dater.qb64b()
}

pub fn dater_qb2(dater: &Dater) -> Result<Vec<u8>> {
    dater.qb2()
}
