use crate::error::Result;
use crate::ffi::primitives::CesrideMatterCodex;
use crate::{Dater, Matter};

pub fn dater_new(dts: Option<String>,
                 code: Option<CesrideMatterCodex>,
                 raw: Option<Vec<u8>>,
                 qb64b: Option<Vec<u8>>,
                 qb64: Option<String>,
                 qb2: Option<Vec<u8>>) -> Result<Dater> {
    Dater::new(dts.as_deref(),
               code.as_ref().map(|code| code.code()),
               raw.as_deref(),
               qb64b.as_deref(),
               qb64.as_deref(),
               qb2.as_deref())
}

pub fn new_with_dts(dts: &str, code: Option<CesrideMatterCodex>) -> Result<Dater> {
    Dater::new_with_dts(dts,
                        code.as_ref().map(|code| code.code()))
}

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

pub fn dater_dtsb(dater: &Dater) -> Result<Vec<u8>> {
    dater.dtsb()
}
