use crate::error::Result;
use crate::ffi::primitives::CesrideIndexerCodex;
use crate::{Indexer, Siger, Verfer};

pub fn siger_new_with_code_and_raw(
    code: &CesrideIndexerCodex,
    raw: &[u8],
    index: u32,
    ondex: Option<u32>,
) -> Result<Siger> {
    Siger::new_with_code_and_raw(code.code(), raw, index, ondex)
}

pub fn siger_new_with_qb64(qb64: &str, verfer: Option<Verfer>) -> Result<Siger> {
    Siger::new_with_qb64(qb64, verfer.as_ref())
}

pub fn siger_new_with_qb64b(qb64b: &[u8], verfer: Option<Verfer>) -> Result<Siger> {
    Siger::new_with_qb64b(qb64b, verfer.as_ref())
}

pub fn siger_new_with_qb2(qb2: &[u8], verfer: Option<Verfer>) -> Result<Siger> {
    Siger::new_with_qb2(qb2, verfer.as_ref())
}

pub fn siger_code(siger: &Siger) -> String {
    siger.code()
}

pub fn siger_raw(siger: &Siger) -> Vec<u8> {
    siger.raw()
}

pub fn siger_qb64(siger: &Siger) -> Result<String> {
    siger.qb64()
}

pub fn siger_qb64b(siger: &Siger) -> Result<Vec<u8>> {
    siger.qb64b()
}

pub fn siger_qb2(siger: &Siger) -> Result<Vec<u8>> {
    siger.qb2()
}
