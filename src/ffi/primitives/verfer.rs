use crate::error::Result;
use crate::ffi::primitives::CesrideMatterCodex;
use crate::{Matter, Verfer};

pub fn verfer_new_with_code_and_raw(code: &CesrideMatterCodex, raw: &[u8]) -> Result<Verfer> {
    Verfer::new_with_code_and_raw(code.code(), raw)
}

pub fn verfer_new_with_qb64(qb64: &str) -> Result<Verfer> {
    Verfer::new_with_qb64(qb64)
}

pub fn verfer_new_with_qb64b(qb64b: &[u8]) -> Result<Verfer> {
    Verfer::new_with_qb64b(qb64b)
}

pub fn verfer_new_with_qb2(qb2: &[u8]) -> Result<Verfer> {
    Verfer::new_with_qb2(qb2)
}

pub fn verfer_code(verfer: &Verfer) -> String {
    verfer.code()
}

pub fn verfer_size(verfer: &Verfer) -> u32 {
    verfer.size()
}

pub fn verfer_raw(verfer: &Verfer) -> Vec<u8> {
    verfer.raw()
}

pub fn verfer_qb64(verfer: &Verfer) -> Result<String> {
    verfer.qb64()
}

pub fn verfer_qb64b(verfer: &Verfer) -> Result<Vec<u8>> {
    verfer.qb64b()
}

pub fn verfer_qb2(verfer: &Verfer) -> Result<Vec<u8>> {
    verfer.qb2()
}
