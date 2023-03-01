use crate::error::Result;
use crate::ffi::primitives::CesrideMatterCodex;
use crate::{Matter, Verfer};

pub fn verfer_new(code: Option<CesrideMatterCodex>,
                  raw: Option<Vec<u8>>,
                  qb64b: Option<Vec<u8>>,
                  qb64: Option<String>,
                  qb2: Option<Vec<u8>>) -> Result<Verfer> {
    Verfer::new(code.as_ref().map(|code| code.code()),
                raw.as_deref(),
                qb64b.as_deref(),
                qb64.as_deref(),
                qb2.as_deref())
}

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

pub fn verfer_verify(verfer: &Verfer, sig: &[u8], ser: &[u8]) -> Result<bool> {
    verfer.verify( sig, ser)
}
