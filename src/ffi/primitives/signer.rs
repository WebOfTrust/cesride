use crate::error::Result;
use crate::ffi::primitives::CesrideMatterCodex;
use crate::{Matter, Signer};

pub fn signer_new_with_code_and_raw(code: &CesrideMatterCodex, raw: &[u8]) -> Result<Signer> {
    Signer::new_with_code_and_raw(code.code(), raw)
}

pub fn signer_new_with_qb64(qb64: &str) -> Result<Signer> {
    Signer::new_with_qb64(qb64)
}

pub fn signer_new_with_qb64b(qb64b: &[u8]) -> Result<Signer> {
    Signer::new_with_qb64b(qb64b)
}

pub fn signer_new_with_qb2(qb2: &[u8]) -> Result<Signer> {
    Signer::new_with_qb2(qb2)
}

pub fn signer_code(signer: &Signer) -> String {
    signer.code()
}

pub fn signer_size(signer: &Signer) -> u32 {
    signer.size()
}

pub fn signer_raw(signer: &Signer) -> Vec<u8> {
    signer.raw()
}

pub fn signer_qb64(signer: &Signer) -> Result<String> {
    signer.qb64()
}

pub fn signer_qb64b(signer: &Signer) -> Result<Vec<u8>> {
    signer.qb64b()
}

pub fn signer_qb2(signer: &Signer) -> Result<Vec<u8>> {
    signer.qb2()
}
