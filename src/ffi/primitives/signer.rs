use crate::error::Result;
use crate::ffi::primitives::CesrideMatterCodex;
use crate::{Cigar, Matter, Siger, Signer};

pub fn signer_new(transferable: Option<bool>,
                  code: Option<CesrideMatterCodex>,
                  raw: Option<Vec<u8>>,
                  qb64b: Option<Vec<u8>>,
                  qb64: Option<String>,
                  qb2: Option<Vec<u8>>) -> Result<Signer> {
    Signer::new(transferable,
                code.as_ref().map(|code| code.code()),
                raw.as_deref(),
                qb64b.as_deref(),
                qb64.as_deref(),
                qb2.as_deref())
}

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

pub fn signer_sign_unindexed(signer: &Signer, ser: &[u8]) -> Result<Cigar> {
    signer.sign_unindexed(ser)
}

pub fn signer_sign_indexed(signer: &Signer,
                           ser: &[u8],
                           only: bool,
                           index: u32,
                           ondex: Option<u32>, ) -> Result<Siger> {
    signer.sign_indexed(ser, only, index, ondex)
}
