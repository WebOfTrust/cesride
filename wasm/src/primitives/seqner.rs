use crate::error::Result;
use crate::ffi::primitives::CesrideMatterCodex;
use crate::{Matter, Seqner};

pub fn seqner_new_with_code_and_raw(code: &CesrideMatterCodex, raw: &[u8]) -> Result<Seqner> {
    Seqner::new_with_code_and_raw(code.code(), raw)
}

pub fn seqner_new_with_qb64(qb64: &str) -> Result<Seqner> {
    Seqner::new_with_qb64(qb64)
}

pub fn seqner_new_with_qb64b(qb64b: &[u8]) -> Result<Seqner> {
    Seqner::new_with_qb64b(qb64b)
}

pub fn seqner_new_with_qb2(qb2: &[u8]) -> Result<Seqner> {
    Seqner::new_with_qb2(qb2)
}

pub fn seqner_code(seqner: &Seqner) -> String {
    seqner.code()
}

pub fn seqner_size(seqner: &Seqner) -> u32 {
    seqner.size()
}

pub fn seqner_raw(seqner: &Seqner) -> Vec<u8> {
    seqner.raw()
}

pub fn seqner_qb64(seqner: &Seqner) -> Result<String> {
    seqner.qb64()
}

pub fn seqner_qb64b(seqner: &Seqner) -> Result<Vec<u8>> {
    seqner.qb64b()
}

pub fn seqner_qb2(seqner: &Seqner) -> Result<Vec<u8>> {
    seqner.qb2()
}
