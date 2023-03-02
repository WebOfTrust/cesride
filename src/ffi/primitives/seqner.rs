use crate::error::Result;
use crate::ffi::primitives::CesrideMatterCodex;
use crate::{Matter, Seqner};

pub fn seqner_new(
    sn: Option<u64>,
    snh: Option<String>,
    code: Option<CesrideMatterCodex>,
    raw: Option<Vec<u8>>,
    qb64b: Option<Vec<u8>>,
    qb64: Option<String>,
    qb2: Option<Vec<u8>>,
) -> Result<Seqner> {
    Seqner::new(
        sn.map(|sn| sn as u128),
        snh.as_deref(),
        code.as_ref().map(|code| code.code()),
        raw.as_deref(),
        qb64b.as_deref(),
        qb64.as_deref(),
        qb2.as_deref(),
    )
}

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

pub fn seqner_sn(seqner: &Seqner) -> Result<u64> {
    seqner.sn().map(|value| value as u64)
}
pub fn seqner_snh(seqner: &Seqner) -> Result<String> {
    seqner.snh()
}
