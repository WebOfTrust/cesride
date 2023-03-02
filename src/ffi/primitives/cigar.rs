use crate::error::Result;
use crate::ffi::primitives::CesrideMatterCodex;
use crate::{Cigar, Matter, Verfer};

pub fn cigar_new(
    verfer: Option<Verfer>,
    code: Option<CesrideMatterCodex>,
    raw: Option<Vec<u8>>,
    qb64b: Option<Vec<u8>>,
    qb64: Option<String>,
    qb2: Option<Vec<u8>>,
) -> Result<Cigar> {
    Cigar::new(
        verfer.as_ref(),
        code.as_ref().map(|code| code.code()),
        raw.as_deref(),
        qb64b.as_deref(),
        qb64.as_deref(),
        qb2.as_deref(),
    )
}

pub fn cigar_new_with_code_and_raw(code: &CesrideMatterCodex, raw: &[u8]) -> Result<Cigar> {
    Cigar::new_with_code_and_raw(code.code(), raw)
}

pub fn cigar_new_with_qb64(qb64: &str, verfer: Option<Verfer>) -> Result<Cigar> {
    Cigar::new_with_qb64(qb64, verfer.as_ref())
}

pub fn cigar_new_with_qb64b(qb64b: &[u8], verfer: Option<Verfer>) -> Result<Cigar> {
    Cigar::new_with_qb64b(qb64b, verfer.as_ref())
}

pub fn cigar_new_with_qb2(qb2: &[u8], verfer: Option<Verfer>) -> Result<Cigar> {
    Cigar::new_with_qb2(qb2, verfer.as_ref())
}

pub fn cigar_code(cigar: &Cigar) -> String {
    cigar.code()
}

pub fn cigar_size(cigar: &Cigar) -> u32 {
    cigar.size()
}

pub fn cigar_raw(cigar: &Cigar) -> Vec<u8> {
    cigar.raw()
}

pub fn cigar_qb64(cigar: &Cigar) -> Result<String> {
    cigar.qb64()
}

pub fn cigar_qb64b(cigar: &Cigar) -> Result<Vec<u8>> {
    cigar.qb64b()
}

pub fn cigar_qb2(cigar: &Cigar) -> Result<Vec<u8>> {
    cigar.qb2()
}
