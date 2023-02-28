use crate::error::Result;
use crate::{Matter, Saider};

pub fn saider_new_with_qb64(qb64: &str) -> Result<Saider> {
    Saider::new_with_qb64(qb64)
}

pub fn saider_new_with_qb64b(qb64b: &[u8]) -> Result<Saider> {
    Saider::new_with_qb64b(qb64b)
}

pub fn saider_new_with_qb2(qb2: &[u8]) -> Result<Saider> {
    Saider::new_with_qb2(qb2)
}

pub fn saider_code(saider: &Saider) -> String {
    saider.code()
}

pub fn saider_size(saider: &Saider) -> u32 {
    saider.size()
}

pub fn saider_raw(saider: &Saider) -> Vec<u8> {
    saider.raw()
}

pub fn saider_qb64(saider: &Saider) -> Result<String> {
    saider.qb64()
}

pub fn saider_qb64b(saider: &Saider) -> Result<Vec<u8>> {
    saider.qb64b()
}

pub fn saider_qb2(saider: &Saider) -> Result<Vec<u8>> {
    saider.qb2()
}
