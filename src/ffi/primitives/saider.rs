use crate::error::Result;
use crate::{CesrideMatterCodex, Matter, Saider};
use crate::data::Value;

pub fn saider_new(sad: Option<Value>,
                  label: Option<String>,
                  kind: Option<String>,
                  ignore: Option<Vec<String>>,
                  code: Option<CesrideMatterCodex>,
                  raw: Option<Vec<u8>>,
                  qb64b: Option<Vec<u8>>,
                  qb64: Option<String>,
                  qb2: Option<Vec<u8>>) -> Result<Saider> {
    Saider::new(sad.as_ref(),
                label.as_deref(),
                kind.as_deref(),
                ignore.as_deref().map(|allows| allows.iter().map(String::as_str).collect::<Vec<&str>>()).as_deref(),
                code.as_ref().map(|code| code.code()),
                raw.as_deref(),
                qb64b.as_deref(),
                qb64.as_deref(),
                qb2.as_deref())
}

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
