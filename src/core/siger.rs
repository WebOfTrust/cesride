use crate::core::indexer::{tables as indexer, Indexer};
use crate::core::verfer::Verfer;
use crate::error::{err, Error, Result};

#[derive(Debug, Clone, PartialEq)]
pub struct Siger {
    pub raw: Vec<u8>,
    pub code: String,
    pub index: u32,
    pub ondex: u32,
    pub verfer: Verfer,
}

impl Default for Siger {
    fn default() -> Self {
        Siger {
            raw: vec![],
            code: indexer::Codex::Ed25519.to_string(),
            index: 0,
            ondex: 0,
            verfer: Verfer::default(),
        }
    }
}

fn validate_code(code: &str) -> Result<()> {
    const CODES: &[&str] = &[
        indexer::Codex::Ed25519,
        indexer::Codex::Ed25519_Crt,
        indexer::Codex::ECDSA_256k1,
        indexer::Codex::ECDSA_256k1_Crt,
        indexer::Codex::Ed448,
        indexer::Codex::Ed448_Crt,
        indexer::Codex::Ed25519_Big,
        indexer::Codex::Ed25519_Big_Crt,
        indexer::Codex::ECDSA_256k1_Big,
        indexer::Codex::ECDSA_256k1_Big_Crt,
        indexer::Codex::Ed448_Big,
        indexer::Codex::Ed448_Big_Crt,
    ];

    if !CODES.contains(&code) {
        return err!(Error::UnexpectedCode(code.to_string()));
    }

    Ok(())
}

impl Siger {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        verfer: Option<&Verfer>,
        index: Option<u32>,
        ondex: Option<u32>,
        code: Option<&str>,
        raw: Option<&[u8]>,
        qb64b: Option<&[u8]>,
        qb64: Option<&str>,
        qb2: Option<&[u8]>,
    ) -> Result<Self> {
        let mut siger: Self = Indexer::new(index, ondex, code, raw, qb64b, qb64, qb2)?;
        if let Some(verfer) = verfer {
            siger.set_verfer(verfer);
        }
        validate_code(&siger.code())?;
        Ok(siger)
    }

    pub fn new_with_raw(
        raw: &[u8],
        verfer: Option<&Verfer>,
        index: Option<u32>,
        ondex: Option<u32>,
        code: Option<&str>,
    ) -> Result<Self> {
        Self::new(verfer, index, ondex, code, Some(raw), None, None, None)
    }

    pub fn new_with_qb64b(qb64b: &[u8], verfer: Option<&Verfer>) -> Result<Self> {
        Self::new(verfer, None, None, None, None, Some(qb64b), None, None)
    }

    pub fn new_with_qb64(qb64: &str, verfer: Option<&Verfer>) -> Result<Self> {
        Self::new(verfer, None, None, None, None, None, Some(qb64), None)
    }

    pub fn new_with_qb2(qb2: &[u8], verfer: Option<&Verfer>) -> Result<Self> {
        Self::new(verfer, None, None, None, None, None, None, Some(qb2))
    }

    pub fn verfer(&self) -> Verfer {
        self.verfer.clone()
    }

    fn set_verfer(&mut self, verfer: &Verfer) {
        self.verfer = verfer.clone();
    }
}

impl Indexer for Siger {
    fn code(&self) -> String {
        self.code.clone()
    }

    fn raw(&self) -> Vec<u8> {
        self.raw.clone()
    }

    fn index(&self) -> u32 {
        self.index
    }

    fn ondex(&self) -> u32 {
        self.ondex
    }

    fn set_code(&mut self, code: &str) {
        self.code = code.to_string();
    }

    fn set_raw(&mut self, raw: &[u8]) {
        self.raw = raw.to_vec();
    }

    fn set_index(&mut self, size: u32) {
        self.index = size;
    }

    fn set_ondex(&mut self, size: u32) {
        self.ondex = size;
    }
}

#[cfg(test)]
mod test {
    use super::{indexer, Indexer, Siger, Verfer};
    use crate::core::matter::tables as matter;
    use base64::{engine::general_purpose as b64_engine, Engine};
    use hex_literal::hex;

    #[test]
    fn convenience() {
        let vcode = matter::Codex::Ed25519;
        let vraw = b"abcdefghijklmnopqrstuvwxyz012345";
        let verfer = Verfer::new(Some(vcode), Some(vraw), None, None, None).unwrap();
        let code = indexer::Codex::Ed25519;
        let raw = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ[]";

        let siger =
            Siger::new(Some(&verfer), None, None, Some(code), Some(raw), None, None, None).unwrap();

        assert!(Siger::new_with_raw(&siger.raw(), Some(&verfer), None, None, Some(&siger.code()))
            .is_ok());
        assert!(Siger::new_with_qb64b(&siger.qb64b().unwrap(), Some(&verfer)).is_ok());
        assert!(Siger::new_with_qb64(&siger.qb64().unwrap(), Some(&verfer)).is_ok());
        assert!(Siger::new_with_qb2(&siger.qb2().unwrap(), Some(&verfer)).is_ok());
    }

    #[test]
    fn new() {
        let vcode = matter::Codex::Ed25519;
        let vraw = b"abcdefghijklmnopqrstuvwxyz012345";
        let verfer = Verfer::new(Some(vcode), Some(vraw), None, None, None).unwrap();
        let code = indexer::Codex::Ed25519;
        let raw = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ[]";

        assert!(
            Siger::new(Some(&verfer), None, None, Some(code), Some(raw), None, None, None).is_ok()
        );
        assert!(Siger::new(None, None, None, Some(code), Some(raw), None, None, None).is_ok());
    }

    #[test]
    fn python_interop() {
        assert!(Siger::new(None, None, None, Some(""), Some(b""), None, None, None).is_err());

        let qsig64 = "AACdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd7K_H9-1298F4Id1DxvIoEmCQ";
        let qsig64b = qsig64.as_bytes();

        let siger = Siger::new(None, None, None, None, None, Some(qsig64b), None, None).unwrap();
        assert_eq!(siger.code(), indexer::Codex::Ed25519);
        assert_eq!(siger.index(), 0);
        assert_eq!(siger.ondex(), 0);
        assert_eq!(siger.qb64().unwrap(), qsig64);
        // this behaviour differs from KERIpy
        assert_eq!(siger.verfer(), Verfer::default());

        let mut siger = Siger::new(None, None, None, None, None, None, Some(qsig64), None).unwrap();
        assert_eq!(siger.code(), indexer::Codex::Ed25519);
        assert_eq!(siger.index(), 0);
        assert_eq!(siger.ondex(), 0);
        assert_eq!(siger.qb64().unwrap(), qsig64);
        // this behaviour differs from KERIpy
        assert_eq!(siger.verfer(), Verfer::default());

        let verfer_raw = hex!("0123456789abcdef00001111222233334444555566667777888899990000aaaa");

        let verfer_code = matter::Codex::Ed25519;
        let verfer = Verfer::new(Some(verfer_code), Some(&verfer_raw), None, None, None).unwrap();

        siger.set_verfer(&verfer);
        assert_eq!(siger.verfer(), verfer);

        let siger =
            Siger::new(Some(&verfer), None, None, None, None, None, Some(qsig64), None).unwrap();
        assert_eq!(siger.verfer(), verfer);

        let raw = b"abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdef";
        let siger = Siger::new(
            None,
            Some(4),
            None,
            Some(indexer::Codex::Ed448),
            Some(raw),
            None,
            None,
            None,
        )
        .unwrap();
        assert_eq!(siger.qb64().unwrap(), "0AEEYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU2Nzg5YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU2Nzg5YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU2Nzg5YWJjZGVm");
    }

    #[test]
    fn new_with_code_and_raw() {
        let verfer_raw = hex!("0123456789abcdef00001111222233334444555566667777888899990000aaaa");

        let verfer_code = matter::Codex::Ed25519;
        let verfer = Verfer::new(Some(verfer_code), Some(&verfer_raw), None, None, None).unwrap();

        let siger_code = indexer::Codex::Ed25519;
        let siger_raw = hex!("0123456789abcdef00001111222233334444555566667777888899990000aaaa"
                                       "0123456789abcdef00001111222233334444555566667777888899990000aaaa");

        assert!(Siger::new(
            Some(&verfer),
            None,
            None,
            Some(siger_code),
            Some(&siger_raw),
            None,
            None,
            None
        )
        .is_ok());
        assert!(Siger::new(None, None, None, Some(siger_code), Some(&siger_raw), None, None, None)
            .is_ok());
    }

    #[test]
    fn new_with_qb64b() {
        let verfer_raw = hex!("0123456789abcdef00001111222233334444555566667777888899990000aaaa");

        let verfer_code = matter::Codex::Ed25519;
        let verfer = Verfer::new(Some(verfer_code), Some(&verfer_raw), None, None, None).unwrap();

        let qsig64 = "AACdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd7K_H9-1298F4Id1DxvIoEmCQ";
        let qsig64b = qsig64.as_bytes();

        assert!(
            Siger::new(Some(&verfer), None, None, None, None, Some(qsig64b), None, None).is_ok()
        );
        assert!(Siger::new(None, None, None, None, None, Some(qsig64b), None, None).is_ok());
    }

    #[test]
    fn new_with_qb2() {
        let verfer_raw = hex!("0123456789abcdef00001111222233334444555566667777888899990000aaaa");

        let verfer_code = matter::Codex::Ed25519;
        let verfer = Verfer::new(Some(verfer_code), Some(&verfer_raw), None, None, None).unwrap();

        let qsig2 = b64_engine::URL_SAFE.decode("AACdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd7K_H9-1298F4Id1DxvIoEmCQ").unwrap();

        assert!(Siger::new(Some(&verfer), None, None, None, None, None, None, Some(&qsig2)).is_ok());
        assert!(Siger::new(None, None, None, None, None, None, None, Some(&qsig2)).is_ok());
    }

    #[test]
    fn unhappy_paths() {
        // invalid code
        assert!(Siger::new(None, None, None, Some("CESR"), Some(&[]), None, None, None).is_err());
    }
}
