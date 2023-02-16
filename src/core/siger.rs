use lazy_static::lazy_static;

use crate::core::indexer::{tables as indexer, Indexer};
use crate::core::verfer::Verfer;
use crate::error::{err, Error, Result};

#[derive(Debug, Clone, PartialEq)]
pub struct Siger {
    raw: Vec<u8>,
    code: String,
    index: u32,
    ondex: u32,
    verfer: Verfer,
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
    lazy_static! {
        static ref CODES: Vec<&'static str> = vec![
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
    }

    if !CODES.contains(&code) {
        return err!(Error::UnexpectedCode(code.to_string()));
    }

    Ok(())
}

impl Siger {
    fn new_with_code_and_raw(
        verfer: Option<&Verfer>,
        code: &str,
        raw: &[u8],
        index: u32,
        ondex: Option<u32>,
    ) -> Result<Self> {
        if !code.is_empty() {
            validate_code(code)?;
        }

        let mut siger: Siger = Indexer::new_with_code_and_raw(code, raw, index, ondex)?;
        if let Some(verfer) = verfer {
            siger.set_verfer(verfer);
        }
        Ok(siger)
    }

    fn new_with_qb64(verfer: Option<&Verfer>, qb64: &str) -> Result<Self> {
        let mut siger: Siger = Indexer::new_with_qb64(qb64)?;
        validate_code(&siger.code())?;
        if let Some(verfer) = verfer {
            siger.set_verfer(verfer);
        }
        Ok(siger)
    }

    fn new_with_qb64b(verfer: Option<&Verfer>, qb64b: &[u8]) -> Result<Self> {
        let mut siger: Siger = Indexer::new_with_qb64b(qb64b)?;
        validate_code(&siger.code())?;
        if let Some(verfer) = verfer {
            siger.set_verfer(verfer);
        }
        Ok(siger)
    }

    fn new_with_qb2(verfer: Option<&Verfer>, qb2: &[u8]) -> Result<Self> {
        let mut siger: Siger = Indexer::new_with_qb2(qb2)?;
        validate_code(&siger.code())?;
        if let Some(verfer) = verfer {
            siger.set_verfer(verfer);
        }
        Ok(siger)
    }

    fn verfer(&self) -> Verfer {
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
mod test_siger {
    use super::{indexer, Indexer, Siger, Verfer};
    use crate::core::matter::tables as matter;
    use base64::{engine::general_purpose as b64_engine, Engine};
    use hex_literal::hex;

    #[test]
    fn test_python_interop() {
        assert!(Siger::new_with_code_and_raw(None, "", b"", 0, Some(0)).is_err());

        let qsig64 = "AACdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd7K_H9-1298F4Id1DxvIoEmCQ";
        let qsig64b = qsig64.as_bytes();

        let siger = Siger::new_with_qb64b(None, qsig64b).unwrap();
        assert_eq!(siger.code(), indexer::Codex::Ed25519);
        assert_eq!(siger.index(), 0);
        assert_eq!(siger.ondex(), 0);
        assert_eq!(siger.qb64().unwrap(), qsig64);
        // this behaviour differs from KERIpy
        assert_eq!(siger.verfer(), Verfer::default());

        let mut siger = Siger::new_with_qb64(None, qsig64).unwrap();
        assert_eq!(siger.code(), indexer::Codex::Ed25519);
        assert_eq!(siger.index(), 0);
        assert_eq!(siger.ondex(), 0);
        assert_eq!(siger.qb64().unwrap(), qsig64);
        // this behaviour differs from KERIpy
        assert_eq!(siger.verfer(), Verfer::default());

        let verfer_raw = hex!("0123456789abcdef00001111222233334444555566667777888899990000aaaa");

        let verfer_code = matter::Codex::Ed25519;
        let verfer = Verfer::new_with_code_and_raw(verfer_code, &verfer_raw).unwrap();

        siger.set_verfer(&verfer);
        assert_eq!(siger.verfer(), verfer);

        let siger = Siger::new_with_qb64(Some(&verfer), qsig64).unwrap();
        assert_eq!(siger.verfer(), verfer);

        let raw = b"abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdef";
        let siger =
            Siger::new_with_code_and_raw(None, indexer::Codex::Ed448, raw, 4, None).unwrap();
        assert_eq!(siger.qb64().unwrap(), "0AEEYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU2Nzg5YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU2Nzg5YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU2Nzg5YWJjZGVm");
    }

    #[test]
    fn test_new_with_code_and_raw() {
        let verfer_raw = hex!("0123456789abcdef00001111222233334444555566667777888899990000aaaa");

        let verfer_code = matter::Codex::Ed25519;
        let verfer = Verfer::new_with_code_and_raw(verfer_code, &verfer_raw).unwrap();

        let siger_code = indexer::Codex::Ed25519;
        let siger_raw = hex!("0123456789abcdef00001111222233334444555566667777888899990000aaaa"
                                       "0123456789abcdef00001111222233334444555566667777888899990000aaaa");

        assert!(
            Siger::new_with_code_and_raw(Some(&verfer), siger_code, &siger_raw, 0, None).is_ok()
        );
        assert!(Siger::new_with_code_and_raw(None, siger_code, &siger_raw, 0, None).is_ok());
    }

    #[test]
    fn test_new_with_qb64b() {
        let verfer_raw = hex!("0123456789abcdef00001111222233334444555566667777888899990000aaaa");

        let verfer_code = matter::Codex::Ed25519;
        let verfer = Verfer::new_with_code_and_raw(verfer_code, &verfer_raw).unwrap();

        let qsig64 = "AACdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd7K_H9-1298F4Id1DxvIoEmCQ";
        let qsig64b = qsig64.as_bytes();

        assert!(Siger::new_with_qb64b(Some(&verfer), qsig64b).is_ok());
        assert!(Siger::new_with_qb64b(None, qsig64b).is_ok());
    }

    #[test]
    fn test_new_with_qb2() {
        let verfer_raw = hex!("0123456789abcdef00001111222233334444555566667777888899990000aaaa");

        let verfer_code = matter::Codex::Ed25519;
        let verfer = Verfer::new_with_code_and_raw(verfer_code, &verfer_raw).unwrap();

        let qsig2 = b64_engine::URL_SAFE.decode("AACdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd7K_H9-1298F4Id1DxvIoEmCQ").unwrap();

        assert!(Siger::new_with_qb2(Some(&verfer), &qsig2).is_ok());
        assert!(Siger::new_with_qb2(None, &qsig2).is_ok());
    }

    #[test]
    fn test_unhappy_paths() {
        // invalid code
        assert!(Siger::new_with_code_and_raw(None, "CESR", &[], 0, None).is_err());
    }
}
