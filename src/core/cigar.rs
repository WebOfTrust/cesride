use lazy_static::lazy_static;

use crate::core::matter::{tables as matter, Matter};
use crate::core::verfer::Verfer;
use crate::error::{err, Error, Result};

#[derive(Debug, Clone)]
pub struct Cigar {
    raw: Vec<u8>,
    code: String,
    size: u32,
    verfer: Verfer,
}

impl Default for Cigar {
    fn default() -> Self {
        Cigar {
            raw: vec![],
            code: matter::Codex::Ed25519_Sig.code().to_string(),
            size: 0,
            verfer: Verfer::default(),
        }
    }
}

fn validate_code(code: &str) -> Result<()> {
    lazy_static! {
        static ref CODES: Vec<&'static str> = vec![
            matter::Codex::Ed25519_Sig.code(),
            matter::Codex::ECDSA_256k1_Sig.code(),
            // matter::Codex::Ed448_Sig.code(),
        ];
    }

    if !CODES.contains(&code) {
        return err!(Error::UnexpectedCode(code.to_string()));
    }

    Ok(())
}

impl Cigar {
    pub fn new_with_code_and_raw(verfer: &Verfer, code: &str, raw: &[u8]) -> Result<Cigar> {
        validate_code(code)?;
        let mut cigar: Cigar = Matter::new_with_code_and_raw(code, raw)?;
        cigar.set_verfer(verfer);
        Ok(cigar)
    }

    pub fn new_with_qb64(verfer: &Verfer, qb64: &str) -> Result<Cigar> {
        let mut cigar: Cigar = Matter::new_with_qb64(qb64)?;
        cigar.set_verfer(verfer);
        validate_code(&cigar.code())?;
        Ok(cigar)
    }

    pub fn new_with_qb64b(verfer: &Verfer, qb64b: &[u8]) -> Result<Cigar> {
        let mut cigar: Cigar = Matter::new_with_qb64b(qb64b)?;
        cigar.set_verfer(verfer);
        validate_code(&cigar.code())?;
        Ok(cigar)
    }

    pub fn new_with_qb2(verfer: &Verfer, qb2: &[u8]) -> Result<Cigar> {
        let mut cigar: Cigar = Matter::new_with_qb2(qb2)?;
        cigar.set_verfer(verfer);
        validate_code(&cigar.code())?;
        Ok(cigar)
    }

    pub fn verfer(&self) -> Verfer {
        self.verfer.clone()
    }

    pub fn set_verfer(&mut self, verfer: &Verfer) {
        self.verfer = verfer.clone()
    }
}

impl Matter for Cigar {
    fn code(&self) -> String {
        self.code.clone()
    }

    fn raw(&self) -> Vec<u8> {
        self.raw.clone()
    }

    fn size(&self) -> u32 {
        self.size
    }

    fn set_code(&mut self, code: &str) {
        self.code = code.to_string();
    }

    fn set_raw(&mut self, raw: &[u8]) {
        self.raw = raw.to_vec();
    }

    fn set_size(&mut self, size: u32) {
        self.size = size;
    }
}

#[cfg(test)]
mod test_cigar {
    use crate::core::cigar::Cigar;
    use crate::core::matter::{tables as matter, Matter};
    use crate::core::verfer::Verfer;

    #[test]
    fn test_new_with_code_and_raw() {
        let vcode = matter::Codex::Ed25519.code();
        let vraw = b"abcdefghijklmnopqrstuvwxyz012345";
        let verfer = Verfer::new_with_code_and_raw(vcode, vraw).unwrap();
        let code = matter::Codex::Ed25519_Sig.code();
        let raw = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ[]";

        let cigar = Cigar::new_with_code_and_raw(&verfer, code, raw).unwrap();
        assert_eq!(cigar.code(), code);
        assert_eq!(cigar.raw(), raw);
        assert_eq!(cigar.verfer().raw(), verfer.raw());
        assert_eq!(cigar.verfer().code(), verfer.code());
    }

    // this test was ported from KERIpy
    #[test]
    fn test_new_with_qb64() {
        let qsig64 = "0BCdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd7K_H9-1298F4Id1DxvIoEmCQ";
        let vcode = matter::Codex::Ed25519.code();
        let vraw = b"abcdefghijklmnopqrstuvwxyz012345";
        let verfer = Verfer::new_with_code_and_raw(vcode, vraw).unwrap();

        let cigar = Cigar::new_with_qb64(&verfer, qsig64).unwrap();

        // this is probably the most critical line (the previous is obviously important too)
        assert_eq!(cigar.code(), matter::Codex::Ed25519_Sig.code());
        assert_eq!(cigar.qb64().unwrap(), qsig64);
        assert_eq!(cigar.verfer().raw(), verfer.raw());
        assert_eq!(cigar.verfer().code(), verfer.code());
    }

    #[test]
    fn test_new_with_qb64b() {
        let qsig64b = "0BCdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd7K_H9-1298F4Id1DxvIoEmCQ".as_bytes();
        let vcode = matter::Codex::Ed25519.code();
        let vraw = b"abcdefghijklmnopqrstuvwxyz012345";
        let verfer = Verfer::new_with_code_and_raw(vcode, vraw).unwrap();

        let cigar = Cigar::new_with_qb64b(&verfer, qsig64b).unwrap();

        // this is probably the most critical line (the previous is obviously important too)
        assert_eq!(cigar.code(), matter::Codex::Ed25519_Sig.code());
        assert_eq!(cigar.qb64b().unwrap(), qsig64b);
        assert_eq!(cigar.verfer().raw(), verfer.raw());
        assert_eq!(cigar.verfer().code(), verfer.code());
    }

    #[test]
    fn test_new_with_qb2() {
        let qb2 = [
            208, 16, 157, 35, 195, 146, 66, 67, 9, 246, 191, 177, 138, 8, 196, 7, 33, 35, 34, 230,
            187, 44, 113, 247, 0, 226, 118, 216, 244, 10, 170, 88, 204, 134, 232, 92, 130, 31, 103,
            25, 23, 10, 158, 204, 249, 42, 242, 157, 236, 175, 199, 247, 237, 118, 247, 193, 120,
            33, 221, 67, 198, 242, 40, 18, 96, 144,
        ];
        let vcode = matter::Codex::Ed25519.code();
        let vraw = b"abcdefghijklmnopqrstuvwxyz012345";
        let verfer = Verfer::new_with_code_and_raw(vcode, vraw).unwrap();

        let cigar = Cigar::new_with_qb2(&verfer, &qb2).unwrap();

        // this is probably the most critical line (the previous is obviously important too)
        assert_eq!(cigar.code(), matter::Codex::Ed25519_Sig.code());
        assert_eq!(cigar.qb2().unwrap(), qb2);
        assert_eq!(cigar.verfer().raw(), verfer.raw());
        assert_eq!(cigar.verfer().code(), verfer.code());
    }

    #[test]
    fn test_set_verfer() {
        let qsig64 = "0BCdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd7K_H9-1298F4Id1DxvIoEmCQ";
        let vcode = matter::Codex::Ed25519.code();
        let vraw = b"abcdefghijklmnopqrstuvwxyz012345";
        let verfer = Verfer::new_with_code_and_raw(vcode, vraw).unwrap();

        let mut cigar = Cigar::new_with_qb64(&verfer, qsig64).unwrap();

        let vcode2 = matter::Codex::Ed25519N.code();
        let vraw2 = b"abcdefghijklmnopqrstuvwxyz543210";
        let verfer2 = Verfer::new_with_code_and_raw(vcode2, vraw2).unwrap();

        assert_ne!(cigar.verfer().raw(), vraw2);
        cigar.set_verfer(&verfer2);
        assert_eq!(cigar.verfer().raw(), vraw2);
    }

    #[test]
    fn test_unhappy_paths() {
        let vcode = matter::Codex::Ed25519.code();
        let vraw = b"abcdefghijklmnopqrstuvwxyz012345";
        let verfer = Verfer::new_with_code_and_raw(vcode, vraw).unwrap();

        assert!(Cigar::new_with_code_and_raw(&verfer, "CESR", &[]).is_err());
    }
}
