use lazy_static::lazy_static;

use crate::core::matter::{tables as matter, Matter};
use crate::error::{err, Error, Result};

#[derive(Debug, Clone)]
pub struct Cigar {
    pub(crate) matter: Matter,
    pub(crate) verfer: Matter,
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
    pub fn new_with_code_and_raw(verfer: &Matter, code: &str, raw: &[u8]) -> Result<Cigar> {
        validate_code(code)?;
        Ok(Cigar { matter: Matter::new_with_code_and_raw(code, raw, 0)?, verfer: verfer.clone() })
    }

    pub fn new_with_qb64(verfer: &Matter, qb64: &str) -> Result<Cigar> {
        let cigar = Cigar { matter: Matter::new_with_qb64(qb64)?, verfer: verfer.clone() };
        validate_code(&cigar.matter.code)?;
        Ok(cigar)
    }

    pub fn new_with_qb64b(verfer: &Matter, qb64b: &[u8]) -> Result<Cigar> {
        let cigar = Cigar { matter: Matter::new_with_qb64b(qb64b)?, verfer: verfer.clone() };
        validate_code(&cigar.matter.code)?;
        Ok(cigar)
    }

    pub fn new_with_qb2(verfer: &Matter, qb2: &[u8]) -> Result<Cigar> {
        let cigar = Cigar { matter: Matter::new_with_qb2(qb2)?, verfer: verfer.clone() };
        validate_code(&cigar.matter.code)?;
        Ok(cigar)
    }

    pub fn code(&self) -> String {
        self.matter.code()
    }

    pub fn size(&self) -> u32 {
        self.matter.size()
    }

    pub fn raw(&self) -> Vec<u8> {
        self.matter.raw()
    }

    pub fn qb64(&self) -> Result<String> {
        self.matter.qb64()
    }

    pub fn qb64b(&self) -> Result<Vec<u8>> {
        self.matter.qb64b()
    }

    pub fn qb2(&self) -> Result<Vec<u8>> {
        self.matter.qb2()
    }

    pub fn verfer(&self) -> Matter {
        self.verfer.clone()
    }

    pub fn set_verfer(&mut self, verfer: &Matter) {
        self.verfer = verfer.clone();
    }
}

#[cfg(test)]
mod test_cigar {
    use super::{Cigar, Matter};
    use crate::core::matter::tables as matter;
    use crate::core::verfer::Verfer;

    #[test]
    fn test_new_with_code_and_raw() {
        let vcode = matter::Codex::Ed25519.code();
        let vraw = b"abcdefghijklmnopqrstuvwxyz012345";
        let verfer = <Matter as Verfer>::new_with_code_and_raw(vcode, vraw).unwrap();
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
        let verfer = <Matter as Verfer>::new_with_code_and_raw(vcode, vraw).unwrap();

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
        let verfer = <Matter as Verfer>::new_with_code_and_raw(vcode, vraw).unwrap();

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
        let verfer = <Matter as Verfer>::new_with_code_and_raw(vcode, vraw).unwrap();

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
        let verfer = <Matter as Verfer>::new_with_code_and_raw(vcode, vraw).unwrap();

        let mut cigar = Cigar::new_with_qb64(&verfer, qsig64).unwrap();

        let vcode2 = matter::Codex::Ed25519N.code();
        let vraw2 = b"abcdefghijklmnopqrstuvwxyz543210";
        let verfer2 = <Matter as Verfer>::new_with_code_and_raw(vcode2, vraw2).unwrap();

        assert_ne!(cigar.verfer().raw(), vraw2);
        cigar.set_verfer(&verfer2);
        assert_eq!(cigar.verfer().raw(), vraw2);
    }

    #[test]
    fn test_overridden_methods() {
        let qsig64 = "0BCdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd7K_H9-1298F4Id1DxvIoEmCQ";
        let vcode = matter::Codex::Ed25519.code();
        let vraw = b"abcdefghijklmnopqrstuvwxyz012345";
        let verfer = <Matter as Verfer>::new_with_code_and_raw(vcode, vraw).unwrap();

        let cigar = Cigar::new_with_qb64(&verfer, qsig64).unwrap();

        assert_eq!(cigar.code(), cigar.matter.code());
        assert_eq!(cigar.raw(), cigar.matter.raw());
        assert_eq!(cigar.size(), cigar.matter.size());
        assert_eq!(cigar.qb64().unwrap(), cigar.matter.qb64().unwrap());
        assert_eq!(cigar.qb64b().unwrap(), cigar.matter.qb64b().unwrap());
        assert_eq!(cigar.qb2().unwrap(), cigar.matter.qb2().unwrap());
    }

    #[test]
    fn test_unhappy_paths() {
        let vcode = matter::Codex::Ed25519.code();
        let vraw = b"abcdefghijklmnopqrstuvwxyz012345";
        let verfer = <Matter as Verfer>::new_with_code_and_raw(vcode, vraw).unwrap();

        assert!(Cigar::new_with_code_and_raw(&verfer, "CESR", &[]).is_err());
    }
}
