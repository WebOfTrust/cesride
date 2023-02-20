use crate::core::matter::{tables as matter, Matter};
use crate::core::verfer::Verfer;
use crate::error::{err, Error, Result};

//  FIXME: writing uniffi bindings forced me to make fields public but it will be better to hid them
#[derive(Debug, Clone, PartialEq)]
pub struct Cigar {
    pub raw: Vec<u8>,
    pub code: String,
    pub size: u32,
    pub verfer: Verfer,
}

impl Default for Cigar {
    fn default() -> Self {
        Cigar {
            raw: vec![],
            code: matter::Codex::Ed25519_Sig.to_string(),
            size: 0,
            verfer: Verfer::default(),
        }
    }
}

fn validate_code(code: &str) -> Result<()> {
    const CODES: &[&str] = &[
        matter::Codex::Ed25519_Sig,
        matter::Codex::ECDSA_256k1_Sig,
        // matter::Codex::Ed448_Sig,
    ];

    if !CODES.contains(&code) {
        return err!(Error::UnexpectedCode(code.to_string()));
    }

    Ok(())
}

impl Cigar {
    pub fn new(
        verfer: Option<&Verfer>,
        code: Option<&str>,
        raw: Option<&[u8]>,
        qb64b: Option<&[u8]>,
        qb64: Option<&str>,
        qb2: Option<&[u8]>,
    ) -> Result<Self> {
        let mut cigar: Self = Matter::new(code, raw, qb64b, qb64, qb2)?;
        if let Some(verfer) = verfer {
            cigar.set_verfer(verfer);
        }
        validate_code(&cigar.code())?;
        Ok(cigar)
    }

    pub fn new_with_raw(raw: &[u8], verfer: Option<&Verfer>, code: Option<&str>) -> Result<Self> {
        Self::new(verfer, code, Some(raw), None, None, None)
    }

    pub fn new_with_qb64b(qb64b: &[u8], verfer: Option<&Verfer>) -> Result<Self> {
        Self::new(verfer, None, None, Some(qb64b), None, None)
    }

    pub fn new_with_qb64(qb64: &str, verfer: Option<&Verfer>) -> Result<Self> {
        Self::new(verfer, None, None, None, Some(qb64), None)
    }

    pub fn new_with_qb2(qb2: &[u8], verfer: Option<&Verfer>) -> Result<Self> {
        Self::new(verfer, None, None, None, None, Some(qb2))
    }

    pub fn verfer(&self) -> Verfer {
        self.verfer.clone()
    }

    fn set_verfer(&mut self, verfer: &Verfer) {
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
mod test {
    use crate::core::cigar::Cigar;
    use crate::core::matter::{tables as matter, Matter};
    use crate::core::verfer::Verfer;

    #[test]
    fn convenience() {
        let vcode = matter::Codex::Ed25519;
        let vraw = b"abcdefghijklmnopqrstuvwxyz012345";
        let verfer = Verfer::new(Some(vcode), Some(vraw), None, None, None).unwrap();
        let code = matter::Codex::Ed25519_Sig;
        let raw = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ[]";

        let cigar = Cigar::new(Some(&verfer), Some(code), Some(raw), None, None, None).unwrap();

        assert!(Cigar::new_with_raw(&cigar.raw(), Some(&verfer), Some(&cigar.code())).is_ok());
        assert!(Cigar::new_with_qb64b(&cigar.qb64b().unwrap(), Some(&verfer)).is_ok());
        assert!(Cigar::new_with_qb64(&cigar.qb64().unwrap(), Some(&verfer)).is_ok());
        assert!(Cigar::new_with_qb2(&cigar.qb2().unwrap(), Some(&verfer)).is_ok());
    }

    #[test]
    fn new() {
        let vcode = matter::Codex::Ed25519;
        let vraw = b"abcdefghijklmnopqrstuvwxyz012345";
        let verfer = Verfer::new(Some(vcode), Some(vraw), None, None, None).unwrap();
        let code = matter::Codex::Ed25519_Sig;
        let raw = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ[]";

        assert!(Cigar::new(Some(&verfer), Some(code), Some(raw), None, None, None,).is_ok());
        assert!(Cigar::new(None, Some(code), Some(raw), None, None, None,).is_ok());
    }

    #[test]
    fn new_with_code_and_raw() {
        let vcode = matter::Codex::Ed25519;
        let vraw = b"abcdefghijklmnopqrstuvwxyz012345";
        let verfer = Verfer::new(Some(vcode), Some(vraw), None, None, None).unwrap();
        let code = matter::Codex::Ed25519_Sig;
        let raw = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ[]";

        let cigar = Cigar::new(Some(&verfer), Some(code), Some(raw), None, None, None).unwrap();
        assert_eq!(cigar.code(), code);
        assert_eq!(cigar.raw(), raw);
        assert_eq!(cigar.verfer().raw(), verfer.raw());
        assert_eq!(cigar.verfer().code(), verfer.code());
    }

    #[test]
    fn new_with_qb64() {
        let qsig64 = "0BCdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd7K_H9-1298F4Id1DxvIoEmCQ";
        let vcode = matter::Codex::Ed25519;
        let vraw = b"abcdefghijklmnopqrstuvwxyz012345";
        let verfer = Verfer::new(Some(vcode), Some(vraw), None, None, None).unwrap();

        let cigar = Cigar::new(Some(&verfer), None, None, None, Some(qsig64), None).unwrap();

        assert_eq!(cigar.code(), matter::Codex::Ed25519_Sig);
        assert_eq!(cigar.qb64().unwrap(), qsig64);
        assert_eq!(cigar.verfer().raw(), verfer.raw());
        assert_eq!(cigar.verfer().code(), verfer.code());
    }

    #[test]
    fn new_with_qb64b() {
        let qsig64b = "0BCdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd7K_H9-1298F4Id1DxvIoEmCQ".as_bytes();
        let vcode = matter::Codex::Ed25519;
        let vraw = b"abcdefghijklmnopqrstuvwxyz012345";
        let verfer = Verfer::new(Some(vcode), Some(vraw), None, None, None).unwrap();

        let cigar = Cigar::new(Some(&verfer), None, None, Some(qsig64b), None, None).unwrap();

        assert_eq!(cigar.code(), matter::Codex::Ed25519_Sig);
        assert_eq!(cigar.qb64b().unwrap(), qsig64b);
        assert_eq!(cigar.verfer().raw(), verfer.raw());
        assert_eq!(cigar.verfer().code(), verfer.code());
    }

    #[test]
    fn new_with_qb2() {
        let qb2 = [
            208, 16, 157, 35, 195, 146, 66, 67, 9, 246, 191, 177, 138, 8, 196, 7, 33, 35, 34, 230,
            187, 44, 113, 247, 0, 226, 118, 216, 244, 10, 170, 88, 204, 134, 232, 92, 130, 31, 103,
            25, 23, 10, 158, 204, 249, 42, 242, 157, 236, 175, 199, 247, 237, 118, 247, 193, 120,
            33, 221, 67, 198, 242, 40, 18, 96, 144,
        ];
        let vcode = matter::Codex::Ed25519;
        let vraw = b"abcdefghijklmnopqrstuvwxyz012345";
        let verfer = Verfer::new(Some(vcode), Some(vraw), None, None, None).unwrap();

        let cigar = Cigar::new(Some(&verfer), None, None, None, None, Some(&qb2)).unwrap();

        // this is probably the most critical line (the previous is obviously important too)
        assert_eq!(cigar.code(), matter::Codex::Ed25519_Sig);
        assert_eq!(cigar.qb2().unwrap(), qb2);
        assert_eq!(cigar.verfer().raw(), verfer.raw());
        assert_eq!(cigar.verfer().code(), verfer.code());
    }

    #[test]
    fn set_verfer() {
        let qsig64 = "0BCdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd7K_H9-1298F4Id1DxvIoEmCQ";
        let vcode = matter::Codex::Ed25519;
        let vraw = b"abcdefghijklmnopqrstuvwxyz012345";
        let verfer = Verfer::new(Some(vcode), Some(vraw), None, None, None).unwrap();

        let mut cigar = Cigar::new(Some(&verfer), None, None, None, Some(qsig64), None).unwrap();

        let vcode2 = matter::Codex::Ed25519N;
        let vraw2 = b"abcdefghijklmnopqrstuvwxyz543210";
        let verfer2 = Verfer::new(Some(vcode2), Some(vraw2), None, None, None).unwrap();

        assert_ne!(cigar.verfer().raw(), vraw2);
        cigar.set_verfer(&verfer2);
        assert_eq!(cigar.verfer().raw(), vraw2);
    }

    #[test]
    fn unhappy_paths() {
        let vcode = matter::Codex::Ed25519;
        let vraw = b"abcdefghijklmnopqrstuvwxyz012345";
        let verfer = Verfer::new(Some(vcode), Some(vraw), None, None, None).unwrap();

        assert!(Cigar::new(Some(&verfer), Some("CESR"), Some(&[]), None, None, None,).is_err());
    }
}
