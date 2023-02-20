use crate::core::matter::{tables as matter, Matter};
use crate::crypto::sign;
use crate::error::{err, Error, Result};

#[derive(Debug, Clone, PartialEq)]
pub struct Verfer {
    pub raw: Vec<u8>,
    pub code: String,
    pub size: u32,
}

impl Default for Verfer {
    fn default() -> Self {
        Verfer { raw: vec![], code: matter::Codex::Ed25519.to_string(), size: 0 }
    }
}

fn validate_code(code: &str) -> Result<()> {
    const CODES: &[&str] = &[
        matter::Codex::Ed25519N,
        matter::Codex::Ed25519,
        matter::Codex::ECDSA_256k1N,
        matter::Codex::ECDSA_256k1,
        // matter::Codex::Ed448N,
        // matter::Codex::Ed448,
    ];

    if !CODES.contains(&code) {
        return err!(Error::UnexpectedCode(code.to_string()));
    }

    Ok(())
}

impl Verfer {
    pub fn new(
        code: Option<&str>,
        raw: Option<&[u8]>,
        qb64b: Option<&[u8]>,
        qb64: Option<&str>,
        qb2: Option<&[u8]>,
    ) -> Result<Self> {
        let code = code.unwrap_or(matter::Codex::Ed25519N);
        let verfer: Self = Matter::new(Some(code), raw, qb64b, qb64, qb2)?;
        validate_code(&verfer.code())?;
        Ok(verfer)
    }

    pub fn new_with_raw(raw: &[u8], code: Option<&str>) -> Result<Self> {
        Self::new(code, Some(raw), None, None, None)
    }

    pub fn new_with_qb64b(qb64b: &[u8]) -> Result<Self> {
        Self::new(None, None, Some(qb64b), None, None)
    }

    pub fn new_with_qb64(qb64: &str) -> Result<Self> {
        Self::new(None, None, None, Some(qb64), None)
    }

    pub fn new_with_qb2(qb2: &[u8]) -> Result<Self> {
        Self::new(None, None, None, None, Some(qb2))
    }

    pub fn verify(&self, sig: &[u8], ser: &[u8]) -> Result<bool> {
        validate_code(&self.code())?;
        sign::verify(&self.code(), &self.raw(), sig, ser)
    }
}

impl Matter for Verfer {
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
    use crate::core::matter::{tables as matter, Matter};
    use crate::core::verfer::Verfer;
    use hex_literal::hex;

    #[test]
    fn convenience() {
        let raw = &hex!("0123456789abcdef00001111222233334444555566667777888899990000aaaa");
        let code = matter::Codex::Ed25519N;

        let verfer = Verfer::new(Some(code), Some(raw), None, None, None).unwrap();

        assert!(Verfer::new_with_raw(&verfer.raw(), Some(&verfer.code())).is_ok());
        assert!(Verfer::new_with_qb64b(&verfer.qb64b().unwrap()).is_ok());
        assert!(Verfer::new_with_qb64(&verfer.qb64().unwrap()).is_ok());
        assert!(Verfer::new_with_qb2(&verfer.qb2().unwrap()).is_ok());
    }

    #[test]
    fn new() {
        let raw = &hex!("0123456789abcdef00001111222233334444555566667777888899990000aaaa");
        let code = matter::Codex::Ed25519N;

        assert!(Verfer::new(Some(code), Some(raw), None, None, None).is_ok());
    }

    #[test]
    fn new_with_code_and_raw() {
        let raw = hex!("0123456789abcdef00001111222233334444555566667777888899990000aaaa");
        let code = matter::Codex::Ed25519N;

        let m = Verfer::new(Some(code), Some(&raw), None, None, None).unwrap();
        assert_eq!(m.raw(), raw);

        let code = matter::Codex::Blake3_256;
        assert!(Verfer::new(Some(code), Some(&raw), None, None, None).is_err());
    }

    #[test]
    fn new_with_qb64() {
        let raw = hex!("0123456789abcdef00001111222233334444555566667777888899990000aaaa");

        let good_code = matter::Codex::Ed25519N;
        let good_qb64 =
            Verfer::new(Some(good_code), Some(&raw), None, None, None).unwrap().qb64().unwrap();

        let bad_code = matter::Codex::Blake3_256;
        let bad_qb64 = <Verfer as Matter>::new(Some(bad_code), Some(&raw), None, None, None)
            .unwrap()
            .qb64()
            .unwrap();

        assert!(Verfer::new(None, None, None, Some(&good_qb64), None).is_ok());
        assert!(Verfer::new(None, None, None, Some(&bad_qb64), None).is_err());
    }

    #[test]
    fn new_with_qb64b() {
        let raw = hex!("0123456789abcdef00001111222233334444555566667777888899990000aaaa");

        let good_code = matter::Codex::Ed25519N;
        let good_qb64b =
            Verfer::new(Some(good_code), Some(&raw), None, None, None).unwrap().qb64b().unwrap();

        let bad_code = matter::Codex::Blake3_256;
        let bad_qb64b = <Verfer as Matter>::new(Some(bad_code), Some(&raw), None, None, None)
            .unwrap()
            .qb64b()
            .unwrap();

        assert!(Verfer::new(None, None, Some(&good_qb64b), None, None).is_ok());
        assert!(Verfer::new(None, None, Some(&bad_qb64b), None, None).is_err());
    }

    #[test]
    fn new_with_qb2() {
        let raw = hex!("0123456789abcdef00001111222233334444555566667777888899990000aaaa");

        let good_code = matter::Codex::Ed25519N;
        let good_qb2 =
            Verfer::new(Some(good_code), Some(&raw), None, None, None).unwrap().qb2().unwrap();

        let bad_code = matter::Codex::Blake3_256;
        let bad_qb2 = <Verfer as Matter>::new(Some(bad_code), Some(&raw), None, None, None)
            .unwrap()
            .qb2()
            .unwrap();

        assert!(Verfer::new(None, None, None, None, Some(&good_qb2)).is_ok());
        assert!(Verfer::new(None, None, None, None, Some(&bad_qb2)).is_err());
    }

    #[test]
    fn verify_ed25519() {
        use ed25519_dalek::Signer;

        let ser = hex!("e1be4d7a8ab5560aa4199eea339849ba8e293d55ca0a81006726d184519e647f"
                                 "5b49b82f805a538c68915c1ae8035c900fd1d4b13902920fd05e1450822f36de");
        let bad_ser = hex!("e1be4d7a8ab5560aa4199eea339849ba8e293d55ca0a81006726d184519e647f"
                                     "5b49b82f805a538c68915c1ae8035c900fd1d4b13902920fd05e1450822f36df");

        let mut csprng = rand::rngs::OsRng::default();
        let keypair = ed25519_dalek::Keypair::generate(&mut csprng);

        let sig = keypair.sign(&ser).to_bytes();
        let mut bad_sig = sig.clone();
        bad_sig[0] ^= 0xff;

        let raw = keypair.public.as_bytes();

        let mut m = Verfer::new(Some(matter::Codex::Ed25519), Some(raw), None, None, None).unwrap();
        assert!(m.verify(&sig, &ser).unwrap());
        assert!(!m.verify(&bad_sig, &ser).unwrap());
        assert!(!m.verify(&sig, &bad_ser).unwrap());
        assert!(m.verify(&[], &ser).is_err());

        // exercise control flows for non-transferrable variant
        m.set_code(&matter::Codex::Ed25519N);
        assert!(m.verify(&sig, &ser).unwrap());
        assert!(!m.verify(&bad_sig, &ser).unwrap());
        assert!(!m.verify(&sig, &bad_ser).unwrap());
    }

    #[test]
    fn verify_ecdsa_256k1() {
        use k256::ecdsa::{signature::Signer, Signature, SigningKey, VerifyingKey};

        let ser = hex!("e1be4d7a8ab5560aa4199eea339849ba8e293d55ca0a81006726d184519e647f"
                                 "5b49b82f805a538c68915c1ae8035c900fd1d4b13902920fd05e1450822f36de");
        let bad_ser = hex!("badd");

        let mut csprng = rand_core::OsRng;
        let private_key = SigningKey::random(&mut csprng);

        let sig = <SigningKey as Signer<Signature>>::sign(&private_key, &ser).to_bytes();
        let mut bad_sig = sig.clone();
        bad_sig[0] ^= 0xff;

        let public_key = VerifyingKey::from(private_key);
        let raw = public_key.to_encoded_point(true).to_bytes();

        let mut m =
            Verfer::new(Some(matter::Codex::ECDSA_256k1), Some(&raw), None, None, None).unwrap();
        assert!(m.verify(&sig, &ser).unwrap());
        assert!(!m.verify(&bad_sig, &ser).unwrap());
        assert!(!m.verify(&sig, &bad_ser).unwrap());
        assert!(m.verify(&[], &ser).is_err());

        m.set_code(&matter::Codex::ECDSA_256k1N);
        assert!(m.verify(&sig, &ser).unwrap());
        assert!(!m.verify(&bad_sig, &ser).unwrap());
        assert!(!m.verify(&sig, &bad_ser).unwrap());
    }

    #[test]
    fn unhappy_paths() {
        assert!(Verfer { code: matter::Codex::Blake3_256.to_string(), raw: vec![], size: 0 }
            .verify(&[], &[])
            .is_err());
    }
}
