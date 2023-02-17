use lazy_static::lazy_static;

use crate::core::{
    cigar::Cigar,
    indexer::{tables as indexer, Indexer},
    matter::{tables as matter, Matter},
    siger::Siger,
    verfer::Verfer,
};
use crate::error::{err, Error, Result};

#[derive(Debug, Clone, PartialEq)]
pub struct Signer {
    raw: Vec<u8>,
    code: String,
    size: u32,
    verfer: Verfer,
}

impl Default for Signer {
    fn default() -> Self {
        Signer {
            raw: vec![],
            code: matter::Codex::Ed25519_Seed.to_string(),
            size: 0,
            verfer: Verfer::default(),
        }
    }
}

fn validate_code(code: &str) -> Result<()> {
    lazy_static! {
        static ref CODES: Vec<&'static str> = vec![
            matter::Codex::Ed25519_Seed,
            matter::Codex::ECDSA_256k1_Seed,
            // matter::Codex::Ed448_Seed,
        ];
    }

    if !CODES.contains(&code) {
        return err!(Error::UnexpectedCode(code.to_string()));
    }

    Ok(())
}

impl Signer {
    pub fn new_with_code_and_raw(code: &str, raw: &[u8], transferable: bool) -> Result<Self> {
        validate_code(code)?;

        let raw = if raw.is_empty() { generate_seed(code)? } else { raw.to_vec() };

        let mut signer: Signer = Matter::new_with_code_and_raw(code, &raw)?;
        signer.derive_verfer(transferable)?;
        Ok(signer)
    }

    pub fn new_with_qb64(qb64: &str, transferable: bool) -> Result<Self> {
        let mut signer: Signer = Matter::new_with_qb64(qb64)?;
        validate_code(&signer.code)?;
        signer.derive_verfer(transferable)?;
        Ok(signer)
    }

    pub fn new_with_qb64b(qb64b: &[u8], transferable: bool) -> Result<Self> {
        let mut signer: Signer = Matter::new_with_qb64b(qb64b)?;
        validate_code(&signer.code)?;
        signer.derive_verfer(transferable)?;
        Ok(signer)
    }

    pub fn new_with_qb2(qb2: &[u8], transferable: bool) -> Result<Self> {
        let mut signer: Signer = Matter::new_with_qb2(qb2)?;
        validate_code(&signer.code)?;
        signer.derive_verfer(transferable)?;
        Ok(signer)
    }

    fn derive_verfer(&mut self, transferable: bool) -> Result<()> {
        self.verfer = derive_verfer(&self.code, &self.raw, transferable)?;
        Ok(())
    }

    pub fn verfer(&self) -> Verfer {
        self.verfer.clone()
    }

    pub fn sign_unindexed(&self, ser: &[u8]) -> Result<Cigar> {
        let code = self.code();
        match code.as_str() {
            matter::Codex::Ed25519_Seed => {
                let sig = self.sign_ed25519(ser)?;
                Cigar::new_with_code_and_raw(&self.verfer(), matter::Codex::Ed25519_Sig, &sig)
            }
            matter::Codex::ECDSA_256k1_Seed => {
                let sig = self.sign_ecdsa_256k1(ser)?;
                Cigar::new_with_code_and_raw(&self.verfer(), matter::Codex::ECDSA_256k1_Sig, &sig)
            }
            _ => err!(Error::UnexpectedCode(code)),
        }
    }

    pub fn sign_indexed(
        &self,
        ser: &[u8],
        only: bool,
        index: u32,
        ondex: Option<u32>,
    ) -> Result<Siger> {
        let (code, ondex) = if only {
            let ondex = None;
            let code = if index < 64 {
                match self.code.as_str() {
                    matter::Codex::Ed25519_Seed => indexer::Codex::Ed25519_Crt,
                    matter::Codex::ECDSA_256k1_Seed => indexer::Codex::ECDSA_256k1_Crt,
                    _ => {
                        return err!(Error::UnexpectedCode(self.code()));
                    }
                }
            } else {
                match self.code.as_str() {
                    matter::Codex::Ed25519_Seed => indexer::Codex::Ed25519_Big_Crt,
                    matter::Codex::ECDSA_256k1_Seed => indexer::Codex::ECDSA_256k1_Big_Crt,
                    _ => {
                        return err!(Error::UnexpectedCode(self.code()));
                    }
                }
            };

            (code, ondex)
        } else {
            let ondex = if let Some(ondex) = ondex { ondex } else { index };

            let code = if index == ondex && index < 64 {
                match self.code.as_str() {
                    matter::Codex::Ed25519_Seed => indexer::Codex::Ed25519,
                    matter::Codex::ECDSA_256k1_Seed => indexer::Codex::ECDSA_256k1,
                    _ => {
                        return err!(Error::UnexpectedCode(self.code()));
                    }
                }
            } else {
                match self.code.as_str() {
                    matter::Codex::Ed25519_Seed => indexer::Codex::Ed25519_Big,
                    matter::Codex::ECDSA_256k1_Seed => indexer::Codex::ECDSA_256k1_Big,
                    _ => {
                        return err!(Error::UnexpectedCode(self.code()));
                    }
                }
            };

            (code, Some(ondex))
        };

        let sig = match self.code.as_str() {
            matter::Codex::Ed25519_Seed => self.sign_ed25519(ser)?,
            matter::Codex::ECDSA_256k1_Seed => self.sign_ecdsa_256k1(ser)?,
            _ => {
                return err!(Error::UnexpectedCode(self.code()));
            }
        };

        Siger::new_with_code_and_raw(code, &sig, index, ondex)
    }

    fn sign_ed25519(&self, ser: &[u8]) -> Result<Vec<u8>> {
        use ed25519_dalek::{ed25519::signature::Signer, Keypair, PublicKey, SecretKey};

        let private_key = SecretKey::from_bytes(&self.raw)?;
        let public_key: PublicKey = (&private_key).into();
        Ok(Keypair { secret: private_key, public: public_key }.sign(ser).to_bytes().to_vec())
    }

    fn sign_ecdsa_256k1(&self, ser: &[u8]) -> Result<Vec<u8>> {
        use k256::ecdsa::{signature::Signer, Signature, SigningKey};

        let private_key = SigningKey::from_bytes(&self.raw)?;
        Ok(<SigningKey as Signer<Signature>>::sign(&private_key, ser).to_bytes().to_vec())
    }
}

fn generate_seed(code: &str) -> Result<Vec<u8>> {
    match code {
        matter::Codex::Ed25519_Seed => {
            use ed25519_dalek::SecretKey;
            use rand::rngs::OsRng;

            let mut csprng = OsRng {};
            let private_key: SecretKey = SecretKey::generate(&mut csprng);
            Ok(private_key.as_bytes().to_vec())
        }
        matter::Codex::ECDSA_256k1_Seed => {
            use k256::ecdsa::SigningKey;
            use rand_core::OsRng;

            let mut csprng = OsRng {};
            let private_key = SigningKey::random(&mut csprng);

            Ok(private_key.to_bytes().to_vec())
        }
        _ => err!(Error::UnexpectedCode(code.to_string())),
    }
}

fn derive_verifying_key(code: &str, private_key_bytes: &[u8]) -> Result<Vec<u8>> {
    match code {
        matter::Codex::Ed25519_Seed => {
            use ed25519_dalek::{PublicKey, SecretKey};

            let private_key = SecretKey::from_bytes(private_key_bytes)?;
            let public_key: PublicKey = (&private_key).into();
            Ok(public_key.as_bytes().to_vec())
        }
        matter::Codex::ECDSA_256k1_Seed => {
            use k256::ecdsa::{SigningKey, VerifyingKey};

            let private_key = SigningKey::from_bytes(private_key_bytes)?;
            let public_key = VerifyingKey::from(private_key);

            Ok(public_key.to_encoded_point(true).as_bytes().to_vec())
        }
        _ => err!(Error::UnexpectedCode(code.to_string())),
    }
}

fn derive_verfer(code: &str, private_key_bytes: &[u8], transferable: bool) -> Result<Verfer> {
    let verfer_raw = derive_verifying_key(code, private_key_bytes)?;
    let verfer_code = match transferable {
        true => match code {
            matter::Codex::Ed25519_Seed => matter::Codex::Ed25519,
            matter::Codex::ECDSA_256k1_Seed => matter::Codex::ECDSA_256k1,
            _ => return err!(Error::UnexpectedCode(code.to_string())),
        },
        false => match code {
            matter::Codex::Ed25519_Seed => matter::Codex::Ed25519N,
            matter::Codex::ECDSA_256k1_Seed => matter::Codex::ECDSA_256k1N,
            _ => return err!(Error::UnexpectedCode(code.to_string())),
        },
    };

    Verfer::new_with_code_and_raw(verfer_code, &verfer_raw)
}

impl Matter for Signer {
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
mod test_signer {
    use super::{indexer, matter, Indexer, Matter, Signer};
    use rstest::rstest;

    #[test]
    fn test_conversions() {
        let signer =
            Signer::new_with_code_and_raw(matter::Codex::Ed25519_Seed, &[], false).unwrap();

        assert!(Signer::new_with_qb2(&signer.qb2().unwrap(), true).is_ok());
        assert!(Signer::new_with_qb64(&signer.qb64().unwrap(), true).is_ok());
        assert!(Signer::new_with_qb64b(&signer.qb64b().unwrap(), true).is_ok());

        let signer =
            Signer::new_with_code_and_raw(matter::Codex::ECDSA_256k1_Seed, &[], false).unwrap();

        assert!(Signer::new_with_qb2(&signer.qb2().unwrap(), true).is_ok());
        assert!(Signer::new_with_qb64(&signer.qb64().unwrap(), true).is_ok());
        assert!(Signer::new_with_qb64b(&signer.qb64b().unwrap(), true).is_ok());
    }

    #[test]
    fn test_sign_ed25519_unindexed() {
        use rand_core::CryptoRngCore;

        let ser = b"abcdefghijklmnopqrstuvwxyz0123456789";
        let bad_ser = b"abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG";

        let mut seed: [u8; 32] = [0; 32];
        let mut csprng = rand_core::OsRng {};
        csprng.as_rngcore().fill_bytes(&mut seed);

        let signer =
            Signer::new_with_code_and_raw(matter::Codex::Ed25519_Seed, &seed, true).unwrap();

        let cigar = signer.sign_unindexed(ser).unwrap();
        assert_eq!(cigar.code(), matter::Codex::Ed25519_Sig);
        assert!(signer.verfer().verify(&cigar.raw(), ser).unwrap());
        assert!(!signer.verfer().verify(&cigar.raw(), bad_ser).unwrap());
    }

    #[test]
    fn test_sign_ecdsa_256k1_unindexed() {
        let ser = b"abcdefghijklmnopqrstuvwxyz0123456789";
        let bad_ser = b"abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG";

        let signer =
            Signer::new_with_code_and_raw(matter::Codex::ECDSA_256k1_Seed, &[], true).unwrap();

        let cigar = signer.sign_unindexed(ser).unwrap();
        assert_eq!(cigar.code(), matter::Codex::ECDSA_256k1_Sig);
        assert!(signer.verfer().verify(&cigar.raw(), ser).unwrap());
        assert!(!signer.verfer().verify(&cigar.raw(), bad_ser).unwrap());
    }

    #[rstest]
    #[case(false, 0, None, 0, indexer::Codex::Ed25519)]
    #[case(false, 1, None, 1, indexer::Codex::Ed25519)]
    #[case(false, 1, Some(3), 3, indexer::Codex::Ed25519_Big)]
    #[case(false, 67, Some(3), 3, indexer::Codex::Ed25519_Big)]
    #[case(false, 67, Some(67), 67, indexer::Codex::Ed25519_Big)]
    #[case(true, 4, None, 0, indexer::Codex::Ed25519_Crt)]
    #[case(true, 4, Some(6), 0, indexer::Codex::Ed25519_Crt)]
    #[case(true, 65, None, 0, indexer::Codex::Ed25519_Big_Crt)]
    #[case(true, 65, Some(67), 0, indexer::Codex::Ed25519_Big_Crt)]
    fn test_sign_ed25519_indexed(
        #[case] only: bool,
        #[case] index: u32,
        #[case] input_ondex: Option<u32>,
        #[case] output_ondex: u32,
        #[case] siger_code: &str,
    ) {
        use rand_core::CryptoRngCore;

        let ser = b"abcdefghijklmnopqrstuvwxyz0123456789";
        let bad_ser = b"abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG";

        let mut seed: [u8; 32] = [0; 32];
        let mut csprng = rand_core::OsRng {};
        csprng.as_rngcore().fill_bytes(&mut seed);

        let signer =
            Signer::new_with_code_and_raw(matter::Codex::Ed25519_Seed, &seed, true).unwrap();

        let siger = signer.sign_indexed(ser, only, index, input_ondex).unwrap();
        assert_eq!(siger.code(), siger_code);
        assert_eq!(siger.index(), index);
        assert_eq!(siger.ondex(), output_ondex);
        assert!(signer.verfer().verify(&siger.raw(), ser).unwrap());
        assert!(!signer.verfer().verify(&siger.raw(), bad_ser).unwrap());
    }

    #[rstest]
    #[case(false, 0, None, 0, indexer::Codex::ECDSA_256k1)]
    #[case(false, 1, None, 1, indexer::Codex::ECDSA_256k1)]
    #[case(false, 1, Some(3), 3, indexer::Codex::ECDSA_256k1_Big)]
    #[case(false, 67, Some(3), 3, indexer::Codex::ECDSA_256k1_Big)]
    #[case(false, 67, Some(67), 67, indexer::Codex::ECDSA_256k1_Big)]
    #[case(true, 4, None, 0, indexer::Codex::ECDSA_256k1_Crt)]
    #[case(true, 4, Some(6), 0, indexer::Codex::ECDSA_256k1_Crt)]
    #[case(true, 65, None, 0, indexer::Codex::ECDSA_256k1_Big_Crt)]
    #[case(true, 65, Some(67), 0, indexer::Codex::ECDSA_256k1_Big_Crt)]
    fn test_sign_ecdsa_256k1_indexed(
        #[case] only: bool,
        #[case] index: u32,
        #[case] input_ondex: Option<u32>,
        #[case] output_ondex: u32,
        #[case] siger_code: &str,
    ) {
        let ser = b"abcdefghijklmnopqrstuvwxyz0123456789";
        let bad_ser = b"abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG";

        let signer =
            Signer::new_with_code_and_raw(matter::Codex::ECDSA_256k1_Seed, &[], true).unwrap();

        let siger = signer.sign_indexed(ser, only, index, input_ondex).unwrap();
        assert_eq!(siger.code(), siger_code);
        assert_eq!(siger.index(), index);
        assert_eq!(siger.ondex(), output_ondex);
        assert!(signer.verfer().verify(&siger.raw(), ser).unwrap());
        assert!(!signer.verfer().verify(&siger.raw(), bad_ser).unwrap());
    }

    #[test]
    fn test_unhappy_paths() {
        let raw: [u8; 32] = [0; 32];
        assert!(Signer::new_with_code_and_raw(matter::Codex::Ed25519N, &raw, false).is_err());
        assert!(Signer::new_with_code_and_raw(matter::Codex::Ed25519N, &[], false).is_err());
    }
}
