use crate::core::{
    cigar::Cigar,
    indexer::tables as indexer,
    matter::{tables as matter, Matter},
    siger::Siger,
    verfer::Verfer,
};
use crate::crypto::sign;
use crate::error::{err, Error, Result};

#[derive(Debug, Clone, PartialEq)]
pub struct Signer {
    pub raw: Vec<u8>,
    pub code: String,
    pub size: u32,
    pub verfer: Verfer,
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
    const CODES: &[&str] = &[
        matter::Codex::Ed25519_Seed,
        matter::Codex::ECDSA_256k1_Seed,
        // matter::Codex::Ed448_Seed,
    ];

    if !CODES.contains(&code) {
        return err!(Error::UnexpectedCode(code.to_string()));
    }

    Ok(())
}

fn derive_verfer(code: &str, private_key: &[u8], transferable: bool) -> Result<Verfer> {
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

    let verfer_raw = sign::public_key(code, private_key)?;
    Verfer::new(Some(verfer_code), Some(&verfer_raw), None, None, None)
}

impl Signer {
    pub fn new(
        transferable: Option<bool>,
        code: Option<&str>,
        raw: Option<&[u8]>,
        qb64b: Option<&[u8]>,
        qb64: Option<&str>,
        qb2: Option<&[u8]>,
    ) -> Result<Self> {
        let transferable = transferable.unwrap_or(true);

        let mut signer: Signer = if qb64b.is_none() && qb64.is_none() && qb2.is_none() {
            let code = code.unwrap_or(matter::Codex::Ed25519_Seed);
            validate_code(code)?;
            let raw = if let Some(raw) = raw { raw.to_vec() } else { sign::generate(code)? };
            Matter::new(Some(code), Some(&raw), None, None, None)?
        } else {
            let signer: Self = Matter::new(code, raw, qb64b, qb64, qb2)?;
            validate_code(&signer.code())?;
            signer
        };
        signer.derive_and_assign_verfer(transferable)?;

        Ok(signer)
    }

    pub fn new_with_raw(
        raw: &[u8],
        transferable: Option<bool>,
        code: Option<&str>,
    ) -> Result<Self> {
        Self::new(transferable, code, Some(raw), None, None, None)
    }

    pub fn new_with_qb64b(qb64b: &[u8]) -> Result<Self> {
        Self::new(None, None, None, Some(qb64b), None, None)
    }

    pub fn new_with_qb64(qb64: &str) -> Result<Self> {
        Self::new(None, None, None, None, Some(qb64), None)
    }

    pub fn new_with_qb2(qb2: &[u8]) -> Result<Self> {
        Self::new(None, None, None, None, None, Some(qb2))
    }

    pub fn sign_unindexed(&self, ser: &[u8]) -> Result<Cigar> {
        let code = match self.code().as_str() {
            matter::Codex::Ed25519_Seed => matter::Codex::Ed25519_Sig,
            matter::Codex::ECDSA_256k1_Seed => matter::Codex::ECDSA_256k1_Sig,
            _ => return err!(Error::UnexpectedCode(self.code())),
        };

        let sig = sign::sign(&self.code(), &self.raw(), ser)?;
        Cigar::new(Some(&self.verfer()), Some(code), Some(&sig), None, None, None)
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
                match self.code().as_str() {
                    matter::Codex::Ed25519_Seed => indexer::Codex::Ed25519_Crt,
                    matter::Codex::ECDSA_256k1_Seed => indexer::Codex::ECDSA_256k1_Crt,
                    _ => return err!(Error::UnexpectedCode(self.code())),
                }
            } else {
                match self.code().as_str() {
                    matter::Codex::Ed25519_Seed => indexer::Codex::Ed25519_Big_Crt,
                    matter::Codex::ECDSA_256k1_Seed => indexer::Codex::ECDSA_256k1_Big_Crt,
                    _ => return err!(Error::UnexpectedCode(self.code())),
                }
            };

            (code, ondex)
        } else {
            let ondex = ondex.unwrap_or(index);

            let code = if index == ondex && index < 64 {
                match self.code().as_str() {
                    matter::Codex::Ed25519_Seed => indexer::Codex::Ed25519,
                    matter::Codex::ECDSA_256k1_Seed => indexer::Codex::ECDSA_256k1,
                    _ => return err!(Error::UnexpectedCode(self.code())),
                }
            } else {
                match self.code().as_str() {
                    matter::Codex::Ed25519_Seed => indexer::Codex::Ed25519_Big,
                    matter::Codex::ECDSA_256k1_Seed => indexer::Codex::ECDSA_256k1_Big,
                    _ => return err!(Error::UnexpectedCode(self.code())),
                }
            };

            (code, Some(ondex))
        };

        let sig = sign::sign(&self.code(), &self.raw(), ser)?;
        Siger::new(None, Some(index), ondex, Some(code), Some(&sig), None, None, None)
    }

    pub fn verfer(&self) -> Verfer {
        self.verfer.clone()
    }

    fn derive_and_assign_verfer(&mut self, transferable: bool) -> Result<()> {
        self.verfer = derive_verfer(&self.code(), &self.raw(), transferable)?;
        Ok(())
    }
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
mod test {
    use crate::core::{
        indexer::{tables as indexer, Indexer},
        matter::{tables as matter, Matter},
        signer::Signer,
    };
    use rstest::rstest;

    #[test]
    fn convenience() {
        let signer = Signer::new(None, None, None, None, None, None).unwrap();

        assert!(Signer::new_with_raw(&signer.raw(), None, Some(&signer.code())).is_ok());
        assert!(Signer::new_with_qb64b(&signer.qb64b().unwrap()).is_ok());
        assert!(Signer::new_with_qb64(&signer.qb64().unwrap()).is_ok());
        assert!(Signer::new_with_qb2(&signer.qb2().unwrap()).is_ok());
    }

    #[test]
    fn new() {
        let signer = Signer::new(None, None, None, None, None, None).unwrap();
        assert!(Signer::new(None, None, None, None, Some(&signer.qb64().unwrap()), None).is_ok());
    }

    #[rstest]
    fn conversions(
        #[values(matter::Codex::Ed25519_Seed, matter::Codex::ECDSA_256k1_Seed)] code: &str,
    ) {
        let signer = Signer::new(Some(false), Some(code), None, None, None, None).unwrap();

        assert!(
            Signer::new(Some(true), None, None, Some(&signer.qb64b().unwrap()), None, None).is_ok()
        );
        assert!(
            Signer::new(Some(true), None, None, None, Some(&signer.qb64().unwrap()), None).is_ok()
        );
        assert!(
            Signer::new(Some(true), None, None, None, None, Some(&signer.qb2().unwrap())).is_ok()
        );
    }

    #[test]
    fn sign_ed25519_unindexed() {
        use rand_core::CryptoRngCore;

        let ser = b"abcdefghijklmnopqrstuvwxyz0123456789";
        let bad_ser = b"abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG";

        let mut seed: [u8; 32] = [0; 32];
        let mut csprng = rand_core::OsRng {};
        // one can use any 32 octet value for an ed25519 key
        csprng.as_rngcore().fill_bytes(&mut seed);

        let signer = Signer::new(
            Some(true),
            Some(matter::Codex::Ed25519_Seed),
            Some(&seed),
            None,
            None,
            None,
        )
        .unwrap();

        let cigar = signer.sign_unindexed(ser).unwrap();
        assert_eq!(cigar.code(), matter::Codex::Ed25519_Sig);
        assert!(signer.verfer().verify(&cigar.raw(), ser).unwrap());
        assert!(!signer.verfer().verify(&cigar.raw(), bad_ser).unwrap());
    }

    #[test]
    fn sign_ecdsa_256k1_unindexed() {
        let ser = b"abcdefghijklmnopqrstuvwxyz0123456789";
        let bad_ser = b"abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG";

        let signer =
            Signer::new(Some(true), Some(matter::Codex::ECDSA_256k1_Seed), None, None, None, None)
                .unwrap();

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
    fn sign_ed25519_indexed(
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

        let signer = Signer::new(
            Some(true),
            Some(matter::Codex::Ed25519_Seed),
            Some(&seed),
            None,
            None,
            None,
        )
        .unwrap();

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
    fn sign_ecdsa_256k1_indexed(
        #[case] only: bool,
        #[case] index: u32,
        #[case] input_ondex: Option<u32>,
        #[case] output_ondex: u32,
        #[case] siger_code: &str,
    ) {
        let ser = b"abcdefghijklmnopqrstuvwxyz0123456789";
        let bad_ser = b"abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG";

        let signer =
            Signer::new(Some(true), Some(matter::Codex::ECDSA_256k1_Seed), None, None, None, None)
                .unwrap();

        let siger = signer.sign_indexed(ser, only, index, input_ondex).unwrap();
        assert_eq!(siger.code(), siger_code);
        assert_eq!(siger.index(), index);
        assert_eq!(siger.ondex(), output_ondex);
        assert!(signer.verfer().verify(&siger.raw(), ser).unwrap());
        assert!(!signer.verfer().verify(&siger.raw(), bad_ser).unwrap());
    }

    #[test]
    fn unhappy_paths() {
        let raw: [u8; 32] = [0; 32];
        assert!(Signer::new(
            Some(false),
            Some(matter::Codex::Ed25519N),
            Some(&raw),
            None,
            None,
            None
        )
        .is_err());
        assert!(Signer::new(Some(false), Some(matter::Codex::Ed25519N), None, None, None, None)
            .is_err());
    }
}
