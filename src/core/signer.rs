use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::core::{
    cigar::Cigar,
    indexer::tables as indexer,
    matter::{tables as matter, Matter},
    siger::Siger,
    verfer::Verfer,
};
use crate::crypto::sign;
use crate::error::{err, Error, Result};

/// ```rust
/// use cesride::{Signer, Indexer, Matter};
/// use std::error::Error;
/// // here we verify that a cigar primitive and a siger primitive have the same underlying
/// // cryptographic material
///
/// fn example() -> Result<(), Box<dyn Error>> {
///     let data = b"abcdefg";
///
///     // defaults to Ed25519
///     let signer = Signer::new_with_defaults(None, None)?;
///
///     // create our signatures
///     let cigar = signer.sign_unindexed(data)?;
///     let siger = signer.sign_indexed(data, false, 0, None)?;
///
///     // compare the raw signatures
///     assert_eq!(cigar.raw(), siger.raw());
///
///     Ok(())
/// }
///
/// example().unwrap();
/// ```
#[derive(Debug, Clone, PartialEq, ZeroizeOnDrop)]
pub struct Signer {
    raw: Vec<u8>,
    #[zeroize(skip)]
    code: String,
    #[zeroize(skip)]
    size: u32,
    #[zeroize(skip)]
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
    const CODES: &[&str] = &[
        matter::Codex::Ed25519_Seed,
        matter::Codex::ECDSA_256k1_Seed,
        matter::Codex::ECDSA_256r1_Seed,
        matter::Codex::CRYSTALS_Dilithium3_Seed,
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
            matter::Codex::ECDSA_256r1_Seed => matter::Codex::ECDSA_256r1,
            matter::Codex::CRYSTALS_Dilithium3_Seed => matter::Codex::CRYSTALS_Dilithium3,
            _ => return err!(Error::UnexpectedCode(code.to_string())),
        },
        false => match code {
            matter::Codex::Ed25519_Seed => matter::Codex::Ed25519N,
            matter::Codex::ECDSA_256k1_Seed => matter::Codex::ECDSA_256k1N,
            matter::Codex::ECDSA_256r1_Seed => matter::Codex::ECDSA_256r1N,
            matter::Codex::CRYSTALS_Dilithium3_Seed => matter::Codex::CRYSTALS_Dilithium3N,
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
            let mut raw = if let Some(raw) = raw { raw.to_vec() } else { sign::generate(code)? };
            let matter = Matter::new(Some(code), Some(&raw), None, None, None)?;
            raw.zeroize();
            matter
        } else {
            let signer: Self = Matter::new(code, raw, qb64b, qb64, qb2)?;
            validate_code(&signer.code())?;
            signer
        };
        signer.derive_and_assign_verfer(transferable)?;

        Ok(signer)
    }

    pub fn new_with_defaults(transferable: Option<bool>, code: Option<&str>) -> Result<Self> {
        Self::new(transferable, code, None, None, None, None)
    }

    pub fn new_with_raw(
        raw: &[u8],
        transferable: Option<bool>,
        code: Option<&str>,
    ) -> Result<Self> {
        Self::new(transferable, code, Some(raw), None, None, None)
    }

    pub fn new_with_qb64b(qb64b: &[u8], transferable: Option<bool>) -> Result<Self> {
        Self::new(transferable, None, None, Some(qb64b), None, None)
    }

    pub fn new_with_qb64(qb64: &str, transferable: Option<bool>) -> Result<Self> {
        Self::new(transferable, None, None, None, Some(qb64), None)
    }

    pub fn new_with_qb2(qb2: &[u8], transferable: Option<bool>) -> Result<Self> {
        Self::new(transferable, None, None, None, None, Some(qb2))
    }

    pub fn sign_unindexed(&self, ser: &[u8]) -> Result<Cigar> {
        let code = match self.code().as_str() {
            matter::Codex::Ed25519_Seed => matter::Codex::Ed25519_Sig,
            matter::Codex::ECDSA_256k1_Seed => matter::Codex::ECDSA_256k1_Sig,
            matter::Codex::ECDSA_256r1_Seed => matter::Codex::ECDSA_256r1_Sig,
            matter::Codex::CRYSTALS_Dilithium3_Seed => matter::Codex::CRYSTALS_Dilithium3_Sig,
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
                    matter::Codex::ECDSA_256r1_Seed => indexer::Codex::ECDSA_256r1_Crt,
                    matter::Codex::CRYSTALS_Dilithium3_Seed => indexer::Codex::CRYSTALS_Dilithium3_Crt,
                    _ => return err!(Error::UnexpectedCode(self.code())),
                }
            } else {
                match self.code().as_str() {
                    matter::Codex::Ed25519_Seed => indexer::Codex::Ed25519_Big_Crt,
                    matter::Codex::ECDSA_256k1_Seed => indexer::Codex::ECDSA_256k1_Big_Crt,
                    matter::Codex::ECDSA_256r1_Seed => indexer::Codex::ECDSA_256r1_Big_Crt,
                    matter::Codex::CRYSTALS_Dilithium3_Seed => indexer::Codex::CRYSTALS_Dilithium3_Big_Crt,
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
                    matter::Codex::ECDSA_256r1_Seed => indexer::Codex::ECDSA_256r1,
                    matter::Codex::CRYSTALS_Dilithium3_Seed => indexer::Codex::CRYSTALS_Dilithium3,
                    _ => return err!(Error::UnexpectedCode(self.code())),
                }
            } else {
                match self.code().as_str() {
                    matter::Codex::Ed25519_Seed => indexer::Codex::Ed25519_Big,
                    matter::Codex::ECDSA_256k1_Seed => indexer::Codex::ECDSA_256k1_Big,
                    matter::Codex::ECDSA_256r1_Seed => indexer::Codex::ECDSA_256r1_Big,
                    matter::Codex::CRYSTALS_Dilithium3_Seed => indexer::Codex::CRYSTALS_Dilithium3_Big,
                    _ => return err!(Error::UnexpectedCode(self.code())),
                }
            };

            (code, Some(ondex))
        };

        let sig = sign::sign(&self.code(), &self.raw(), ser)?;
        Siger::new(
            Some(&self.verfer()),
            Some(index),
            ondex,
            Some(code),
            Some(&sig),
            None,
            None,
            None,
        )
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
        cigar::Cigar,
        indexer::{tables as indexer, Indexer},
        matter::{tables as matter, Matter},
        signer::Signer,
    };
    use rstest::rstest;

    #[test]
    fn cigar_siger_raw_material_equivalence() {
        let data = b"abcdef";
        let signer = Signer::new_with_defaults(None, None).unwrap();

        let cigar = signer.sign_unindexed(data).unwrap();
        let siger = signer.sign_indexed(data, false, 0, None).unwrap();

        assert_eq!(cigar.raw(), siger.raw());
    }

    #[test]
    fn convenience() {
        let signer = Signer::new(None, None, None, None, None, None).unwrap();

        assert!(Signer::new_with_defaults(None, None).is_ok());
        assert!(Signer::new_with_raw(&signer.raw(), None, Some(&signer.code())).is_ok());
        assert!(Signer::new_with_qb64b(&signer.qb64b().unwrap(), None).is_ok());
        assert!(Signer::new_with_qb64(&signer.qb64().unwrap(), None).is_ok());
        assert!(Signer::new_with_qb2(&signer.qb2().unwrap(), None).is_ok());
    }

    #[test]
    fn new() {
        let signer = Signer::new(None, None, None, None, None, None).unwrap();
        assert!(Signer::new(None, None, None, None, Some(&signer.qb64().unwrap()), None).is_ok());
    }

    #[rstest]
    #[case(
        matter::Codex::Ed25519_Seed,
        matter::Codex::Ed25519,
        "AJ97qKeoQzmWJvqxmeuqIMQbRxHErlNBUsm9BJ2FKX6T",
        "DFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH"
    )]
    #[case(
        matter::Codex::ECDSA_256k1_Seed,
        matter::Codex::ECDSA_256k1,
        "JJ97qKeoQzmWJvqxmeuqIMQbRxHErlNBUsm9BJ2FKX6T",
        "1AABAg299p5IMvuw71HW_TlbzGq5cVOQ7bRbeDuhheF-DPYk"
    )]
    #[case(
        matter::Codex::ECDSA_256r1_Seed,
        matter::Codex::ECDSA_256r1,
        "QJ97qKeoQzmWJvqxmeuqIMQbRxHErlNBUsm9BJ2FKX6T",
        "1AAJA3cK_P2CDlh-_EMFPvyqTPI1POkw-dr14DANx5JEXDCZ"
    )]
    #[case(
        matter::Codex::CRYSTALS_Dilithium3_Seed,
        matter::Codex::CRYSTALS_Dilithium3,
        "TJ97qKeoQzmWJvqxmeuqIMQbRxHErlNBUsm9BJ2FKX6T",
        "SFXIJIfr7VJTb6AV6A-zZfinSBo7NlZkeffGOL2a4jbeuLU4SIqchhoT6PuAL1SP-Izi84lJDEP7wmU3L6iess2gvI6nGWn0QYGWoOh2fXC4ZXRqqbQcVlqfUL_VH0vGLpYxPQEljaHPtxtZO1vVUHyburUjmZ6d3YzGxJ2G3L1sGjveFiwGO_vV7tC12Fs4F_2Qtq2oybIn5FrCPPns-MrRXSKM3VgXSHzrUYbmAwmufLlW3IfQPsIWPMzfA0sFk5wuD6tBVIw5nGme2D0SjjY8kg5McYxScZX_Oe6tS6dXXAJ4ibk3xv0VeQRGOfTgViM_GANIJ5OTcWS-Rwe60_i95hYJG9F-fQ2jt8Y2bYqI-ELTQeozF5PnkcMm1Z3PCnRxdfgrVuAmxVxWR8to1yPMHVKw9Uzn-nK5P7y1Z_VYn1jdfdHq4YnrVNmZn_F9g4CyTNqEYY3j8HUXFP9Dax3-XhHYqMnL4tJ6pUMaDLmqQ7LVCr8V-VQN9WTRIIHuhF5ixnVI94LV8FeSinFv-UEPqnVQ3aTvCpRdQV4uhvXu7DA_hata6R_TYJB2iGJyij9PhZDBTs2gDR0EQ5qFGFXqtp_FE-YYVT8dx3PpINTvTSGoPBpj6KraGaFKuuamJHZN2PlRR9zV8eSGwzA0I-8TlAtC5YePGMWJEPsc3dOzGcktfuPQn3tMka3LuYxZ9NaoHc3iRWZnXN-KnhRf31JSuVQWxmhB4pCd5L46AdwXapL5SFiJhkvV9LKiqzsbOLThCocuRLdGOrLFDnrBkxnit6_sbpV7fRVJYshu2sZ2u4TDjAj4XgM4tR7tkgD9pNqhtdMaqeS9E3aKcTNldDe11vRlT5tEOlcD6w9VrAzRO2V0sqZdKopzeS_QWohUxZYlF3QKuJ6Vd30GuvOa2za9EQdwLhWVoJHYl5vU6yerDEloTnX_AZFGxzqQEK0Pc31R5rU9s9OjZrcRPn19XI0BmfphrCMxv_eTThHPtlLS5AE7wzQEfk1mhjPzXh1lbDA0L7l846fI8EvWfpyTsniOubBZLHGFzOheZoOlJsyjPcs-9eFEgRGdGvwELkA_qlqb16V7aBJ27MZ22aYl2dMGcBGqObnwdJS055ZYS_gG4Skl6Valse9w95npfNmfu5TgoqUqdC8FV86vV4wR-mwagHKsrahKMIpjpmH7pobNQm8G9hU_ZpTd_VhIwObaMfmNMwTEWufzgYB7ouUF_Z6gkm0xJkVZ0LXfmL2cpF4zljej2vcNcbNNlKqM4GgYvDpV67niDooXqycGOrF_VH_OQUnew0r1An8TvOPKH_HiiD6YJtHUTEa-5mdouVlN9SHBGPkwm3JSqHW_Cmtir1qrV_lNyYOPwaYzgME-alkizNrzY7mA1iTzl0sdUHcLXq92ej9Dy0RY7C4bmlNzO0LYlpFk8szpx5h3kAKjq-E7qg8pwyMs6Bg_G6qrbJyFMo4mzVq8OvdTYJToMi626S1SH5LQPMzUP9wF3sSlsulpFXXFFcOtlMgSSYv-g1JuqV6euFyqW7tNL5IboLtOrZkBQBCzJj4w1pkl5IUVfHpGXauv-WkrHsUbpMeZAPHNUJbRbki8U7Lh9mrXriiglFelQO89KO5CICLfve6sydk20szrNh7RQZWL1X9eE1VIhaiOIUkoKn9mPmcpZfNFXlj67f1Dhc9OLRGOmcEaWZNJ1rCMJET3_MZnintbsWycKVcrGRidqly8KmxN8DB27_N73Ei1ejSmE2LNJCtcAoD-LWtpu0UTrZ9exH3U_dsJwUZAcywqzJLvBDTZE53GRq-taP1pfGBB_1gaSkO_CAHz0xZtuJyZzS3T8C_ZXgGEL1wuSiYZJXMf7Vw2W-6drRXt63sdrz5nk2THiS9kmn9gQkIO7319fIXOToNpCO6cROOT_rQkv4ZClIdoAER-eWS-aP0wHvDcgSlroeZjRk_qApD34yWtNNBexWE6wyoL6HEI7kxHJbcQ_Zsxjnb8bOTdHJ-weZLMPAGHVzyTJSrDqYvxsBJuCGnjTE44Tw8FjKGM_rJaqOygJjTpHwTOjYQdo-bDjbDaNxwcQCpOUeic_QwxXbB2MP7PJahRU-NhGLYWCS3yh8aVslNcgmMto7juVCSKtrp3GCOwK-gB0Ay4_A0bly33LbadQTuw10QrkD_pIWigYAeD_FYcjixcmn382vRe6yWJBUtPaiwFjQ9fJ0icYZcrHCfZsDMa-lkyld3rRKZv7UFiTJdtUgRg-UCo7inQoK6lW-wFCwVD5lwjWpda1HHn-8uFje9or533XRlEezKEofEAGy6WTd9pttaVyxyq1buagnUGSEf7fxf6AObpFzzQt01WVl5bQCf1SdoUfw5yqKe7xKmsfqUmsIoX1AfMdM9Iyy4TGuz5y-uWWxv0hbrsVIzrPpnxc_h_IRksfxeuGCXFx-sSIb0lj7cqdPCs2PbJxp0opbw6qKCbafOXzKrqhnCTUbjfaYuwN4PNOnWYIhelI327jTNiDk3GoRn0lBjx75ACBGeGbE1qiI55bMCJjDhRwmfsDtpd83cN7isFJo6djOlN_WjytOVAm8b2m-QXp2kUlNDcwZcw"
    )]
    fn hardcoded(
        #[case] signer_code: &str,
        #[case] verfer_code: &str,
        #[case] signer_qb64: &str,
        #[case] verfer_qb64: &str,
    ) {
        let seed = b"\x9f{\xa8\xa7\xa8C9\x96&\xfa\xb1\x99\xeb\xaa \xc4\x1bG\x11\xc4\xaeSAR\xc9\xbd\x04\x9d\x85)~\x93";
        let signer = Signer::new_with_raw(seed, None, Some(signer_code)).unwrap();

        assert_eq!(signer.code(), signer_code);
        assert_eq!(signer.raw().len(), matter::raw_size(signer_code).unwrap() as usize);
        assert_eq!(signer.raw(), seed);
        assert_eq!(signer.qb64().unwrap(), signer_qb64);

        assert_eq!(signer.verfer().code(), verfer_code);
        assert_eq!(signer.verfer().raw().len(), matter::raw_size(verfer_code).unwrap() as usize);
        assert_eq!(signer.verfer().qb64().unwrap(), verfer_qb64);
    }

    #[rstest]
    // openssl genpkey -algorithm ed25519 -text
    #[case(
        matter::Codex::Ed25519_Seed,
        matter::Codex::Ed25519,
        matter::Codex::Ed25519_Sig,
        b"\xaa\xd1\x4e\x47\xa8\xc9\x59\xd1\x04\xe2\x46\xd3\x76\x57\x79\x2a\xe8\x2a\x13\x3b\x8f\xf6\x32\x36\xea\xc7\xb9\x6c\x5f\xf3\x08\x33",
        b"\x05\x91\xa1\x24\x0d\x9a\x69\xc3\x4d\xc5\x72\x20\x5a\xdf\x90\x66\x09\xba\xb0\x38\x54\x7b\xe6\xb1\x2e\x78\x7e\x67\xd3\xe9\xf0\x6f",
        b"\x1c\x6d\x3c\xef\x3a\x57\x55\xe3\x70\x06\x01\x6e\xb2\xbf\x59\x6e\xca\x5a\xf8\x04\xf6\xf4\xe8\x1f\x0f\x8b\x27\x10\xd5\x26\xce\x37\x4f\x50\x3d\x05\xb7\xf3\x5d\xa7\xce\x5c\xda\x8a\xd7\xfe\x86\x6c\x82\x48\x6f\xa6\x7a\xf7\x37\xfe\x43\x87\x0d\x3d\xe9\x8f\xa0\x00",
        "AKrRTkeoyVnRBOJG03ZXeSroKhM7j_YyNurHuWxf8wgz",
        "DAWRoSQNmmnDTcVyIFrfkGYJurA4VHvmsS54fmfT6fBv",
        "0BAcbTzvOldV43AGAW6yv1luylr4BPb06B8PiycQ1SbON09QPQW3812nzlzaitf-hmyCSG-mevc3_kOHDT3pj6AA",
    )]
    // openssl ecparam -name secp256k1 -genkey | openssl ec -pubout -text -param_enc explicit -conv_form compressed
    #[case(
        matter::Codex::ECDSA_256k1_Seed,
        matter::Codex::ECDSA_256k1,
        matter::Codex::ECDSA_256k1_Sig,
        b"\x7f\x98\x0a\x3b\xe4\x45\xd7\x8c\xc9\x79\xa1\xee\x26\x20\x9c\x17\x71\x16\xab\xa6\xd6\xf1\x6a\x01\xe7\xb3\xce\xfe\xe2\x6c\x06\x08",
        b"\x02\xdb\x98\x33\x85\xa8\x0e\xbb\x7c\x15\x5d\xdd\xc6\x47\x6a\x24\x07\x9a\x7c\x96\x5f\x05\x0f\x62\xde\x2d\x47\x56\x9b\x54\x29\x16\x79",
        b"\x5f\x80\xc0\x5a\xe4\x71\x32\x5d\xf7\xcb\xdb\x1b\xc2\xf4\x11\xc3\x05\xaf\xf4\xbe\x3b\x7e\xac\x3e\x8c\x15\x3a\x9f\xa5\x0a\x3d\x69\x75\x45\x93\x34\xc8\x96\x2b\xfe\x79\x8d\xd1\x4e\x9c\x1f\x6c\xa7\xc8\x12\xd6\x7a\x6c\xc5\x74\x9f\xef\x8d\xa7\x25\xa2\x95\x47\xcc",
        "JH-YCjvkRdeMyXmh7iYgnBdxFqum1vFqAeezzv7ibAYI",
        "1AABAtuYM4WoDrt8FV3dxkdqJAeafJZfBQ9i3i1HVptUKRZ5",
        "0CBfgMBa5HEyXffL2xvC9BHDBa_0vjt-rD6MFTqfpQo9aXVFkzTIliv-eY3RTpwfbKfIEtZ6bMV0n--NpyWilUfM",
    )]
    // openssl ecparam -name prime256v1 -genkey | openssl ec -pubout -text -param_enc explicit -conv_form compressed
    #[case(
        matter::Codex::ECDSA_256r1_Seed,
        matter::Codex::ECDSA_256r1,
        matter::Codex::ECDSA_256r1_Sig,
        b"\x35\x86\xc9\xa0\x4d\x33\x67\x85\xd5\xe4\x6a\xda\x62\xf0\x54\xc5\xa5\xf4\x32\x3f\x46\xcb\x92\x23\x07\xe0\xe2\x79\xb7\xe5\xf5\x0a",
        b"\x03\x16\x99\xbc\xa0\x51\x8f\xa6\x6c\xb3\x5d\x6b\x0a\x92\xf6\x84\x96\x28\x7b\xb6\x64\xe8\xe8\x57\x69\x15\xb8\xea\x9a\x02\x06\x2a\xff",
        b"\x8c\xfa\xb4\x40\x01\xd2\xab\x4a\xbc\xc5\x96\x8b\xa2\x65\x76\xcd\x51\x9d\x3b\x40\xc3\x35\x21\x73\x9a\x1b\xe8\x2f\xe1\x30\x28\xe1\x07\x90\x08\xa6\x42\xd7\x3f\x36\x8c\x96\x32\xff\x01\x64\x03\x18\x08\x85\xb8\xa4\x97\x76\xbe\x9c\xe4\xd7\xc5\xe7\x05\xda\x51\x23",
        "QDWGyaBNM2eF1eRq2mLwVMWl9DI_RsuSIwfg4nm35fUK",
        "1AAJAxaZvKBRj6Zss11rCpL2hJYoe7Zk6OhXaRW46poCBir_",
        "0ICM-rRAAdKrSrzFlouiZXbNUZ07QMM1IXOaG-gv4TAo4QeQCKZC1z82jJYy_wFkAxgIhbikl3a-nOTXxecF2lEj",
    )]
    fn hardcoded_openssl_vectors(
        #[case] signer_code: &str,
        #[case] verfer_code: &str,
        #[case] cigar_code: &str,
        #[case] seed: &[u8],
        #[case] public_key: &[u8],
        #[case] signature: &[u8],
        #[case] signer_qb64: &str,
        #[case] verfer_qb64: &str,
        #[case] cigar_qb64: &str,
    ) {
        let ser = b"abc";
        let signer = Signer::new_with_raw(seed, None, Some(signer_code)).unwrap();
        let cigar = signer.sign_unindexed(ser).unwrap();

        assert_eq!(signer.code(), signer_code);
        assert_eq!(signer.raw().len(), matter::raw_size(signer_code).unwrap() as usize);
        assert_eq!(signer.raw(), seed);
        assert_eq!(signer.qb64().unwrap(), signer_qb64);

        assert_eq!(signer.verfer().code(), verfer_code);
        assert_eq!(signer.verfer().raw().len(), matter::raw_size(verfer_code).unwrap() as usize);
        assert_eq!(signer.verfer().raw(), public_key);
        assert_eq!(signer.verfer().qb64().unwrap(), verfer_qb64);

        // the signatures we generate for ecdsa contain a random element and differ each time
        // so we test that the one generated verifies
        assert_eq!(cigar.code(), cigar_code);
        assert_eq!(cigar.raw().len(), matter::raw_size(cigar_code).unwrap() as usize);
        assert!(signer.verfer().verify(&cigar.raw(), ser).unwrap());

        // and then we test that a precomputed signature verifies
        let cigar = Cigar::new(None, Some(cigar_code), Some(signature), None, None, None).unwrap();
        assert_eq!(cigar.code(), cigar_code);
        assert_eq!(cigar.raw().len(), matter::raw_size(cigar_code).unwrap() as usize);
        assert_eq!(cigar.raw(), signature);
        assert_eq!(cigar.qb64().unwrap(), cigar_qb64);
        assert!(signer.verfer().verify(&cigar.raw(), ser).unwrap());
    }

    #[rstest]
    fn conversions(
        #[values(
            matter::Codex::Ed25519_Seed,
            matter::Codex::ECDSA_256k1_Seed,
            matter::Codex::ECDSA_256r1_Seed,
            matter::Codex::CRYSTALS_Dilithium3_Seed,
        )]
        code: &str,
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

    #[test]
    fn sign_ecdsa_256r1_unindexed() {
        let ser = b"abcdefghijklmnopqrstuvwxyz0123456789";
        let bad_ser = b"abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG";

        let signer =
            Signer::new(Some(true), Some(matter::Codex::ECDSA_256r1_Seed), None, None, None, None)
                .unwrap();

        let cigar = signer.sign_unindexed(ser).unwrap();
        assert_eq!(cigar.code(), matter::Codex::ECDSA_256r1_Sig);
        assert!(signer.verfer().verify(&cigar.raw(), ser).unwrap());
        assert!(!signer.verfer().verify(&cigar.raw(), bad_ser).unwrap());
    }

    #[test]
    fn sign_crystals_dilithium_unindexed() {
        let ser = b"abcdefghijklmnopqrstuvwxyz0123456789";
        let bad_ser = b"abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG";

        let signer =
            Signer::new(Some(true), Some(matter::Codex::CRYSTALS_Dilithium3_Seed), None, None, None, None)
                .unwrap();

        let cigar = signer.sign_unindexed(ser).unwrap();
        assert_eq!(cigar.code(), matter::Codex::CRYSTALS_Dilithium3_Sig);
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

    #[rstest]
    #[case(false, 0, None, 0, indexer::Codex::ECDSA_256r1)]
    #[case(false, 1, None, 1, indexer::Codex::ECDSA_256r1)]
    #[case(false, 1, Some(3), 3, indexer::Codex::ECDSA_256r1_Big)]
    #[case(false, 67, Some(3), 3, indexer::Codex::ECDSA_256r1_Big)]
    #[case(false, 67, Some(67), 67, indexer::Codex::ECDSA_256r1_Big)]
    #[case(true, 4, None, 0, indexer::Codex::ECDSA_256r1_Crt)]
    #[case(true, 4, Some(6), 0, indexer::Codex::ECDSA_256r1_Crt)]
    #[case(true, 65, None, 0, indexer::Codex::ECDSA_256r1_Big_Crt)]
    #[case(true, 65, Some(67), 0, indexer::Codex::ECDSA_256r1_Big_Crt)]
    fn sign_ecdsa_256r1_indexed(
        #[case] only: bool,
        #[case] index: u32,
        #[case] input_ondex: Option<u32>,
        #[case] output_ondex: u32,
        #[case] siger_code: &str,
    ) {
        let ser = b"abcdefghijklmnopqrstuvwxyz0123456789";
        let bad_ser = b"abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG";

        let signer =
            Signer::new(Some(true), Some(matter::Codex::ECDSA_256r1_Seed), None, None, None, None)
                .unwrap();

        let siger = signer.sign_indexed(ser, only, index, input_ondex).unwrap();
        assert_eq!(siger.code(), siger_code);
        assert_eq!(siger.index(), index);
        assert_eq!(siger.ondex(), output_ondex);
        assert!(signer.verfer().verify(&siger.raw(), ser).unwrap());
        assert!(!signer.verfer().verify(&siger.raw(), bad_ser).unwrap());
    }

    #[rstest]
    #[case(false, 0, None, 0, indexer::Codex::CRYSTALS_Dilithium3)]
    #[case(false, 1, None, 1, indexer::Codex::CRYSTALS_Dilithium3)]
    #[case(false, 1, Some(3), 3, indexer::Codex::CRYSTALS_Dilithium3_Big)]
    #[case(false, 67, Some(3), 3, indexer::Codex::CRYSTALS_Dilithium3_Big)]
    #[case(false, 67, Some(67), 67, indexer::Codex::CRYSTALS_Dilithium3_Big)]
    #[case(true, 4, None, 0, indexer::Codex::CRYSTALS_Dilithium3_Crt)]
    #[case(true, 4, Some(6), 0, indexer::Codex::CRYSTALS_Dilithium3_Crt)]
    #[case(true, 65, None, 0, indexer::Codex::CRYSTALS_Dilithium3_Big_Crt)]
    #[case(true, 65, Some(67), 0, indexer::Codex::CRYSTALS_Dilithium3_Big_Crt)]
    fn sign_crystals_dilithium_indexed(
        #[case] only: bool,
        #[case] index: u32,
        #[case] input_ondex: Option<u32>,
        #[case] output_ondex: u32,
        #[case] siger_code: &str,
    ) {
        let ser = b"abcdefghijklmnopqrstuvwxyz0123456789";
        let bad_ser = b"abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG";

        let signer =
            Signer::new(Some(true), Some(matter::Codex::CRYSTALS_Dilithium3_Seed), None, None, None, None)
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
