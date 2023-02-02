use crate::core::matter::{tables as matter, Matter};
use crate::error::{err, Error, Result};

pub trait Verfer {
    fn new_with_code_and_raw(code: &str, raw: &[u8]) -> Result<Matter>
    where
        Self: Sized;
    fn new_with_qb64(qb64: &str) -> Result<Matter>
    where
        Self: Sized;
    fn new_with_qb64b(qb64b: &[u8]) -> Result<Matter>
    where
        Self: Sized;
    fn new_with_qb2(qb2: &[u8]) -> Result<Matter>
    where
        Self: Sized;
    fn verify(&self, sig: &[u8], ser: &[u8]) -> Result<bool>;
}

fn validate_code(code: &str) -> Result<()> {
    if !vec![
        matter::Codex::Ed25519N.code(),
        matter::Codex::Ed25519.code(),
        matter::Codex::ECDSA_256k1N.code(),
        matter::Codex::ECDSA_256k1.code(),
        // matter::Codex::Ed448N.code(),
        // matter::Codex::Ed448.code(),
    ]
    .contains(&code)
    {
        return err!(Error::UnexpectedCode(code.to_string()));
    }

    Ok(())
}

fn verify_ed25519_signature(verfer: &Matter, sig: &[u8], ser: &[u8]) -> Result<bool> {
    use ed25519_dalek::{PublicKey, Signature, Verifier};

    let public_key = PublicKey::from_bytes(verfer.raw.as_slice())?;
    let signature = Signature::from_bytes(sig)?;

    match public_key.verify(ser, &signature) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

fn verify_ecdsa_256k1_signature(verfer: &Matter, sig: &[u8], ser: &[u8]) -> Result<bool> {
    use k256::ecdsa::{signature::Verifier, Signature, VerifyingKey};

    let public_key = VerifyingKey::from_sec1_bytes(verfer.raw.as_slice())?;
    let signature = match Signature::try_from(sig) {
        Ok(s) => s,
        Err(e) => {
            return err!(e);
        }
    };

    match public_key.verify(ser, &signature) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

// fn verify_ed448_signature(verfer: &Matter, sig: &[u8], ser: &[u8]) -> Result<bool> {
//     Ok(true)
// }

impl Verfer for Matter {
    fn new_with_code_and_raw(code: &str, raw: &[u8]) -> Result<Matter> {
        validate_code(code)?;
        Matter::new_with_code_and_raw(code, raw, 0)
    }

    fn new_with_qb64(qb64: &str) -> Result<Matter> {
        let verfer = Matter::new_with_qb64(qb64)?;
        validate_code(&verfer.code)?;
        Ok(verfer)
    }

    fn new_with_qb64b(qb64b: &[u8]) -> Result<Matter> {
        let verfer = Matter::new_with_qb64b(qb64b)?;
        validate_code(&verfer.code)?;
        Ok(verfer)
    }

    fn new_with_qb2(qb2: &[u8]) -> Result<Matter> {
        let verfer = Matter::new_with_qb2(qb2)?;
        validate_code(&verfer.code)?;
        Ok(verfer)
    }

    fn verify(&self, sig: &[u8], ser: &[u8]) -> Result<bool> {
        let ev = matter::Codex::from_code(&self.code)?;

        match ev {
            matter::Codex::Ed25519N => verify_ed25519_signature(self, sig, ser),
            matter::Codex::Ed25519 => verify_ed25519_signature(self, sig, ser),
            matter::Codex::ECDSA_256k1N => verify_ecdsa_256k1_signature(self, sig, ser),
            matter::Codex::ECDSA_256k1 => verify_ecdsa_256k1_signature(self, sig, ser),
            // matter::Codex::Ed448N => verify_ed448_signature(verfer, sig, ser)?,
            // matter::Codex::Ed448 => verify_ed448_signature(verfer, sig, ser)?,
            _ => err!(Error::UnexpectedCode(format!(
                "unexpected signature code: code = '{}'",
                ev.code()
            ))),
        }
    }
}

#[cfg(test)]
mod test_verfer {
    use super::{matter, Matter, Verfer};
    use hex_literal::hex;

    #[test]
    fn test_new_with_code_and_raw() {
        let raw = hex!("0123456789abcdef00001111222233334444555566667777888899990000aaaa");
        let code = matter::Codex::Ed25519N.code();

        let m = <Matter as Verfer>::new_with_code_and_raw(code, &raw).unwrap();
        assert_eq!(m.raw(), raw);

        let code = matter::Codex::Blake3_256.code();
        assert!(<Matter as Verfer>::new_with_code_and_raw(code, &raw).is_err());
    }

    #[test]
    fn test_new_with_qb64() {
        let raw = hex!("0123456789abcdef00001111222233334444555566667777888899990000aaaa");

        let good_code = matter::Codex::Ed25519N.code();
        let good_qb64 = Matter::new_with_code_and_raw(good_code, &raw, 0).unwrap().qb64().unwrap();

        let bad_code = matter::Codex::Blake3_256.code();
        let bad_qb64 = Matter::new_with_code_and_raw(bad_code, &raw, 0).unwrap().qb64().unwrap();

        assert!(<Matter as Verfer>::new_with_qb64(&good_qb64).is_ok());
        assert!(<Matter as Verfer>::new_with_qb64(&bad_qb64).is_err());
    }

    #[test]
    fn test_new_with_qb64b() {
        let raw = hex!("0123456789abcdef00001111222233334444555566667777888899990000aaaa");

        let good_code = matter::Codex::Ed25519N.code();
        let good_qb64b =
            Matter::new_with_code_and_raw(good_code, &raw, 0).unwrap().qb64b().unwrap();

        let bad_code = matter::Codex::Blake3_256.code();
        let bad_qb64b = Matter::new_with_code_and_raw(bad_code, &raw, 0).unwrap().qb64b().unwrap();

        assert!(<Matter as Verfer>::new_with_qb64b(&good_qb64b).is_ok());
        assert!(<Matter as Verfer>::new_with_qb64b(&bad_qb64b).is_err());
    }

    #[test]
    fn test_new_with_qb2() {
        let raw = hex!("0123456789abcdef00001111222233334444555566667777888899990000aaaa");

        let good_code = matter::Codex::Ed25519N.code();
        let good_qb2 = Matter::new_with_code_and_raw(good_code, &raw, 0).unwrap().qb2().unwrap();

        let bad_code = matter::Codex::Blake3_256.code();
        let bad_qb2 = Matter::new_with_code_and_raw(bad_code, &raw, 0).unwrap().qb2().unwrap();

        assert!(<Matter as Verfer>::new_with_qb2(&good_qb2).is_ok());
        assert!(<Matter as Verfer>::new_with_qb2(&bad_qb2).is_err());
    }

    #[test]
    fn test_verify_ed25519() {
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

        let mut m =
            <Matter as Verfer>::new_with_code_and_raw(matter::Codex::Ed25519.code(), raw).unwrap();
        assert!(m.verify(&sig, &ser).unwrap());
        assert!(!m.verify(&bad_sig, &ser).unwrap());
        assert!(!m.verify(&sig, &bad_ser).unwrap());
        assert!(m.verify(&[], &ser).is_err());

        // exercise control flows for non-transferrable variant
        m.code = matter::Codex::Ed25519N.code().to_string();
        assert!(m.verify(&sig, &ser).unwrap());
        assert!(!m.verify(&bad_sig, &ser).unwrap());
        assert!(!m.verify(&sig, &bad_ser).unwrap());
    }

    #[test]
    fn test_verify_ecdsa_256k1() {
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
            <Matter as Verfer>::new_with_code_and_raw(matter::Codex::ECDSA_256k1.code(), &raw)
                .unwrap();
        assert!(m.verify(&sig, &ser).unwrap());
        assert!(!m.verify(&bad_sig, &ser).unwrap());
        assert!(!m.verify(&sig, &bad_ser).unwrap());
        assert!(m.verify(&[], &ser).is_err());

        m.code = matter::Codex::ECDSA_256k1N.code().to_string();
        assert!(m.verify(&sig, &ser).unwrap());
        assert!(!m.verify(&bad_sig, &ser).unwrap());
        assert!(!m.verify(&sig, &bad_ser).unwrap());
    }

    #[test]
    fn test_unhappy_paths() {
        assert!(Matter {
            code: matter::Codex::Blake3_256.code().to_string(),
            raw: vec![],
            size: 0
        }
        .verify(&[], &[])
        .is_err());
    }
}
