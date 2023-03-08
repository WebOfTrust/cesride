use crate::core::matter::tables as matter;
use crate::error::{err, Error, Result};

pub(crate) fn generate(code: &str) -> Result<Vec<u8>> {
    match code {
        matter::Codex::Ed25519
        | matter::Codex::Ed25519N
        | matter::Codex::Ed25519_Seed
        | matter::Codex::Ed25519_Sig => ed25519::generate(),
        matter::Codex::ECDSA_256k1
        | matter::Codex::ECDSA_256k1N
        | matter::Codex::ECDSA_256k1_Seed
        | matter::Codex::ECDSA_256k1_Sig => ecdsa_256k1::generate(),
        matter::Codex::Ed448
        | matter::Codex::Ed448N
        | matter::Codex::Ed448_Seed
        | matter::Codex::Ed448_Sig => ed448::generate(),
        _ => err!(Error::UnexpectedCode(code.to_string())),
    }
}

pub(crate) fn public_key(code: &str, private_key: &[u8]) -> Result<Vec<u8>> {
    match code {
        matter::Codex::Ed25519
        | matter::Codex::Ed25519N
        | matter::Codex::Ed25519_Seed
        | matter::Codex::Ed25519_Sig => ed25519::public_key(private_key),
        matter::Codex::ECDSA_256k1
        | matter::Codex::ECDSA_256k1N
        | matter::Codex::ECDSA_256k1_Seed
        | matter::Codex::ECDSA_256k1_Sig => ecdsa_256k1::public_key(private_key),
        matter::Codex::Ed448
        | matter::Codex::Ed448N
        | matter::Codex::Ed448_Seed
        | matter::Codex::Ed448_Sig => ed448::public_key(private_key),
        _ => err!(Error::UnexpectedCode(code.to_string())),
    }
}

pub(crate) fn sign(code: &str, private_key: &[u8], ser: &[u8]) -> Result<Vec<u8>> {
    match code {
        matter::Codex::Ed25519
        | matter::Codex::Ed25519N
        | matter::Codex::Ed25519_Seed
        | matter::Codex::Ed25519_Sig => ed25519::sign(private_key, ser),
        matter::Codex::ECDSA_256k1
        | matter::Codex::ECDSA_256k1N
        | matter::Codex::ECDSA_256k1_Seed
        | matter::Codex::ECDSA_256k1_Sig => ecdsa_256k1::sign(private_key, ser),
        matter::Codex::Ed448
        | matter::Codex::Ed448N
        | matter::Codex::Ed448_Seed
        | matter::Codex::Ed448_Sig => ed448::sign(private_key, ser),
        _ => err!(Error::UnexpectedCode(code.to_string())),
    }
}

pub(crate) fn verify(code: &str, public_key: &[u8], sig: &[u8], ser: &[u8]) -> Result<bool> {
    match code {
        matter::Codex::Ed25519
        | matter::Codex::Ed25519N
        | matter::Codex::Ed25519_Seed
        | matter::Codex::Ed25519_Sig => ed25519::verify(public_key, sig, ser),
        matter::Codex::ECDSA_256k1
        | matter::Codex::ECDSA_256k1N
        | matter::Codex::ECDSA_256k1_Seed
        | matter::Codex::ECDSA_256k1_Sig => ecdsa_256k1::verify(public_key, sig, ser),
        matter::Codex::Ed448
        | matter::Codex::Ed448N
        | matter::Codex::Ed448_Seed
        | matter::Codex::Ed448_Sig => ed448::verify(public_key, sig, ser),
        _ => err!(Error::UnexpectedCode(code.to_string())),
    }
}

mod ed25519 {
    use ed25519_dalek::{
        ed25519::signature::Signer, Keypair, PublicKey, SecretKey, Signature, Verifier,
    };
    use rand::rngs::OsRng;

    use crate::error::Result;

    pub(crate) fn generate() -> Result<Vec<u8>> {
        let mut csprng = OsRng {};
        let private_key: SecretKey = SecretKey::generate(&mut csprng);
        Ok(private_key.as_bytes().to_vec())
    }

    pub(crate) fn public_key(private_key: &[u8]) -> Result<Vec<u8>> {
        let private_key = SecretKey::from_bytes(private_key)?;
        let public_key: PublicKey = (&private_key).into();
        Ok(public_key.as_bytes().to_vec())
    }

    pub(crate) fn sign(private_key: &[u8], ser: &[u8]) -> Result<Vec<u8>> {
        let private_key = SecretKey::from_bytes(private_key)?;
        let public_key: PublicKey = (&private_key).into();
        Ok(Keypair { secret: private_key, public: public_key }.sign(ser).to_bytes().to_vec())
    }

    pub(crate) fn verify(public_key: &[u8], sig: &[u8], ser: &[u8]) -> Result<bool> {
        let public_key = PublicKey::from_bytes(public_key)?;
        let signature = Signature::from_bytes(sig)?;

        match public_key.verify(ser, &signature) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}

mod ecdsa_256k1 {
    use k256::ecdsa::{
        signature::{Signer, Verifier},
        Signature, SigningKey, VerifyingKey,
    };
    use rand_core::OsRng;

    use crate::error::{err, Result};

    pub(crate) fn generate() -> Result<Vec<u8>> {
        let mut csprng = OsRng {};
        let private_key = SigningKey::random(&mut csprng);
        Ok(private_key.to_bytes().to_vec())
    }

    pub(crate) fn public_key(private_key: &[u8]) -> Result<Vec<u8>> {
        let private_key = SigningKey::from_bytes(private_key)?;
        let public_key = VerifyingKey::from(private_key);
        Ok(public_key.to_encoded_point(true).as_bytes().to_vec())
    }

    pub(crate) fn sign(private_key: &[u8], ser: &[u8]) -> Result<Vec<u8>> {
        let private_key = SigningKey::from_bytes(private_key)?;
        Ok(<SigningKey as Signer<Signature>>::sign(&private_key, ser).to_bytes().to_vec())
    }

    pub(crate) fn verify(public_key: &[u8], sig: &[u8], ser: &[u8]) -> Result<bool> {
        let public_key = VerifyingKey::from_sec1_bytes(public_key)?;
        let signature = match Signature::try_from(sig) {
            Ok(s) => s,
            Err(e) => return err!(e),
        };

        match public_key.verify(ser, &signature) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}

mod ed448 {
    use crate::error::{err, Error, Result};

    use ed448_rust::{PrivateKey, PublicKey, KEY_LENGTH};
    use rand_core::OsRng;

    pub(crate) fn generate() -> Result<Vec<u8>> {
        let key = PrivateKey::new(&mut OsRng);
        Ok(key.as_bytes().to_vec())
    }

    pub(crate) fn public_key(private_key: &[u8]) -> Result<Vec<u8>> {
        if private_key.len() < KEY_LENGTH {
            return err!(Error::Conversion(
                "not enough private key material submitted to generate public key".to_string()
            ));
        }

        let mut key = [0u8; KEY_LENGTH];
        key.copy_from_slice(private_key);
        Ok(PublicKey::from(&PrivateKey::from(key)).as_bytes().to_vec())
    }

    pub(crate) fn sign(private_key: &[u8], ser: &[u8]) -> Result<Vec<u8>> {
        if private_key.len() < KEY_LENGTH {
            return err!(Error::Conversion(
                "not enough private key material submitted to generate public key".to_string()
            ));
        }

        let mut key = [0u8; KEY_LENGTH];
        key.copy_from_slice(private_key);

        let result = match PrivateKey::from(key).sign(ser, None) {
            Ok(s) => s,
            Err(_) => return err!(Error::Derivation("could not sign data".to_string())),
        };

        Ok(result.to_vec())
    }

    pub(crate) fn verify(public_key: &[u8], sig: &[u8], ser: &[u8]) -> Result<bool> {
        if public_key.len() < KEY_LENGTH {
            return err!(Error::Conversion(
                "not enough private key material submitted to generate public key".to_string()
            ));
        }

        let mut key = [0u8; KEY_LENGTH];
        key.copy_from_slice(public_key);

        match PublicKey::try_from(&key) {
            Ok(public_key) => match public_key.verify(ser, sig, None) {
                Ok(()) => Ok(true),
                Err(_) => Ok(false),
            },
            Err(_) => Ok(false),
        }
    }
}

#[cfg(test)]
mod test {
    use crate::core::matter::tables as matter;
    use crate::crypto::sign;
    use hex_literal::hex;
    use rstest::rstest;

    #[rstest]
    fn end_to_end(
        #[values(matter::Codex::Ed25519, matter::Codex::ECDSA_256k1, matter::Codex::Ed448)]
        code: &str,
    ) {
        let ser = b"abcdefghijklmnopqrstuvwxyz";
        let private_key = sign::generate(code).unwrap();
        let signature = sign::sign(code, &private_key, ser).unwrap();
        let public_key = sign::public_key(code, &private_key).unwrap();
        assert!(sign::verify(code, &public_key, &signature, ser).unwrap());
    }

    #[test]
    // rfc 8032
    fn ed448() {
        let code = matter::Codex::Ed448;

        assert_eq!(sign::generate(code).unwrap().len(), 57);

        let private_key = hex!("6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6"
                              "e348a3528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b");
        let public_key = hex!("5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80"
                              "e96778edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180");
        let message = b"";
        let signature = hex!("533a37f6bbe457251f023c0d88f976ae2dfb504a843e34d2074fd823d41a591f2b233f034f628281f2fd7a22ddd47d7828c59bd0a21bfd3980"
                                   "ff0d2028d4b18a9df63e006c5d1c2d345b925d8dc00b4104852db99ac5c7cdda8530a113a0f4dbb61149f05a7363268c71d95808ff2e652600");

        assert_eq!(sign::public_key(code, &private_key).unwrap(), public_key);
        assert_eq!(sign::sign(code, &private_key, message).unwrap(), signature);
        assert!(sign::verify(code, &public_key, &signature, message).unwrap());
    }

    #[test]
    fn unhappy_paths() {
        let code = matter::Codex::SHA3_256;
        assert!(sign::generate(code).is_err());
        assert!(sign::public_key(code, &[]).is_err());
        assert!(sign::sign(code, &[], &[]).is_err());
        assert!(sign::verify(code, &[], &[], &[]).is_err());
    }
}
