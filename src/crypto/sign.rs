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
        matter::Codex::ECDSA_256r1
        | matter::Codex::ECDSA_256r1N
        | matter::Codex::ECDSA_256r1_Seed
        | matter::Codex::ECDSA_256r1_Sig => ecdsa_256r1::generate(),
        matter::Codex::CRYSTALS_Dilithium
        | matter::Codex::CRYSTALS_DilithiumN
        | matter::Codex::CRYSTALS_Dilithium_Seed
        | matter::Codex::CRYSTALS_Dilithium_Sig => crystals_dilithium_mod::generate(),
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
        matter::Codex::ECDSA_256r1
        | matter::Codex::ECDSA_256r1N
        | matter::Codex::ECDSA_256r1_Seed
        | matter::Codex::ECDSA_256r1_Sig => ecdsa_256r1::public_key(private_key),
        matter::Codex::CRYSTALS_Dilithium
        | matter::Codex::CRYSTALS_DilithiumN
        | matter::Codex::CRYSTALS_Dilithium_Seed
        | matter::Codex::CRYSTALS_Dilithium_Sig => crystals_dilithium_mod::public_key(private_key),
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
        matter::Codex::ECDSA_256r1
        | matter::Codex::ECDSA_256r1N
        | matter::Codex::ECDSA_256r1_Seed
        | matter::Codex::ECDSA_256r1_Sig => ecdsa_256r1::sign(private_key, ser),
        matter::Codex::CRYSTALS_Dilithium
        | matter::Codex::CRYSTALS_DilithiumN
        | matter::Codex::CRYSTALS_Dilithium_Seed
        | matter::Codex::CRYSTALS_Dilithium_Sig => crystals_dilithium_mod::sign(private_key, ser),
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
        matter::Codex::ECDSA_256r1
        | matter::Codex::ECDSA_256r1N
        | matter::Codex::ECDSA_256r1_Seed
        | matter::Codex::ECDSA_256r1_Sig => ecdsa_256r1::verify(public_key, sig, ser),
        matter::Codex::CRYSTALS_Dilithium
        | matter::Codex::CRYSTALS_DilithiumN
        | matter::Codex::CRYSTALS_Dilithium_Seed
        | matter::Codex::CRYSTALS_Dilithium_Sig => crystals_dilithium_mod::verify(public_key, sig, ser),
        _ => err!(Error::UnexpectedCode(code.to_string())),
    }
}

mod ed25519 {
    use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
    use rand_core::OsRng;

    use crate::error::Result;

    pub(crate) fn generate() -> Result<Vec<u8>> {
        let mut csprng = OsRng {};
        let mut private_key = SigningKey::generate(&mut csprng);
        let verifying_key = private_key.verifying_key();
        let mut weak = verifying_key.is_weak();

        while weak {
            private_key = SigningKey::generate(&mut csprng);
            let verifying_key = private_key.verifying_key();
            weak = verifying_key.is_weak();
        }

        Ok(private_key.to_bytes().to_vec())
    }

    pub(crate) fn public_key(private_key: &[u8]) -> Result<Vec<u8>> {
        let private_key = SigningKey::from_bytes(&private_key[..32].try_into()?);
        let public_key: VerifyingKey = (&private_key).into();
        Ok(public_key.as_bytes().to_vec())
    }

    pub(crate) fn sign(private_key: &[u8], ser: &[u8]) -> Result<Vec<u8>> {
        let private_key = SigningKey::from_bytes(private_key.try_into()?);
        Ok(private_key.sign(ser).to_bytes().to_vec())
    }

    pub(crate) fn verify(public_key: &[u8], sig: &[u8], ser: &[u8]) -> Result<bool> {
        let public_key = VerifyingKey::from_bytes(public_key.try_into()?)?;
        let signature = Signature::from_bytes(sig.try_into()?);

        match public_key.verify(ser, &signature) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}

mod ecdsa_256k1 {
    use k256::ecdsa::{
        signature::{RandomizedSigner, Verifier},
        Signature, SigningKey, VerifyingKey,
    };
    use rand_core::OsRng;

    use crate::error::Result;

    pub(crate) fn generate() -> Result<Vec<u8>> {
        let mut csprng = OsRng {};
        let private_key = SigningKey::random(&mut csprng);
        Ok(private_key.to_bytes().to_vec())
    }

    pub(crate) fn public_key(private_key: &[u8]) -> Result<Vec<u8>> {
        let private_key = SigningKey::from_slice(private_key)?;
        let public_key = VerifyingKey::from(private_key);
        Ok(public_key.to_encoded_point(true).as_bytes().to_vec())
    }

    pub(crate) fn sign(private_key: &[u8], ser: &[u8]) -> Result<Vec<u8>> {
        let private_key = SigningKey::from_slice(private_key)?;
        let signature: Signature = private_key.sign_with_rng(&mut OsRng, ser);
        Ok(signature.to_vec())
    }

    pub(crate) fn verify(public_key: &[u8], sig: &[u8], ser: &[u8]) -> Result<bool> {
        let public_key = VerifyingKey::from_sec1_bytes(public_key)?;
        let signature = Signature::try_from(sig)?;

        match public_key.verify(ser, &signature) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}

mod ecdsa_256r1 {
    use p256::ecdsa::{
        signature::{RandomizedSigner, Verifier},
        Signature, SigningKey, VerifyingKey,
    };
    use rand_core::OsRng;

    use crate::error::Result;

    pub(crate) fn generate() -> Result<Vec<u8>> {
        let mut csprng = OsRng {};
        let private_key = SigningKey::random(&mut csprng);
        Ok(private_key.to_bytes().to_vec())
    }

    pub(crate) fn public_key(private_key: &[u8]) -> Result<Vec<u8>> {
        let private_key = SigningKey::from_slice(private_key)?;
        let public_key = VerifyingKey::from(private_key);
        Ok(public_key.to_encoded_point(true).as_bytes().to_vec())
    }

    pub(crate) fn sign(private_key: &[u8], ser: &[u8]) -> Result<Vec<u8>> {
        let private_key = SigningKey::from_slice(private_key)?;
        let signature: Signature = private_key.sign_with_rng(&mut OsRng, ser);
        Ok(signature.to_vec())
    }

    pub(crate) fn verify(public_key: &[u8], sig: &[u8], ser: &[u8]) -> Result<bool> {
        let public_key = VerifyingKey::from_sec1_bytes(public_key)?;
        let signature = Signature::try_from(sig)?;

        match public_key.verify(ser, &signature) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}

mod crystals_dilithium_mod {
    use crystals_dilithium::dilithium3::{Keypair, PublicKey};
    use zeroize::Zeroize;

    use crate::crypto::csprng;
    use crate::error::Result;

    pub(crate) fn generate() -> Result<Vec<u8>> {
        let mut bytes = [0u8; 32];
        csprng::fill_bytes(&mut bytes);

        let result = bytes.to_vec();
        bytes.zeroize();

        Ok(result)
    }

    pub(crate) fn public_key(seed: &[u8]) -> Result<Vec<u8>> {
        let keypair = Keypair::generate(Some(seed));
        Ok(keypair.public.to_bytes().to_vec())
    }

    pub(crate) fn sign(seed: &[u8], ser: &[u8]) -> Result<Vec<u8>> {
        let keypair = Keypair::generate(Some(seed));
        let mut signature = keypair.sign(ser);
        let result = signature.to_vec();
        signature.zeroize();
        Ok(result)
    }

    pub(crate) fn verify(public_key: &[u8], sig: &[u8], ser: &[u8]) -> Result<bool> {
        let public_key = PublicKey::from_bytes(public_key);
        Ok(public_key.verify(ser, sig))
    }
}

#[cfg(test)]
mod test {
    use crate::core::matter::tables as matter;
    use crate::crypto::sign;
    use rstest::rstest;

    #[rstest]
    fn end_to_end(
        #[values(matter::Codex::Ed25519, matter::Codex::ECDSA_256k1, matter::Codex::ECDSA_256r1, matter::Codex::CRYSTALS_Dilithium)]
        code: &str,
    ) {
        let ser = b"abcdefghijklmnopqrstuvwxyz";
        let private_key = sign::generate(code).unwrap();
        let signature = sign::sign(code, &private_key, ser).unwrap();
        let public_key = sign::public_key(code, &private_key).unwrap();
        assert!(sign::verify(code, &public_key, &signature, ser).unwrap());
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
