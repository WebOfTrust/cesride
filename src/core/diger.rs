use blake2::Digest;
use lazy_static::lazy_static;

use crate::core::matter::{tables as matter, Matter};
use crate::error::{err, Error, Result};

type Blake2b256 = blake2::Blake2b<blake2::digest::consts::U32>;

pub struct Diger {
    pub(crate) matter: Matter,
}

impl Diger {
    fn new_with_code_and_raw(code: &str, raw: &[u8]) -> Result<Self> {
        validate_code(code)?;
        Ok(Diger { matter: Matter::new_with_code_and_raw(code, raw)? })
    }

    fn new_with_code_and_ser(code: &str, ser: &[u8]) -> Result<Self> {
        validate_code(code)?;
        let ev = matter::Codex::from_code(code)?;
        let dig = derive_digest(ev, ser)?;

        Ok(Diger { matter: Matter::new_with_code_and_raw(code, &dig)? })
    }

    fn new_with_qb64(qb64: &str) -> Result<Self> {
        let diger = Diger { matter: Matter::new_with_qb64(qb64)? };
        validate_code(&diger.matter.code)?;
        Ok(diger)
    }

    fn new_with_qb64b(qb64b: &[u8]) -> Result<Self> {
        let diger = Diger { matter: Matter::new_with_qb64b(qb64b)? };
        validate_code(&diger.matter.code)?;
        Ok(diger)
    }

    fn new_with_qb2(qb2: &[u8]) -> Result<Self> {
        let diger = Diger { matter: Matter::new_with_qb2(qb2)? };
        validate_code(&diger.matter.code)?;
        Ok(diger)
    }

    fn verify(&self, ser: &[u8]) -> Result<bool> {
        let ev = matter::Codex::from_code(&self.matter.code)?;
        let dig = derive_digest(ev, ser)?;
        Ok(dig == self.matter.raw())
    }

    fn compare_dig(&self, ser: &[u8], dig: &[u8]) -> Result<bool> {
        if dig == self.matter.qb64b()? {
            return Ok(true);
        }

        let diger = Diger { matter: Matter::new_with_qb64b(dig)? };

        if diger.matter.code == self.matter.code {
            return Ok(false);
        }

        if diger.verify(ser)? && self.verify(ser)? {
            return Ok(true);
        }

        Ok(false)
    }

    fn compare_diger(&self, ser: &[u8], diger: &Diger) -> Result<bool> {
        // reference implementation uses qb64b() but that's an extra conversion here
        if diger.matter.qb64()? == self.matter.qb64()? {
            return Ok(true);
        }

        if diger.matter.code == self.matter.code {
            return Ok(false);
        }

        if diger.verify(ser)? && self.verify(ser)? {
            return Ok(true);
        }

        Ok(false)
    }
}

fn derive_digest(ev: matter::Codex, ser: &[u8]) -> Result<Vec<u8>> {
    let out = match ev {
        matter::Codex::Blake3_256 => blake3::hash(ser).as_bytes().to_vec(),
        matter::Codex::Blake3_512 => {
            let mut hasher = blake3::Hasher::new();
            hasher.update(ser);
            let mut buf: [u8; 64] = [0; 64];
            hasher.finalize_xof().fill(&mut buf);
            buf.to_vec()
        }
        matter::Codex::Blake2b_256 => {
            let mut hasher = Blake2b256::new();
            hasher.update(ser);
            hasher.finalize().to_vec()
        }
        matter::Codex::Blake2b_512 => {
            let mut hasher = blake2::Blake2b512::new();
            hasher.update(ser);
            hasher.finalize().to_vec()
        }
        matter::Codex::Blake2s_256 => {
            let mut hasher = blake2::Blake2s256::new();
            hasher.update(ser);
            hasher.finalize().to_vec()
        }
        matter::Codex::SHA3_256 => {
            let mut hasher = sha3::Sha3_256::new();
            hasher.update(ser);
            hasher.finalize().to_vec()
        }
        matter::Codex::SHA3_512 => {
            let mut hasher = sha3::Sha3_512::new();
            hasher.update(ser);
            hasher.finalize().to_vec()
        }
        matter::Codex::SHA2_256 => {
            let mut hasher = sha2::Sha256::new();
            hasher.update(ser);
            hasher.finalize().to_vec()
        }
        matter::Codex::SHA2_512 => {
            let mut hasher = sha2::Sha512::new();
            hasher.update(ser);
            hasher.finalize().to_vec()
        }
        _ => {
            return err!(Error::UnexpectedCode(format!(
                "unexpected digest code: code = '{}'",
                ev.code()
            )))
        }
    };

    Ok(out)
}

fn validate_code(code: &str) -> Result<()> {
    lazy_static! {
        static ref CODES: Vec<&'static str> = vec![
            matter::Codex::Blake3_256.code(),
            matter::Codex::Blake3_512.code(),
            matter::Codex::Blake2b_256.code(),
            matter::Codex::Blake2b_512.code(),
            matter::Codex::Blake2s_256.code(),
            matter::Codex::SHA3_256.code(),
            matter::Codex::SHA3_512.code(),
            matter::Codex::SHA2_256.code(),
            matter::Codex::SHA2_512.code(),
        ];
    }

    if !CODES.contains(&code) {
        return err!(Error::UnexpectedCode(code.to_string()));
    }

    Ok(())
}

#[cfg(test)]
mod test_diger {
    use super::derive_digest;
    use crate::core::diger::Diger;
    use crate::core::matter::{tables as matter, Matter};
    use hex_literal::hex;
    use rstest::rstest;

    #[test]
    fn test_new_with_code_and_raw() {
        let raw = hex!("0123456789abcdef00001111222233334444555566667777888899990000aaaa");
        let code = matter::Codex::Blake3_256.code();

        let d = Diger::new_with_code_and_raw(code, &raw).unwrap();
        assert_eq!(d.matter.raw(), raw);
    }

    #[rstest]
    // https://github.com/BLAKE3-team/BLAKE3/blob/master/test_vectors/test_vectors.json
    #[case(b"\x00\x01\x02", matter::Codex::Blake3_256.code(),
        &hex!("e1be4d7a8ab5560aa4199eea339849ba8e293d55ca0a81006726d184519e647f"))]
    #[case(b"\x00\x01\x02", matter::Codex::Blake3_512.code(),
        &hex!("e1be4d7a8ab5560aa4199eea339849ba8e293d55ca0a81006726d184519e647f"
              "5b49b82f805a538c68915c1ae8035c900fd1d4b13902920fd05e1450822f36de"))]
    // https://github.com/jasoncolburne/jason-math/blob/main/spec/jason/math/cryptography/digest/blake_spec.rb
    #[case(b"abc", matter::Codex::Blake2b_256.code(),
        &hex!("bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319"))]
    #[case(b"The quick brown fox jumps over the lazy dog", matter::Codex::Blake2b_512.code(),
        &hex!("a8add4bdddfd93e4877d2746e62817b116364a1fa7bc148d95090bc7333b3673"
              "f82401cf7aa2e4cb1ecd90296e3f14cb5413f8ed77be73045b13914cdcd6a918"))]
    // generated locally
    #[case(b"\x00\x01\x02", matter::Codex::Blake2s_256.code(),
        &hex!("e8f91c6ef232a041452ab0e149070cdd7dd1769e75b3a5921be37876c45c9900"))]
    // https://github.com/jasoncolburne/jason-math/blob/main/spec/jason/math/cryptography/digest/secure_hash_algorithm_spec.rb
    #[case(b"abc", matter::Codex::SHA3_256.code(),
        &hex!("3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"))]
    #[case(b"abc", matter::Codex::SHA3_512.code(),
        &hex!("b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e"
              "10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"))]
    #[case(b"abc", matter::Codex::SHA2_256.code(),
        &hex!("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"))]
    #[case(b"abc", matter::Codex::SHA2_512.code(),
        &hex!("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
              "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"))]

    fn test_new_with_code_and_ser(#[case] ser: &[u8], #[case] code: &str, #[case] raw: &[u8]) {
        let d = Diger::new_with_code_and_ser(code, ser).unwrap();
        assert_eq!(d.matter.raw(), raw);
    }

    #[test]
    fn test_new_with_qb64() {
        let raw = b"abcdefghijklmnopqrstuvwxyz012345";

        let valid_diger =
            Matter::new_with_code_and_raw(matter::Codex::Blake3_256.code(), raw).unwrap();
        let invalid_diger =
            Matter::new_with_code_and_raw(matter::Codex::Ed25519.code(), raw).unwrap();

        assert!(Diger::new_with_qb64(&valid_diger.qb64().unwrap()).is_ok());
        assert!(Diger::new_with_qb64(&invalid_diger.qb64().unwrap()).is_err());
    }

    #[test]
    fn test_new_with_qb64b() {
        let raw = b"abcdefghijklmnopqrstuvwxyz012345";

        let valid_diger =
            Matter::new_with_code_and_raw(matter::Codex::Blake3_256.code(), raw).unwrap();
        let invalid_diger =
            Matter::new_with_code_and_raw(matter::Codex::Ed25519.code(), raw).unwrap();

        assert!(Diger::new_with_qb64b(&valid_diger.qb64b().unwrap()).is_ok());
        assert!(Diger::new_with_qb64b(&invalid_diger.qb64b().unwrap()).is_err());
    }

    #[test]
    fn test_new_with_qb2() {
        let raw = b"abcdefghijklmnopqrstuvwxyz012345";

        let valid_diger =
            Matter::new_with_code_and_raw(matter::Codex::Blake3_256.code(), raw).unwrap();
        let invalid_diger =
            Matter::new_with_code_and_raw(matter::Codex::Ed25519.code(), raw).unwrap();

        assert!(Diger::new_with_qb2(&valid_diger.qb2().unwrap()).is_ok());
        assert!(Diger::new_with_qb2(&invalid_diger.qb2().unwrap()).is_err());
    }

    #[test]
    fn test_verify() {
        let raw = hex!("e1be4d7a8ab5560aa4199eea339849ba8e293d55ca0a81006726d184519e647f"
                                 "5b49b82f805a538c68915c1ae8035c900fd1d4b13902920fd05e1450822f36de");

        let d = Diger::new_with_code_and_raw(matter::Codex::Blake3_512.code(), &raw).unwrap();
        assert!(d.verify(&vec![0, 1, 2]).unwrap());
    }

    #[test]
    fn test_compare_dig() {
        let code = matter::Codex::Blake3_256.code();
        let raw = hex!("e1be4d7a8ab5560aa4199eea339849ba8e293d55ca0a81006726d184519e647f");
        let ser = vec![0, 1, 2];

        // dig == self.qb64b() - should return true
        let d = Diger { matter: Matter::new_with_code_and_raw(code, &raw).unwrap() };
        let mut qb64b = d.matter.qb64b().unwrap();
        assert!(d.compare_dig(&ser, &qb64b).unwrap());

        // diger.code == self.code, dig != qb64b - should return false
        let mut x = qb64b[30]; // break a piece of the value, without breaking encoding
        x = if x == 0 { 63 } else { x - 1 };
        qb64b[30] = x;
        assert!(!d.compare_dig(&ser, &qb64b).unwrap());

        // same ser, different algorithm - should return true
        let code2 = matter::Codex::Blake2b_256.code();
        let ev = matter::Codex::from_code(code2).unwrap();
        let raw2 = derive_digest(ev.clone(), &ser).unwrap();
        let m2 = Matter::new_with_code_and_raw(code2, &raw2).unwrap();
        assert!(d.compare_dig(&ser, &m2.qb64b().unwrap()).unwrap());

        // different ser, different algorithm - should return false
        let raw2 = derive_digest(ev, &vec![0, 1, 2, 3]).unwrap();
        let m2 = Matter::new_with_code_and_raw(code2, &raw2).unwrap();
        assert!(!d.compare_dig(&ser, &m2.qb64b().unwrap()).unwrap());
    }

    #[test]
    fn test_compare_diger() {
        let code = matter::Codex::Blake3_256.code();
        let raw = hex!("e1be4d7a8ab5560aa4199eea339849ba8e293d55ca0a81006726d184519e647f");
        let ser = vec![0, 1, 2];

        // diger.qb64b() == self.qb64b() - should return true
        let d = Diger { matter: Matter::new_with_code_and_raw(code, &raw).unwrap() };
        let mut qb64b = d.matter.qb64b().unwrap();
        let d2 = Diger { matter: Matter::new_with_qb64b(&qb64b).unwrap() };
        assert!(d.compare_diger(&ser, &d2).unwrap());

        // diger.code == self.code, diger.qb64() != self.qb64b() - should return false
        let mut x = qb64b[30]; // break a piece of the value, without breaking encoding
        x = if x == 0 { 63 } else { x - 1 };
        qb64b[30] = x;
        let d2 = Diger { matter: Matter::new_with_qb64b(&qb64b).unwrap() };
        assert!(!d.compare_diger(&ser, &d2).unwrap());

        // same ser, different algorithm - should return true
        let code2 = matter::Codex::Blake2b_256.code();
        let ev = matter::Codex::from_code(code2).unwrap();
        let raw2 = derive_digest(ev.clone(), &ser).unwrap();
        let d2 = Diger { matter: Matter::new_with_code_and_raw(code2, &raw2).unwrap() };
        assert!(d.compare_diger(&ser, &d2).unwrap());

        // different ser, different algorithm - should return false
        let raw2 = derive_digest(ev, &vec![0, 1, 2, 3]).unwrap();
        let d2 = Diger { matter: Matter::new_with_code_and_raw(code2, &raw2).unwrap() };
        assert!(!d.compare_diger(&ser, &d2).unwrap());
    }

    #[test]
    fn test_python_interop() {
        // compare() will exercise the most code
        let ser = b"abcdefghijklmnopqrstuvwxyz0123456789";

        let diger0 = Diger::new_with_code_and_ser(matter::Codex::Blake3_256.code(), ser).unwrap();
        let diger1 = Diger::new_with_code_and_ser(matter::Codex::SHA3_256.code(), ser).unwrap();
        let diger2 = Diger::new_with_code_and_ser(matter::Codex::Blake2b_256.code(), ser).unwrap();

        assert!(diger0.compare_diger(ser, &diger1).unwrap());
        assert!(diger0.compare_diger(ser, &diger2).unwrap());
        assert!(diger1.compare_diger(ser, &diger2).unwrap());

        assert!(diger0.compare_dig(ser, &diger1.matter.qb64b().unwrap()).unwrap());
        assert!(diger0.compare_dig(ser, &diger2.matter.qb64b().unwrap()).unwrap());
        assert!(diger1.compare_dig(ser, &diger2.matter.qb64b().unwrap()).unwrap());

        let ser1 = b"ABCDEFGHIJKLMNOPQSTUVWXYXZabcdefghijklmnopqrstuvwxyz0123456789";
        let diger = Diger::new_with_code_and_ser(matter::Codex::Blake3_256.code(), ser1).unwrap();

        assert!(!diger0.compare_diger(ser, &diger).unwrap()); // codes match
        assert!(!diger0.compare_dig(ser, &diger.matter.qb64b().unwrap()).unwrap()); // codes match

        let diger = Diger::new_with_code_and_ser(matter::Codex::SHA3_256.code(), ser1).unwrap();

        assert!(!diger0.compare_diger(ser, &diger).unwrap()); // codes match
        assert!(!diger0.compare_dig(ser, &diger.matter.qb64b().unwrap()).unwrap());
        // codes match
    }

    #[test]
    fn test_unhappy_paths() {
        assert!(derive_digest(matter::Codex::Big, &[]).is_err());
    }
}
