use blake2::Digest;

use crate::core::matter::tables as matter;
use crate::error::{err, Error, Result};

type Blake2b256 = blake2::Blake2b<blake2::digest::consts::U32>;

pub(crate) fn digest(code: &str, ser: &[u8]) -> Result<Vec<u8>> {
    let out = match code {
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
            return err!(Error::UnexpectedCode(format!("unexpected digest code: code = '{code}'",)))
        }
    };

    Ok(out)
}

#[cfg(test)]
mod test {
    use crate::core::matter::tables as matter;
    use crate::crypto::hash;
    use hex_literal::hex;
    use rstest::rstest;

    #[rstest]
    // https://github.com/BLAKE3-team/BLAKE3/blob/master/test_vectors/test_vectors.json
    #[case(b"\x00\x01\x02", matter::Codex::Blake3_256,
        &hex!("e1be4d7a8ab5560aa4199eea339849ba8e293d55ca0a81006726d184519e647f"))]
    #[case(b"\x00\x01\x02", matter::Codex::Blake3_512,
        &hex!("e1be4d7a8ab5560aa4199eea339849ba8e293d55ca0a81006726d184519e647f"
              "5b49b82f805a538c68915c1ae8035c900fd1d4b13902920fd05e1450822f36de"))]
    // https://github.com/jasoncolburne/jason-math/blob/main/spec/jason/math/cryptography/digest/blake_spec.rb
    #[case(b"abc", matter::Codex::Blake2b_256,
        &hex!("bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319"))]
    #[case(b"The quick brown fox jumps over the lazy dog", matter::Codex::Blake2b_512,
        &hex!("a8add4bdddfd93e4877d2746e62817b116364a1fa7bc148d95090bc7333b3673"
              "f82401cf7aa2e4cb1ecd90296e3f14cb5413f8ed77be73045b13914cdcd6a918"))]
    // generated locally
    #[case(b"\x00\x01\x02", matter::Codex::Blake2s_256,
        &hex!("e8f91c6ef232a041452ab0e149070cdd7dd1769e75b3a5921be37876c45c9900"))]
    // https://github.com/jasoncolburne/jason-math/blob/main/spec/jason/math/cryptography/digest/secure_hash_algorithm_spec.rb
    #[case(b"abc", matter::Codex::SHA3_256,
        &hex!("3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"))]
    #[case(b"abc", matter::Codex::SHA3_512,
        &hex!("b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e"
              "10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"))]
    #[case(b"abc", matter::Codex::SHA2_256,
        &hex!("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"))]
    #[case(b"abc", matter::Codex::SHA2_512,
        &hex!("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
              "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"))]
    fn digest(#[case] ser: &[u8], #[case] code: &str, #[case] dig: &[u8]) {
        assert_eq!(hash::digest(code, ser).unwrap(), dig);
    }

    #[test]
    fn unhappy_paths() {
        assert!(hash::digest(matter::Codex::Ed25519, &[]).is_err());
    }
}
