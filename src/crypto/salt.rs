use crate::core::common::Tierage;
use crate::error::{err, Error, Result};
use argon2::{Algorithm, Argon2, Params, Version};

fn params(tier: &str, length: usize) -> Result<Params> {
    let params = match tier {
        // had to check here https://github.com/jedisct1/libsodium/blob/master/src/libsodium/crypto_pwhash/argon2/pwhash_argon2id.c
        // to make sure we are compatible with the KERIpy implementation
        Tierage::min => Params::new(8, 1, 1, Some(length)),
        Tierage::low => Params::new(65536, 2, 1, Some(length)),
        Tierage::med => Params::new(262144, 3, 1, Some(length)),
        Tierage::high => Params::new(1048576, 4, 1, Some(length)),
        _ => return err!(Error::Value("unknown security tier selected".to_string())),
    };

    Ok(match params {
        Ok(p) => p,
        Err(e) => return err!(Error::Derivation(e.to_string())),
    })
}

pub(crate) fn stretch(pwd: &[u8], salt: &[u8], length: usize, tier: &str) -> Result<Vec<u8>> {
    let params = params(tier, length)?;
    let algorithm = Algorithm::Argon2id;
    let version = Version::V0x13;
    let stretcher = Argon2::new(algorithm, version, params);

    let mut result: Vec<u8> = vec![0; length];
    match stretcher.hash_password_into(pwd, salt, &mut result) {
        Ok(_) => (),
        Err(e) => return err!(Error::Derivation(e.to_string())),
    };

    Ok(result)
}

#[cfg(test)]
mod test {
    use crate::core::common::Tierage;
    use crate::crypto::salt;

    #[test]
    fn params() {
        assert!(salt::params(Tierage::min, 32).is_ok());
        assert!(salt::params(Tierage::low, 32).is_ok());
        assert!(salt::params(Tierage::med, 32).is_ok());
        assert!(salt::params(Tierage::high, 32).is_ok());
        assert!(salt::params("CESR", 32).is_err());
        assert!(salt::params(Tierage::high, 0).is_err());
    }

    #[test]
    fn stretch() {
        assert!(salt::stretch(&[], &[], 0, Tierage::min).is_err());
        assert!(salt::stretch(&[], &[], 32, Tierage::min).is_err());
        assert!(salt::stretch(&[0; 16], &[0; 16], 32, Tierage::min).is_ok());

        let expected: [u8; 32] = [
            18, 204, 212, 191, 84, 194, 87, 100, 6, 30, 92, 215, 51, 38, 107, 153, 250, 56, 19, 67,
            240, 139, 73, 162, 108, 231, 67, 120, 152, 225, 46, 245,
        ];
        assert_eq!(salt::stretch(&[0; 16], &[0; 16], 32, Tierage::min).unwrap(), expected);
    }
}
