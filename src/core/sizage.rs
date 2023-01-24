use crate::error;

#[derive(Debug, PartialEq)]
pub struct Sizage {
    pub hs: u32,
    pub ss: u32,
    pub ls: u32,
    pub fs: u32,
}

impl Sizage {
    pub fn new(hs: u32, ss: u32, fs: u32, ls: u32) -> Sizage {
        Self { hs, ss, ls, fs }
    }
}

pub (crate) fn sizage(s: &str) -> error::Result<Sizage> {
    match s {
        "A" => Ok(Sizage::new(1, 0, 44, 0)),
        "B" => Ok(Sizage::new(1, 0, 44, 0)),
        "C" => Ok(Sizage::new(1, 0, 44, 0)),
        "D" => Ok(Sizage::new(1, 0, 44, 0)),
        "E" => Ok(Sizage::new(1, 0, 44, 0)),
        "F" => Ok(Sizage::new(1, 0, 44, 0)),
        "G" => Ok(Sizage::new(1, 0, 44, 0)),
        "H" => Ok(Sizage::new(1, 0, 44, 0)),
        "I" => Ok(Sizage::new(1, 0, 44, 0)),
        "J" => Ok(Sizage::new(1, 0, 44, 0)),
        "K" => Ok(Sizage::new(1, 0, 76, 0)),
        "L" => Ok(Sizage::new(1, 0, 76, 0)),
        "M" => Ok(Sizage::new(1, 0, 4, 0)),
        "N" => Ok(Sizage::new(1, 0, 12, 0)),
        "O" => Ok(Sizage::new(1, 0, 44, 0)),
        "P" => Ok(Sizage::new(1, 0, 124, 0)),
        "0A" => Ok(Sizage::new(2, 0, 24, 0)),
        "0B" => Ok(Sizage::new(2, 0, 88, 0)),
        "0C" => Ok(Sizage::new(2, 0, 88, 0)),
        "0D" => Ok(Sizage::new(2, 0, 88, 0)),
        "0E" => Ok(Sizage::new(2, 0, 88, 0)),
        "0F" => Ok(Sizage::new(2, 0, 88, 0)),
        "0G" => Ok(Sizage::new(2, 0, 88, 0)),
        "0H" => Ok(Sizage::new(2, 0, 8, 0)),
        "1AAA" => Ok(Sizage::new(4, 0, 48, 0)),
        "1AAB" => Ok(Sizage::new(4, 0, 48, 0)),
        "1AAC" => Ok(Sizage::new(4, 0, 80, 0)),
        "1AAD" => Ok(Sizage::new(4, 0, 80, 0)),
        "1AAE" => Ok(Sizage::new(4, 0, 56, 0)),
        "1AAF" => Ok(Sizage::new(4, 0, 8, 0)),
        "1AAG" => Ok(Sizage::new(4, 0, 36, 0)),
        "1AAH" => Ok(Sizage::new(4, 0, 100, 0)),
        "2AAA" => Ok(Sizage::new(4, 0, 8, 1)),
        "3AAA" => Ok(Sizage::new(4, 0, 8, 2)),
        "4A" => Ok(Sizage::new(2, 2, 0, 0)),
        "5A" => Ok(Sizage::new(2, 2, 0, 1)),
        "6A" => Ok(Sizage::new(2, 2, 0, 2)),
        "7AAA" => Ok(Sizage::new(4, 4, 0, 0)),
        "8AAA" => Ok(Sizage::new(4, 4, 0, 1)),
        "9AAA" => Ok(Sizage::new(4, 4, 0, 2)),
        "4B" => Ok(Sizage::new(2, 2, 0, 0)),
        "5B" => Ok(Sizage::new(2, 2, 0, 1)),
        "6B" => Ok(Sizage::new(2, 2, 0, 2)),
        "7AAB" => Ok(Sizage::new(4, 4, 0, 0)),
        "8AAB" => Ok(Sizage::new(4, 4, 0, 1)),
        "9AAB" => Ok(Sizage::new(4, 4, 0, 2)),
        _ => Err(Box::new(error::Error::UnknownSizage(s.to_owned()))),
    }
}

#[cfg(test)]
mod sizage_tests {
    use crate::core::{
        matter::MatterCodex,
        sizage::{sizage, Sizage},
    };

    #[test]
    fn test_sizage() {
        let mut s: Sizage;

        s = sizage(MatterCodex::Ed25519_Seed.code()).unwrap();
        assert_eq!(s.hs, 1);
        assert_eq!(s.ss, 0);
        assert_eq!(s.fs, 44);
        assert_eq!(s.ls, 0);

        s = sizage(MatterCodex::Ed25519N.code()).unwrap();
        assert_eq!(s.hs, 1);
        assert_eq!(s.ss, 0);
        assert_eq!(s.fs, 44);
        assert_eq!(s.ls, 0);

        s = sizage(MatterCodex::X25519.code()).unwrap();
        assert_eq!(s.hs, 1);
        assert_eq!(s.ss, 0);
        assert_eq!(s.fs, 44);
        assert_eq!(s.ls, 0);

        s = sizage(MatterCodex::Ed25519.code()).unwrap();
        assert_eq!(s.hs, 1);
        assert_eq!(s.ss, 0);
        assert_eq!(s.fs, 44);
        assert_eq!(s.ls, 0);

        s = sizage(MatterCodex::Blake3_256.code()).unwrap();
        assert_eq!(s.hs, 1);
        assert_eq!(s.ss, 0);
        assert_eq!(s.fs, 44);
        assert_eq!(s.ls, 0);

        s = sizage(MatterCodex::Blake2b_256.code()).unwrap();
        assert_eq!(s.hs, 1);
        assert_eq!(s.ss, 0);
        assert_eq!(s.fs, 44);
        assert_eq!(s.ls, 0);

        s = sizage(MatterCodex::Blake2s_256.code()).unwrap();
        assert_eq!(s.hs, 1);
        assert_eq!(s.ss, 0);
        assert_eq!(s.fs, 44);
        assert_eq!(s.ls, 0);

        s = sizage(MatterCodex::SHA3_256.code()).unwrap();
        assert_eq!(s.hs, 1);
        assert_eq!(s.ss, 0);
        assert_eq!(s.fs, 44);
        assert_eq!(s.ls, 0);

        s = sizage(MatterCodex::SHA2_256.code()).unwrap();
        assert_eq!(s.hs, 1);
        assert_eq!(s.ss, 0);
        assert_eq!(s.fs, 44);
        assert_eq!(s.ls, 0);

        s = sizage(MatterCodex::ECDSA_256k1_Seed.code()).unwrap();
        assert_eq!(s.hs, 1);
        assert_eq!(s.ss, 0);
        assert_eq!(s.fs, 44);
        assert_eq!(s.ls, 0);

        s = sizage(MatterCodex::Ed448_Seed.code()).unwrap();
        assert_eq!(s.hs, 1);
        assert_eq!(s.ss, 0);
        assert_eq!(s.fs, 76);
        assert_eq!(s.ls, 0);

        s = sizage(MatterCodex::X448.code()).unwrap();
        assert_eq!(s.hs, 1);
        assert_eq!(s.ss, 0);
        assert_eq!(s.fs, 76);
        assert_eq!(s.ls, 0);

        s = sizage(MatterCodex::Short.code()).unwrap();
        assert_eq!(s.hs, 1);
        assert_eq!(s.ss, 0);
        assert_eq!(s.fs, 4);
        assert_eq!(s.ls, 0);

        s = sizage(MatterCodex::Big.code()).unwrap();
        assert_eq!(s.hs, 1);
        assert_eq!(s.ss, 0);
        assert_eq!(s.fs, 12);
        assert_eq!(s.ls, 0);

        s = sizage(MatterCodex::X25519_Private.code()).unwrap();
        assert_eq!(s.hs, 1);
        assert_eq!(s.ss, 0);
        assert_eq!(s.fs, 44);
        assert_eq!(s.ls, 0);

        s = sizage(MatterCodex::X25519_Cipher_Seed.code()).unwrap();
        assert_eq!(s.hs, 1);
        assert_eq!(s.ss, 0);
        assert_eq!(s.fs, 124);
        assert_eq!(s.ls, 0);

        s = sizage(MatterCodex::Salt_128.code()).unwrap();
        assert_eq!(s.hs, 2);
        assert_eq!(s.ss, 0);
        assert_eq!(s.fs, 24);
        assert_eq!(s.ls, 0);

        s = sizage(MatterCodex::Ed25519_Sig.code()).unwrap();
        assert_eq!(s.hs, 2);
        assert_eq!(s.ss, 0);
        assert_eq!(s.fs, 88);
        assert_eq!(s.ls, 0);

        s = sizage(MatterCodex::ECDSA_256k1_Sig.code()).unwrap();
        assert_eq!(s.hs, 2);
        assert_eq!(s.ss, 0);
        assert_eq!(s.fs, 88);
        assert_eq!(s.ls, 0);

        s = sizage(MatterCodex::Blake3_512.code()).unwrap();
        assert_eq!(s.hs, 2);
        assert_eq!(s.ss, 0);
        assert_eq!(s.fs, 88);
        assert_eq!(s.ls, 0);

        s = sizage(MatterCodex::Blake2b_512.code()).unwrap();
        assert_eq!(s.hs, 2);
        assert_eq!(s.ss, 0);
        assert_eq!(s.fs, 88);
        assert_eq!(s.ls, 0);

        s = sizage(MatterCodex::SHA3_512.code()).unwrap();
        assert_eq!(s.hs, 2);
        assert_eq!(s.ss, 0);
        assert_eq!(s.fs, 88);
        assert_eq!(s.ls, 0);

        s = sizage(MatterCodex::SHA2_512.code()).unwrap();
        assert_eq!(s.hs, 2);
        assert_eq!(s.ss, 0);
        assert_eq!(s.fs, 88);
        assert_eq!(s.ls, 0);

        s = sizage(MatterCodex::Long.code()).unwrap();
        assert_eq!(s.hs, 2);
        assert_eq!(s.ss, 0);
        assert_eq!(s.fs, 8);
        assert_eq!(s.ls, 0);

        s = sizage(MatterCodex::ECDSA_256k1N.code()).unwrap();
        assert_eq!(s.hs, 4);
        assert_eq!(s.ss, 0);
        assert_eq!(s.fs, 48);
        assert_eq!(s.ls, 0);

        s = sizage(MatterCodex::ECDSA_256k1.code()).unwrap();
        assert_eq!(s.hs, 4);
        assert_eq!(s.ss, 0);
        assert_eq!(s.fs, 48);
        assert_eq!(s.ls, 0);

        s = sizage(MatterCodex::Ed448N.code()).unwrap();
        assert_eq!(s.hs, 4);
        assert_eq!(s.ss, 0);
        assert_eq!(s.fs, 80);
        assert_eq!(s.ls, 0);

        s = sizage(MatterCodex::Ed448.code()).unwrap();
        assert_eq!(s.hs, 4);
        assert_eq!(s.ss, 0);
        assert_eq!(s.fs, 80);
        assert_eq!(s.ls, 0);

        s = sizage(MatterCodex::Ed448_Sig.code()).unwrap();
        assert_eq!(s.hs, 4);
        assert_eq!(s.ss, 0);
        assert_eq!(s.fs, 56);
        assert_eq!(s.ls, 0);

        s = sizage(MatterCodex::Tern.code()).unwrap();
        assert_eq!(s.hs, 4);
        assert_eq!(s.ss, 0);
        assert_eq!(s.fs, 8);
        assert_eq!(s.ls, 0);

        s = sizage(MatterCodex::DateTime.code()).unwrap();
        assert_eq!(s.hs, 4);
        assert_eq!(s.ss, 0);
        assert_eq!(s.fs, 36);
        assert_eq!(s.ls, 0);

        s = sizage(MatterCodex::X25519_Cipher_Salt.code()).unwrap();
        assert_eq!(s.hs, 4);
        assert_eq!(s.ss, 0);
        assert_eq!(s.fs, 100);
        assert_eq!(s.ls, 0);

        s = sizage(MatterCodex::TBD1.code()).unwrap();
        assert_eq!(s.hs, 4);
        assert_eq!(s.ss, 0);
        assert_eq!(s.fs, 8);
        assert_eq!(s.ls, 1);

        s = sizage(MatterCodex::TBD2.code()).unwrap();
        assert_eq!(s.hs, 4);
        assert_eq!(s.ss, 0);
        assert_eq!(s.fs, 8);
        assert_eq!(s.ls, 2);

        s = sizage(MatterCodex::StrB64_L0.code()).unwrap();
        assert_eq!(s.hs, 2);
        assert_eq!(s.ss, 2);
        assert_eq!(s.fs, 0);
        assert_eq!(s.ls, 0);

        s = sizage(MatterCodex::StrB64_L1.code()).unwrap();
        assert_eq!(s.hs, 2);
        assert_eq!(s.ss, 2);
        assert_eq!(s.fs, 0);
        assert_eq!(s.ls, 1);

        s = sizage(MatterCodex::StrB64_L2.code()).unwrap();
        assert_eq!(s.hs, 2);
        assert_eq!(s.ss, 2);
        assert_eq!(s.fs, 0);
        assert_eq!(s.ls, 2);

        s = sizage(MatterCodex::StrB64_Big_L0.code()).unwrap();
        assert_eq!(s.hs, 4);
        assert_eq!(s.ss, 4);
        assert_eq!(s.fs, 0);
        assert_eq!(s.ls, 0);

        s = sizage(MatterCodex::StrB64_Big_L1.code()).unwrap();
        assert_eq!(s.hs, 4);
        assert_eq!(s.ss, 4);
        assert_eq!(s.fs, 0);
        assert_eq!(s.ls, 1);

        s = sizage(MatterCodex::StrB64_Big_L2.code()).unwrap();
        assert_eq!(s.hs, 4);
        assert_eq!(s.ss, 4);
        assert_eq!(s.fs, 0);
        assert_eq!(s.ls, 2);

        s = sizage(MatterCodex::Bytes_L0.code()).unwrap();
        assert_eq!(s.hs, 2);
        assert_eq!(s.ss, 2);
        assert_eq!(s.fs, 0);
        assert_eq!(s.ls, 0);

        s = sizage(MatterCodex::Bytes_L1.code()).unwrap();
        assert_eq!(s.hs, 2);
        assert_eq!(s.ss, 2);
        assert_eq!(s.fs, 0);
        assert_eq!(s.ls, 1);

        s = sizage(MatterCodex::Bytes_L2.code()).unwrap();
        assert_eq!(s.hs, 2);
        assert_eq!(s.ss, 2);
        assert_eq!(s.fs, 0);
        assert_eq!(s.ls, 2);

        s = sizage(MatterCodex::Bytes_Big_L0.code()).unwrap();
        assert_eq!(s.hs, 4);
        assert_eq!(s.ss, 4);
        assert_eq!(s.fs, 0);
        assert_eq!(s.ls, 0);

        s = sizage(MatterCodex::Bytes_Big_L1.code()).unwrap();
        assert_eq!(s.hs, 4);
        assert_eq!(s.ss, 4);
        assert_eq!(s.fs, 0);
        assert_eq!(s.ls, 1);

        s = sizage(MatterCodex::Bytes_Big_L2.code()).unwrap();
        assert_eq!(s.hs, 4);
        assert_eq!(s.ss, 4);
        assert_eq!(s.fs, 0);
        assert_eq!(s.ls, 2);
    }
}
