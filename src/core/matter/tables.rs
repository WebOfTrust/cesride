use crate::error::{err, Error, Result};

pub(crate) const SMALL_VRZ_DEX: [char; 3] = ['4', '5', '6'];
pub(crate) const LARGE_VRZ_DEX: [char; 3] = ['7', '8', '9'];
pub(crate) const SMALL_VRZ_BYTES: u32 = 3;
pub(crate) const LARGE_VRZ_BYTES: u32 = 6;

#[derive(Debug, PartialEq)]
pub(crate) struct Sizage {
    pub hs: u32,
    pub ss: u32,
    pub ls: u32,
    pub fs: u32,
}

pub(crate) fn sizage(s: &str) -> Result<Sizage> {
    Ok(match s {
        "A" => Sizage { hs: 1, ss: 0, fs: 44, ls: 0 },
        "B" => Sizage { hs: 1, ss: 0, fs: 44, ls: 0 },
        "C" => Sizage { hs: 1, ss: 0, fs: 44, ls: 0 },
        "D" => Sizage { hs: 1, ss: 0, fs: 44, ls: 0 },
        "E" => Sizage { hs: 1, ss: 0, fs: 44, ls: 0 },
        "F" => Sizage { hs: 1, ss: 0, fs: 44, ls: 0 },
        "G" => Sizage { hs: 1, ss: 0, fs: 44, ls: 0 },
        "H" => Sizage { hs: 1, ss: 0, fs: 44, ls: 0 },
        "I" => Sizage { hs: 1, ss: 0, fs: 44, ls: 0 },
        "J" => Sizage { hs: 1, ss: 0, fs: 44, ls: 0 },
        "K" => Sizage { hs: 1, ss: 0, fs: 76, ls: 0 },
        "L" => Sizage { hs: 1, ss: 0, fs: 76, ls: 0 },
        "M" => Sizage { hs: 1, ss: 0, fs: 4, ls: 0 },
        "N" => Sizage { hs: 1, ss: 0, fs: 12, ls: 0 },
        "O" => Sizage { hs: 1, ss: 0, fs: 44, ls: 0 },
        "P" => Sizage { hs: 1, ss: 0, fs: 124, ls: 0 },
        "0A" => Sizage { hs: 2, ss: 0, fs: 24, ls: 0 },
        "0B" => Sizage { hs: 2, ss: 0, fs: 88, ls: 0 },
        "0C" => Sizage { hs: 2, ss: 0, fs: 88, ls: 0 },
        "0D" => Sizage { hs: 2, ss: 0, fs: 88, ls: 0 },
        "0E" => Sizage { hs: 2, ss: 0, fs: 88, ls: 0 },
        "0F" => Sizage { hs: 2, ss: 0, fs: 88, ls: 0 },
        "0G" => Sizage { hs: 2, ss: 0, fs: 88, ls: 0 },
        "0H" => Sizage { hs: 2, ss: 0, fs: 8, ls: 0 },
        "1AAA" => Sizage { hs: 4, ss: 0, fs: 48, ls: 0 },
        "1AAB" => Sizage { hs: 4, ss: 0, fs: 48, ls: 0 },
        "1AAC" => Sizage { hs: 4, ss: 0, fs: 80, ls: 0 },
        "1AAD" => Sizage { hs: 4, ss: 0, fs: 80, ls: 0 },
        "1AAE" => Sizage { hs: 4, ss: 0, fs: 56, ls: 0 },
        "1AAF" => Sizage { hs: 4, ss: 0, fs: 8, ls: 0 },
        "1AAG" => Sizage { hs: 4, ss: 0, fs: 36, ls: 0 },
        "1AAH" => Sizage { hs: 4, ss: 0, fs: 100, ls: 0 },
        "2AAA" => Sizage { hs: 4, ss: 0, fs: 8, ls: 1 },
        "3AAA" => Sizage { hs: 4, ss: 0, fs: 8, ls: 2 },
        "4A" => Sizage { hs: 2, ss: 2, fs: 0, ls: 0 },
        "5A" => Sizage { hs: 2, ss: 2, fs: 0, ls: 1 },
        "6A" => Sizage { hs: 2, ss: 2, fs: 0, ls: 2 },
        "7AAA" => Sizage { hs: 4, ss: 4, fs: 0, ls: 0 },
        "8AAA" => Sizage { hs: 4, ss: 4, fs: 0, ls: 1 },
        "9AAA" => Sizage { hs: 4, ss: 4, fs: 0, ls: 2 },
        "4B" => Sizage { hs: 2, ss: 2, fs: 0, ls: 0 },
        "5B" => Sizage { hs: 2, ss: 2, fs: 0, ls: 1 },
        "6B" => Sizage { hs: 2, ss: 2, fs: 0, ls: 2 },
        "7AAB" => Sizage { hs: 4, ss: 4, fs: 0, ls: 0 },
        "8AAB" => Sizage { hs: 4, ss: 4, fs: 0, ls: 1 },
        "9AAB" => Sizage { hs: 4, ss: 4, fs: 0, ls: 2 },
        _ => return err!(Error::UnknownSizage(s.to_string())),
    })
}

pub(crate) fn hardage(c: char) -> Result<i32> {
    match c {
        'A'..='Z' | 'a'..='z' => Ok(1),
        '0' | '4' | '5' | '6' => Ok(2),
        '1' | '2' | '3' | '7' | '8' | '9' => Ok(4),
        '-' => err!(Error::UnexpectedCode("count code start".to_string())),
        '_' => err!(Error::UnexpectedCode("op code start".to_string())),
        _ => err!(Error::UnknownHardage(c.to_string())),
    }
}

#[allow(non_camel_case_types)]
#[derive(Debug, Eq, PartialEq, Clone)]
pub enum Codex {
    Ed25519_Seed,
    Ed25519N,
    X25519,
    Ed25519,
    Blake3_256,
    Blake2b_256,
    Blake2s_256,
    SHA3_256,
    SHA2_256,
    ECDSA_256k1_Seed,
    Ed448_Seed,
    X448,
    Short,
    Big,
    X25519_Private,
    X25519_Cipher_Seed,
    Salt_128,
    Ed25519_Sig,
    ECDSA_256k1_Sig,
    Blake3_512,
    Blake2b_512,
    SHA3_512,
    SHA2_512,
    Long,
    ECDSA_256k1N,
    ECDSA_256k1,
    Ed448N,
    Ed448,
    Ed448_Sig,
    Tern,
    DateTime,
    X25519_Cipher_Salt,
    TBD1,
    TBD2,
    StrB64_L0,
    StrB64_L1,
    StrB64_L2,
    StrB64_Big_L0,
    StrB64_Big_L1,
    StrB64_Big_L2,
    Bytes_L0,
    Bytes_L1,
    Bytes_L2,
    Bytes_Big_L0,
    Bytes_Big_L1,
    Bytes_Big_L2,
}

impl Codex {
    pub(crate) fn code(&self) -> &'static str {
        match self {
            Codex::Ed25519_Seed => "A", // Ed25519 256 bit random seed for private key
            Codex::Ed25519N => "B", // Ed25519 verification key non-transferable, basic derivation.
            Codex::X25519 => "C", // X25519 public encryption key, converted from Ed25519 or Ed25519N.
            Codex::Ed25519 => "D", // Ed25519 verification key basic derivation
            Codex::Blake3_256 => "E", // Blake3 256 bit digest self-addressing derivation.
            Codex::Blake2b_256 => "F", // Blake2b 256 bit digest self-addressing derivation.
            Codex::Blake2s_256 => "G", // Blake2s 256 bit digest self-addressing derivation.
            Codex::SHA3_256 => "H", // SHA3 256 bit digest self-addressing derivation.
            Codex::SHA2_256 => "I", // SHA2 256 bit digest self-addressing derivation.
            Codex::ECDSA_256k1_Seed => "J", // ECDSA secp256k1 256 bit random Seed for private key
            Codex::Ed448_Seed => "K", // Ed448 448 bit random Seed for private key
            Codex::X448 => "L",   // X448 public encryption key, converted from Ed448
            Codex::Short => "M",  // Short 2 byte b2 number
            Codex::Big => "N",    // Big 8 byte b2 number
            Codex::X25519_Private => "O", // X25519 private decryption key converted from Ed25519
            Codex::X25519_Cipher_Seed => "P", // X25519 124 char b64 Cipher of 44 char qb64 Seed
            Codex::Salt_128 => "0A", // 128 bit random salt or 128 bit number (see Huge)
            Codex::Ed25519_Sig => "0B", // Ed25519 signature.
            Codex::ECDSA_256k1_Sig => "0C", // ECDSA secp256k1 signature.
            Codex::Blake3_512 => "0D", // Blake3 512 bit digest self-addressing derivation.
            Codex::Blake2b_512 => "0E", // Blake2b 512 bit digest self-addressing derivation.
            Codex::SHA3_512 => "0F", // SHA3 512 bit digest self-addressing derivation.
            Codex::SHA2_512 => "0G", // SHA2 512 bit digest self-addressing derivation.
            Codex::Long => "0H",  // Long 4 byte b2 number
            Codex::ECDSA_256k1N => "1AAA", // ECDSA secp256k1 verification key non-transferable, basic derivation.
            Codex::ECDSA_256k1 => "1AAB", // Ed25519 public verification or encryption key, basic derivation
            Codex::Ed448N => "1AAC", // Ed448 non-transferable prefix public signing verification key. Basic derivation.
            Codex::Ed448 => "1AAD",  // Ed448 public signing verification key. Basic derivation.
            Codex::Ed448_Sig => "1AAE", // Ed448 signature. Self-signing derivation.
            Codex::Tern => "1AAF",   // 3 byte b2 number or 4 char B64 str.
            Codex::DateTime => "1AAG", // Base64 custom encoded 32 char ISO-8601 DateTime
            Codex::X25519_Cipher_Salt => "1AAH", // X25519 100 char b64 Cipher of 24 char qb64 Salt
            Codex::TBD1 => "2AAA",   // Testing purposes only fixed with lead size 1
            Codex::TBD2 => "3AAA",   // Testing purposes only of fixed with lead size 2
            Codex::StrB64_L0 => "4A", // String Base64 Only Lead Size 0 (4095 * 3 | 4)
            Codex::StrB64_L1 => "5A", // String Base64 Only Lead Size 1
            Codex::StrB64_L2 => "6A", // String Base64 Only Lead Size 2
            Codex::StrB64_Big_L0 => "7AAA", // String Base64 Only Big Lead Size 0 (16777215 * 3 | 4)
            Codex::StrB64_Big_L1 => "8AAA", // String Base64 Only Big Lead Size 1
            Codex::StrB64_Big_L2 => "9AAA", // String Base64 Only Big Lead Size 2
            Codex::Bytes_L0 => "4B", // Byte String Leader Size 0
            Codex::Bytes_L1 => "5B", // Byte String Leader Size 1
            Codex::Bytes_L2 => "6B", // Byte String Leader Size 2
            Codex::Bytes_Big_L0 => "7AAB", // Byte String Big Leader Size 0
            Codex::Bytes_Big_L1 => "8AAB", // Byte String Big Leader Size 1
            Codex::Bytes_Big_L2 => "9AAB", // Byte String Big Leader Size 2
        }
    }

    pub(crate) fn from_code(code: &str) -> Result<Self> {
        Ok(match code {
            "A" => Codex::Ed25519_Seed,
            "B" => Codex::Ed25519N,
            "C" => Codex::X25519,
            "D" => Codex::Ed25519,
            "E" => Codex::Blake3_256,
            "F" => Codex::Blake2b_256,
            "G" => Codex::Blake2s_256,
            "H" => Codex::SHA3_256,
            "I" => Codex::SHA2_256,
            "J" => Codex::ECDSA_256k1_Seed,
            "K" => Codex::Ed448_Seed,
            "L" => Codex::X448,
            "M" => Codex::Short,
            "N" => Codex::Big,
            "O" => Codex::X25519_Private,
            "P" => Codex::X25519_Cipher_Seed,
            "0A" => Codex::Salt_128,
            "0B" => Codex::Ed25519_Sig,
            "0C" => Codex::ECDSA_256k1_Sig,
            "0D" => Codex::Blake3_512,
            "0E" => Codex::Blake2b_512,
            "0F" => Codex::SHA3_512,
            "0G" => Codex::SHA2_512,
            "0H" => Codex::Long,
            "1AAA" => Codex::ECDSA_256k1N,
            "1AAB" => Codex::ECDSA_256k1,
            "1AAC" => Codex::Ed448N,
            "1AAD" => Codex::Ed448,
            "1AAE" => Codex::Ed448_Sig,
            "1AAF" => Codex::Tern,
            "1AAG" => Codex::DateTime,
            "1AAH" => Codex::X25519_Cipher_Salt,
            "2AAA" => Codex::TBD1,
            "3AAA" => Codex::TBD2,
            "4A" => Codex::StrB64_L0,
            "5A" => Codex::StrB64_L1,
            "6A" => Codex::StrB64_L2,
            "7AAA" => Codex::StrB64_Big_L0,
            "8AAA" => Codex::StrB64_Big_L1,
            "9AAA" => Codex::StrB64_Big_L2,
            "4B" => Codex::Bytes_L0,
            "5B" => Codex::Bytes_L1,
            "6B" => Codex::Bytes_L2,
            "7AAB" => Codex::Bytes_Big_L0,
            "8AAB" => Codex::Bytes_Big_L1,
            "9AAB" => Codex::Bytes_Big_L2,
            _ => return err!(Error::UnexpectedCode(code.to_string())),
        })
    }
}

#[cfg(test)]
mod tables_tests {
    use super::{hardage, sizage, Codex, Sizage};

    #[test]
    fn test_sizage() {
        let mut s: Sizage;

        s = sizage(Codex::Ed25519_Seed.code()).unwrap();
        assert_eq!(s.hs, 1);
        assert_eq!(s.ss, 0);
        assert_eq!(s.fs, 44);
        assert_eq!(s.ls, 0);

        s = sizage(Codex::Ed25519N.code()).unwrap();
        assert_eq!(s.hs, 1);
        assert_eq!(s.ss, 0);
        assert_eq!(s.fs, 44);
        assert_eq!(s.ls, 0);

        s = sizage(Codex::X25519.code()).unwrap();
        assert_eq!(s.hs, 1);
        assert_eq!(s.ss, 0);
        assert_eq!(s.fs, 44);
        assert_eq!(s.ls, 0);

        s = sizage(Codex::Ed25519.code()).unwrap();
        assert_eq!(s.hs, 1);
        assert_eq!(s.ss, 0);
        assert_eq!(s.fs, 44);
        assert_eq!(s.ls, 0);

        s = sizage(Codex::Blake3_256.code()).unwrap();
        assert_eq!(s.hs, 1);
        assert_eq!(s.ss, 0);
        assert_eq!(s.fs, 44);
        assert_eq!(s.ls, 0);

        s = sizage(Codex::Blake2b_256.code()).unwrap();
        assert_eq!(s.hs, 1);
        assert_eq!(s.ss, 0);
        assert_eq!(s.fs, 44);
        assert_eq!(s.ls, 0);

        s = sizage(Codex::Blake2s_256.code()).unwrap();
        assert_eq!(s.hs, 1);
        assert_eq!(s.ss, 0);
        assert_eq!(s.fs, 44);
        assert_eq!(s.ls, 0);

        s = sizage(Codex::SHA3_256.code()).unwrap();
        assert_eq!(s.hs, 1);
        assert_eq!(s.ss, 0);
        assert_eq!(s.fs, 44);
        assert_eq!(s.ls, 0);

        s = sizage(Codex::SHA2_256.code()).unwrap();
        assert_eq!(s.hs, 1);
        assert_eq!(s.ss, 0);
        assert_eq!(s.fs, 44);
        assert_eq!(s.ls, 0);

        s = sizage(Codex::ECDSA_256k1_Seed.code()).unwrap();
        assert_eq!(s.hs, 1);
        assert_eq!(s.ss, 0);
        assert_eq!(s.fs, 44);
        assert_eq!(s.ls, 0);

        s = sizage(Codex::Ed448_Seed.code()).unwrap();
        assert_eq!(s.hs, 1);
        assert_eq!(s.ss, 0);
        assert_eq!(s.fs, 76);
        assert_eq!(s.ls, 0);

        s = sizage(Codex::X448.code()).unwrap();
        assert_eq!(s.hs, 1);
        assert_eq!(s.ss, 0);
        assert_eq!(s.fs, 76);
        assert_eq!(s.ls, 0);

        s = sizage(Codex::Short.code()).unwrap();
        assert_eq!(s.hs, 1);
        assert_eq!(s.ss, 0);
        assert_eq!(s.fs, 4);
        assert_eq!(s.ls, 0);

        s = sizage(Codex::Big.code()).unwrap();
        assert_eq!(s.hs, 1);
        assert_eq!(s.ss, 0);
        assert_eq!(s.fs, 12);
        assert_eq!(s.ls, 0);

        s = sizage(Codex::X25519_Private.code()).unwrap();
        assert_eq!(s.hs, 1);
        assert_eq!(s.ss, 0);
        assert_eq!(s.fs, 44);
        assert_eq!(s.ls, 0);

        s = sizage(Codex::X25519_Cipher_Seed.code()).unwrap();
        assert_eq!(s.hs, 1);
        assert_eq!(s.ss, 0);
        assert_eq!(s.fs, 124);
        assert_eq!(s.ls, 0);

        s = sizage(Codex::Salt_128.code()).unwrap();
        assert_eq!(s.hs, 2);
        assert_eq!(s.ss, 0);
        assert_eq!(s.fs, 24);
        assert_eq!(s.ls, 0);

        s = sizage(Codex::Ed25519_Sig.code()).unwrap();
        assert_eq!(s.hs, 2);
        assert_eq!(s.ss, 0);
        assert_eq!(s.fs, 88);
        assert_eq!(s.ls, 0);

        s = sizage(Codex::ECDSA_256k1_Sig.code()).unwrap();
        assert_eq!(s.hs, 2);
        assert_eq!(s.ss, 0);
        assert_eq!(s.fs, 88);
        assert_eq!(s.ls, 0);

        s = sizage(Codex::Blake3_512.code()).unwrap();
        assert_eq!(s.hs, 2);
        assert_eq!(s.ss, 0);
        assert_eq!(s.fs, 88);
        assert_eq!(s.ls, 0);

        s = sizage(Codex::Blake2b_512.code()).unwrap();
        assert_eq!(s.hs, 2);
        assert_eq!(s.ss, 0);
        assert_eq!(s.fs, 88);
        assert_eq!(s.ls, 0);

        s = sizage(Codex::SHA3_512.code()).unwrap();
        assert_eq!(s.hs, 2);
        assert_eq!(s.ss, 0);
        assert_eq!(s.fs, 88);
        assert_eq!(s.ls, 0);

        s = sizage(Codex::SHA2_512.code()).unwrap();
        assert_eq!(s.hs, 2);
        assert_eq!(s.ss, 0);
        assert_eq!(s.fs, 88);
        assert_eq!(s.ls, 0);

        s = sizage(Codex::Long.code()).unwrap();
        assert_eq!(s.hs, 2);
        assert_eq!(s.ss, 0);
        assert_eq!(s.fs, 8);
        assert_eq!(s.ls, 0);

        s = sizage(Codex::ECDSA_256k1N.code()).unwrap();
        assert_eq!(s.hs, 4);
        assert_eq!(s.ss, 0);
        assert_eq!(s.fs, 48);
        assert_eq!(s.ls, 0);

        s = sizage(Codex::ECDSA_256k1.code()).unwrap();
        assert_eq!(s.hs, 4);
        assert_eq!(s.ss, 0);
        assert_eq!(s.fs, 48);
        assert_eq!(s.ls, 0);

        s = sizage(Codex::Ed448N.code()).unwrap();
        assert_eq!(s.hs, 4);
        assert_eq!(s.ss, 0);
        assert_eq!(s.fs, 80);
        assert_eq!(s.ls, 0);

        s = sizage(Codex::Ed448.code()).unwrap();
        assert_eq!(s.hs, 4);
        assert_eq!(s.ss, 0);
        assert_eq!(s.fs, 80);
        assert_eq!(s.ls, 0);

        s = sizage(Codex::Ed448_Sig.code()).unwrap();
        assert_eq!(s.hs, 4);
        assert_eq!(s.ss, 0);
        assert_eq!(s.fs, 56);
        assert_eq!(s.ls, 0);

        s = sizage(Codex::Tern.code()).unwrap();
        assert_eq!(s.hs, 4);
        assert_eq!(s.ss, 0);
        assert_eq!(s.fs, 8);
        assert_eq!(s.ls, 0);

        s = sizage(Codex::DateTime.code()).unwrap();
        assert_eq!(s.hs, 4);
        assert_eq!(s.ss, 0);
        assert_eq!(s.fs, 36);
        assert_eq!(s.ls, 0);

        s = sizage(Codex::X25519_Cipher_Salt.code()).unwrap();
        assert_eq!(s.hs, 4);
        assert_eq!(s.ss, 0);
        assert_eq!(s.fs, 100);
        assert_eq!(s.ls, 0);

        s = sizage(Codex::TBD1.code()).unwrap();
        assert_eq!(s.hs, 4);
        assert_eq!(s.ss, 0);
        assert_eq!(s.fs, 8);
        assert_eq!(s.ls, 1);

        s = sizage(Codex::TBD2.code()).unwrap();
        assert_eq!(s.hs, 4);
        assert_eq!(s.ss, 0);
        assert_eq!(s.fs, 8);
        assert_eq!(s.ls, 2);

        s = sizage(Codex::StrB64_L0.code()).unwrap();
        assert_eq!(s.hs, 2);
        assert_eq!(s.ss, 2);
        assert_eq!(s.fs, 0);
        assert_eq!(s.ls, 0);

        s = sizage(Codex::StrB64_L1.code()).unwrap();
        assert_eq!(s.hs, 2);
        assert_eq!(s.ss, 2);
        assert_eq!(s.fs, 0);
        assert_eq!(s.ls, 1);

        s = sizage(Codex::StrB64_L2.code()).unwrap();
        assert_eq!(s.hs, 2);
        assert_eq!(s.ss, 2);
        assert_eq!(s.fs, 0);
        assert_eq!(s.ls, 2);

        s = sizage(Codex::StrB64_Big_L0.code()).unwrap();
        assert_eq!(s.hs, 4);
        assert_eq!(s.ss, 4);
        assert_eq!(s.fs, 0);
        assert_eq!(s.ls, 0);

        s = sizage(Codex::StrB64_Big_L1.code()).unwrap();
        assert_eq!(s.hs, 4);
        assert_eq!(s.ss, 4);
        assert_eq!(s.fs, 0);
        assert_eq!(s.ls, 1);

        s = sizage(Codex::StrB64_Big_L2.code()).unwrap();
        assert_eq!(s.hs, 4);
        assert_eq!(s.ss, 4);
        assert_eq!(s.fs, 0);
        assert_eq!(s.ls, 2);

        s = sizage(Codex::Bytes_L0.code()).unwrap();
        assert_eq!(s.hs, 2);
        assert_eq!(s.ss, 2);
        assert_eq!(s.fs, 0);
        assert_eq!(s.ls, 0);

        s = sizage(Codex::Bytes_L1.code()).unwrap();
        assert_eq!(s.hs, 2);
        assert_eq!(s.ss, 2);
        assert_eq!(s.fs, 0);
        assert_eq!(s.ls, 1);

        s = sizage(Codex::Bytes_L2.code()).unwrap();
        assert_eq!(s.hs, 2);
        assert_eq!(s.ss, 2);
        assert_eq!(s.fs, 0);
        assert_eq!(s.ls, 2);

        s = sizage(Codex::Bytes_Big_L0.code()).unwrap();
        assert_eq!(s.hs, 4);
        assert_eq!(s.ss, 4);
        assert_eq!(s.fs, 0);
        assert_eq!(s.ls, 0);

        s = sizage(Codex::Bytes_Big_L1.code()).unwrap();
        assert_eq!(s.hs, 4);
        assert_eq!(s.ss, 4);
        assert_eq!(s.fs, 0);
        assert_eq!(s.ls, 1);

        s = sizage(Codex::Bytes_Big_L2.code()).unwrap();
        assert_eq!(s.hs, 4);
        assert_eq!(s.ss, 4);
        assert_eq!(s.fs, 0);
        assert_eq!(s.ls, 2);
    }

    #[test]
    fn test_hardage() {
        assert_eq!(hardage('A').unwrap(), 1);
        assert_eq!(hardage('G').unwrap(), 1);
        assert_eq!(hardage('b').unwrap(), 1);
        assert_eq!(hardage('z').unwrap(), 1);
        assert_eq!(hardage('1').unwrap(), 4);
        assert_eq!(hardage('0').unwrap(), 2);
    }

    #[test]
    fn test_codes() {
        assert_eq!(Codex::Ed25519_Seed.code(), "A");
        assert_eq!(Codex::Ed25519N.code(), "B");
        assert_eq!(Codex::X25519.code(), "C");
        assert_eq!(Codex::Ed25519.code(), "D");
        assert_eq!(Codex::Blake3_256.code(), "E");
        assert_eq!(Codex::Blake2b_256.code(), "F");
        assert_eq!(Codex::Blake2s_256.code(), "G");
        assert_eq!(Codex::SHA3_256.code(), "H");
        assert_eq!(Codex::SHA2_256.code(), "I");
        assert_eq!(Codex::ECDSA_256k1_Seed.code(), "J");
        assert_eq!(Codex::Ed448_Seed.code(), "K");
        assert_eq!(Codex::X448.code(), "L");
        assert_eq!(Codex::Short.code(), "M");
        assert_eq!(Codex::Big.code(), "N");
        assert_eq!(Codex::X25519_Private.code(), "O");
        assert_eq!(Codex::X25519_Cipher_Seed.code(), "P");
        assert_eq!(Codex::Salt_128.code(), "0A");
        assert_eq!(Codex::Ed25519_Sig.code(), "0B");
        assert_eq!(Codex::ECDSA_256k1_Sig.code(), "0C");
        assert_eq!(Codex::Blake3_512.code(), "0D");
        assert_eq!(Codex::Blake2b_512.code(), "0E");
        assert_eq!(Codex::SHA3_512.code(), "0F");
        assert_eq!(Codex::SHA2_512.code(), "0G");
        assert_eq!(Codex::Long.code(), "0H");
        assert_eq!(Codex::ECDSA_256k1N.code(), "1AAA");
        assert_eq!(Codex::ECDSA_256k1.code(), "1AAB");
        assert_eq!(Codex::Ed448N.code(), "1AAC");
        assert_eq!(Codex::Ed448.code(), "1AAD");
        assert_eq!(Codex::Ed448_Sig.code(), "1AAE");
        assert_eq!(Codex::Tern.code(), "1AAF");
        assert_eq!(Codex::DateTime.code(), "1AAG");
        assert_eq!(Codex::X25519_Cipher_Salt.code(), "1AAH");
        assert_eq!(Codex::TBD1.code(), "2AAA");
        assert_eq!(Codex::TBD2.code(), "3AAA");
        assert_eq!(Codex::StrB64_L0.code(), "4A");
        assert_eq!(Codex::StrB64_L1.code(), "5A");
        assert_eq!(Codex::StrB64_L2.code(), "6A");
        assert_eq!(Codex::StrB64_Big_L0.code(), "7AAA");
        assert_eq!(Codex::StrB64_Big_L1.code(), "8AAA");
        assert_eq!(Codex::StrB64_Big_L2.code(), "9AAA");
        assert_eq!(Codex::Bytes_L0.code(), "4B");
        assert_eq!(Codex::Bytes_L1.code(), "5B");
        assert_eq!(Codex::Bytes_L2.code(), "6B");
        assert_eq!(Codex::Bytes_Big_L0.code(), "7AAB");
        assert_eq!(Codex::Bytes_Big_L1.code(), "8AAB");
        assert_eq!(Codex::Bytes_Big_L2.code(), "9AAB");

        assert_eq!(Codex::from_code("A").unwrap(), Codex::Ed25519_Seed);
        assert_eq!(Codex::from_code("B").unwrap(), Codex::Ed25519N);
        assert_eq!(Codex::from_code("C").unwrap(), Codex::X25519);
        assert_eq!(Codex::from_code("D").unwrap(), Codex::Ed25519);
        assert_eq!(Codex::from_code("E").unwrap(), Codex::Blake3_256);
        assert_eq!(Codex::from_code("F").unwrap(), Codex::Blake2b_256);
        assert_eq!(Codex::from_code("G").unwrap(), Codex::Blake2s_256);
        assert_eq!(Codex::from_code("H").unwrap(), Codex::SHA3_256);
        assert_eq!(Codex::from_code("I").unwrap(), Codex::SHA2_256);
        assert_eq!(Codex::from_code("J").unwrap(), Codex::ECDSA_256k1_Seed);
        assert_eq!(Codex::from_code("K").unwrap(), Codex::Ed448_Seed);
        assert_eq!(Codex::from_code("L").unwrap(), Codex::X448);
        assert_eq!(Codex::from_code("M").unwrap(), Codex::Short);
        assert_eq!(Codex::from_code("N").unwrap(), Codex::Big);
        assert_eq!(Codex::from_code("O").unwrap(), Codex::X25519_Private);
        assert_eq!(Codex::from_code("P").unwrap(), Codex::X25519_Cipher_Seed);
        assert_eq!(Codex::from_code("0A").unwrap(), Codex::Salt_128);
        assert_eq!(Codex::from_code("0B").unwrap(), Codex::Ed25519_Sig);
        assert_eq!(Codex::from_code("0C").unwrap(), Codex::ECDSA_256k1_Sig);
        assert_eq!(Codex::from_code("0D").unwrap(), Codex::Blake3_512);
        assert_eq!(Codex::from_code("0E").unwrap(), Codex::Blake2b_512);
        assert_eq!(Codex::from_code("0F").unwrap(), Codex::SHA3_512);
        assert_eq!(Codex::from_code("0G").unwrap(), Codex::SHA2_512);
        assert_eq!(Codex::from_code("0H").unwrap(), Codex::Long);
        assert_eq!(Codex::from_code("1AAA").unwrap(), Codex::ECDSA_256k1N);
        assert_eq!(Codex::from_code("1AAB").unwrap(), Codex::ECDSA_256k1);
        assert_eq!(Codex::from_code("1AAC").unwrap(), Codex::Ed448N);
        assert_eq!(Codex::from_code("1AAD").unwrap(), Codex::Ed448);
        assert_eq!(Codex::from_code("1AAE").unwrap(), Codex::Ed448_Sig);
        assert_eq!(Codex::from_code("1AAF").unwrap(), Codex::Tern);
        assert_eq!(Codex::from_code("1AAG").unwrap(), Codex::DateTime);
        assert_eq!(Codex::from_code("1AAH").unwrap(), Codex::X25519_Cipher_Salt);
        assert_eq!(Codex::from_code("2AAA").unwrap(), Codex::TBD1);
        assert_eq!(Codex::from_code("3AAA").unwrap(), Codex::TBD2);
        assert_eq!(Codex::from_code("4A").unwrap(), Codex::StrB64_L0);
        assert_eq!(Codex::from_code("5A").unwrap(), Codex::StrB64_L1);
        assert_eq!(Codex::from_code("6A").unwrap(), Codex::StrB64_L2);
        assert_eq!(Codex::from_code("7AAA").unwrap(), Codex::StrB64_Big_L0);
        assert_eq!(Codex::from_code("8AAA").unwrap(), Codex::StrB64_Big_L1);
        assert_eq!(Codex::from_code("9AAA").unwrap(), Codex::StrB64_Big_L2);
        assert_eq!(Codex::from_code("4B").unwrap(), Codex::Bytes_L0);
        assert_eq!(Codex::from_code("5B").unwrap(), Codex::Bytes_L1);
        assert_eq!(Codex::from_code("6B").unwrap(), Codex::Bytes_L2);
        assert_eq!(Codex::from_code("7AAB").unwrap(), Codex::Bytes_Big_L0);
        assert_eq!(Codex::from_code("8AAB").unwrap(), Codex::Bytes_Big_L1);
        assert_eq!(Codex::from_code("9AAB").unwrap(), Codex::Bytes_Big_L2);
    }

    #[test]
    fn test_unhappy_paths() {
        assert!(hardage('-').is_err());
        assert!(hardage('_').is_err());
        assert!(hardage('#').is_err());
        assert!(Codex::from_code("CESR").is_err());
    }
}
