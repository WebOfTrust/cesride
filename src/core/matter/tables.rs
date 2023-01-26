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

pub(crate) fn sizage(s: &str) -> error::Result<Sizage> {
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

pub(crate) fn hardage(c: char) -> error::Result<i32> {
    match c {
        'A'..='Z' | 'a'..='z' => Ok(1),
        '0' | '4' | '5' | '6' => Ok(2),
        '1' | '2' | '3' | '7' | '8' | '9' => Ok(4),
        '-' => Err(Box::new(error::Error::UnexpectedCode(
            "count code start".to_owned(),
        ))),
        '_' => Err(Box::new(error::Error::UnexpectedCode(
            "op code start".to_owned(),
        ))),
        _ => Err(Box::new(error::Error::UnknownHardage(c.to_string()))),
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

    pub(crate) fn from_code(code: &str) -> error::Result<Self> {
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
            _ => return Err(Box::new(error::Error::UnexpectedCode(code.to_owned()))),
        })
    }
}

#[cfg(test)]
mod tables_tests {
    use crate::core::matter::tables::{hardage, sizage, Codex, Sizage};

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
    }
}
