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

pub(crate) fn hardage(c: char) -> Result<u32> {
    match c {
        'A'..='Z' | 'a'..='z' => Ok(1),
        '0' | '4' | '5' | '6' => Ok(2),
        '1' | '2' | '3' | '7' | '8' | '9' => Ok(4),
        '-' => err!(Error::UnexpectedCode("count code start".to_string())),
        '_' => err!(Error::UnexpectedCode("op code start".to_string())),
        _ => err!(Error::UnknownHardage(c.to_string())),
    }
}

pub(crate) fn bardage(b: u8) -> Result<u32> {
    match b {
        b'\x00'..=b'\x33' => Ok(1),
        b'\x34' | b'\x38'..=b'\x3a' => Ok(2),
        b'\x35'..=b'\x37' | b'\x3b'..=b'\x3d' => Ok(4),
        b'\x3e' => err!(Error::UnexpectedCode("count code start".to_string())),
        b'\x3f' => err!(Error::UnexpectedCode("op code start".to_string())),
        _ => err!(Error::UnknownBardage(b.to_string())),
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
    use crate::core::matter::tables::{bardage, hardage, sizage, Codex};
    use rstest::rstest;

    #[rstest]
    #[case("A", 1, 0, 44, 0)]
    #[case("B", 1, 0, 44, 0)]
    #[case("C", 1, 0, 44, 0)]
    #[case("D", 1, 0, 44, 0)]
    #[case("E", 1, 0, 44, 0)]
    #[case("F", 1, 0, 44, 0)]
    #[case("G", 1, 0, 44, 0)]
    #[case("H", 1, 0, 44, 0)]
    #[case("I", 1, 0, 44, 0)]
    #[case("J", 1, 0, 44, 0)]
    #[case("K", 1, 0, 76, 0)]
    #[case("L", 1, 0, 76, 0)]
    #[case("M", 1, 0, 4, 0)]
    #[case("N", 1, 0, 12, 0)]
    #[case("O", 1, 0, 44, 0)]
    #[case("P", 1, 0, 124, 0)]
    #[case("0A", 2, 0, 24, 0)]
    #[case("0B", 2, 0, 88, 0)]
    #[case("0C", 2, 0, 88, 0)]
    #[case("0D", 2, 0, 88, 0)]
    #[case("0E", 2, 0, 88, 0)]
    #[case("0F", 2, 0, 88, 0)]
    #[case("0G", 2, 0, 88, 0)]
    #[case("0H", 2, 0, 8, 0)]
    #[case("1AAA", 4, 0, 48, 0)]
    #[case("1AAB", 4, 0, 48, 0)]
    #[case("1AAC", 4, 0, 80, 0)]
    #[case("1AAD", 4, 0, 80, 0)]
    #[case("1AAE", 4, 0, 56, 0)]
    #[case("1AAF", 4, 0, 8, 0)]
    #[case("1AAG", 4, 0, 36, 0)]
    #[case("1AAH", 4, 0, 100, 0)]
    #[case("2AAA", 4, 0, 8, 1)]
    #[case("3AAA", 4, 0, 8, 2)]
    #[case("4A", 2, 2, 0, 0)]
    #[case("5A", 2, 2, 0, 1)]
    #[case("6A", 2, 2, 0, 2)]
    #[case("7AAA", 4, 4, 0, 0)]
    #[case("8AAA", 4, 4, 0, 1)]
    #[case("9AAA", 4, 4, 0, 2)]
    #[case("4B", 2, 2, 0, 0)]
    #[case("5B", 2, 2, 0, 1)]
    #[case("6B", 2, 2, 0, 2)]
    #[case("7AAB", 4, 4, 0, 0)]
    #[case("8AAB", 4, 4, 0, 1)]
    #[case("9AAB", 4, 4, 0, 2)]
    fn test_sizage(
        #[case] code: &str,
        #[case] hs: u32,
        #[case] ss: u32,
        #[case] fs: u32,
        #[case] ls: u32,
    ) {
        let s = sizage(code).unwrap();
        assert_eq!(s.hs, hs);
        assert_eq!(s.ss, ss);
        assert_eq!(s.fs, fs);
        assert_eq!(s.ls, ls);
    }

    #[rstest]
    #[case('A', 1)]
    #[case('B', 1)]
    #[case('C', 1)]
    #[case('D', 1)]
    #[case('E', 1)]
    #[case('F', 1)]
    #[case('G', 1)]
    #[case('H', 1)]
    #[case('I', 1)]
    #[case('J', 1)]
    #[case('K', 1)]
    #[case('L', 1)]
    #[case('M', 1)]
    #[case('N', 1)]
    #[case('O', 1)]
    #[case('P', 1)]
    #[case('Q', 1)]
    #[case('R', 1)]
    #[case('S', 1)]
    #[case('T', 1)]
    #[case('U', 1)]
    #[case('V', 1)]
    #[case('W', 1)]
    #[case('X', 1)]
    #[case('Y', 1)]
    #[case('Z', 1)]
    #[case('a', 1)]
    #[case('b', 1)]
    #[case('c', 1)]
    #[case('d', 1)]
    #[case('e', 1)]
    #[case('f', 1)]
    #[case('g', 1)]
    #[case('h', 1)]
    #[case('i', 1)]
    #[case('j', 1)]
    #[case('k', 1)]
    #[case('l', 1)]
    #[case('m', 1)]
    #[case('n', 1)]
    #[case('o', 1)]
    #[case('p', 1)]
    #[case('q', 1)]
    #[case('r', 1)]
    #[case('s', 1)]
    #[case('t', 1)]
    #[case('u', 1)]
    #[case('v', 1)]
    #[case('w', 1)]
    #[case('x', 1)]
    #[case('y', 1)]
    #[case('z', 1)]
    #[case('0', 2)]
    #[case('4', 2)]
    #[case('5', 2)]
    #[case('6', 2)]
    #[case('1', 4)]
    #[case('2', 4)]
    #[case('3', 4)]
    #[case('7', 4)]
    #[case('8', 4)]
    #[case('9', 4)]
    fn test_hardage(#[case] code: char, #[case] hdg: u32) {
        assert_eq!(hardage(code).unwrap(), hdg);
    }

    #[rstest]
    #[case(Codex::Ed25519_Seed, "A")]
    #[case(Codex::Ed25519N, "B")]
    #[case(Codex::X25519, "C")]
    #[case(Codex::Ed25519, "D")]
    #[case(Codex::Blake3_256, "E")]
    #[case(Codex::Blake2b_256, "F")]
    #[case(Codex::Blake2s_256, "G")]
    #[case(Codex::SHA3_256, "H")]
    #[case(Codex::SHA2_256, "I")]
    #[case(Codex::ECDSA_256k1_Seed, "J")]
    #[case(Codex::Ed448_Seed, "K")]
    #[case(Codex::X448, "L")]
    #[case(Codex::Short, "M")]
    #[case(Codex::Big, "N")]
    #[case(Codex::X25519_Private, "O")]
    #[case(Codex::X25519_Cipher_Seed, "P")]
    #[case(Codex::Salt_128, "0A")]
    #[case(Codex::Ed25519_Sig, "0B")]
    #[case(Codex::ECDSA_256k1_Sig, "0C")]
    #[case(Codex::Blake3_512, "0D")]
    #[case(Codex::Blake2b_512, "0E")]
    #[case(Codex::SHA3_512, "0F")]
    #[case(Codex::SHA2_512, "0G")]
    #[case(Codex::Long, "0H")]
    #[case(Codex::ECDSA_256k1N, "1AAA")]
    #[case(Codex::ECDSA_256k1, "1AAB")]
    #[case(Codex::Ed448N, "1AAC")]
    #[case(Codex::Ed448, "1AAD")]
    #[case(Codex::Ed448_Sig, "1AAE")]
    #[case(Codex::Tern, "1AAF")]
    #[case(Codex::DateTime, "1AAG")]
    #[case(Codex::X25519_Cipher_Salt, "1AAH")]
    #[case(Codex::TBD1, "2AAA")]
    #[case(Codex::TBD2, "3AAA")]
    #[case(Codex::StrB64_L0, "4A")]
    #[case(Codex::StrB64_L1, "5A")]
    #[case(Codex::StrB64_L2, "6A")]
    #[case(Codex::StrB64_Big_L0, "7AAA")]
    #[case(Codex::StrB64_Big_L1, "8AAA")]
    #[case(Codex::StrB64_Big_L2, "9AAA")]
    #[case(Codex::Bytes_L0, "4B")]
    #[case(Codex::Bytes_L1, "5B")]
    #[case(Codex::Bytes_L2, "6B")]
    #[case(Codex::Bytes_Big_L0, "7AAB")]
    #[case(Codex::Bytes_Big_L1, "8AAB")]
    #[case(Codex::Bytes_Big_L2, "9AAB")]
    fn test_codes(#[case] variant: Codex, #[case] code: &str) {
        assert_eq!(variant.code(), code);
        assert_eq!(Codex::from_code(code).unwrap(), variant);
    }

    #[test]
    fn test_unhappy_paths() {
        assert!(hardage('-').is_err());
        assert!(hardage('_').is_err());
        assert!(hardage('#').is_err());
        assert!(bardage(0x40).is_err());
        assert!(Codex::from_code("CESR").is_err());
    }
}
