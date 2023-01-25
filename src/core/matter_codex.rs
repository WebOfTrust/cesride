#[allow(non_camel_case_types)]
#[derive(Debug, Eq, PartialEq, Clone)]
pub enum MatterCodex {
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

impl MatterCodex {
    pub(crate) fn code(&self) -> &'static str {
        match self {
            MatterCodex::Ed25519_Seed => "A", // Ed25519 256 bit random seed for private key
            MatterCodex::Ed25519N => "B", // Ed25519 verification key non-transferable, basic derivation.
            MatterCodex::X25519 => "C", // X25519 public encryption key, converted from Ed25519 or Ed25519N.
            MatterCodex::Ed25519 => "D", // Ed25519 verification key basic derivation
            MatterCodex::Blake3_256 => "E", // Blake3 256 bit digest self-addressing derivation.
            MatterCodex::Blake2b_256 => "F", // Blake2b 256 bit digest self-addressing derivation.
            MatterCodex::Blake2s_256 => "G", // Blake2s 256 bit digest self-addressing derivation.
            MatterCodex::SHA3_256 => "H", // SHA3 256 bit digest self-addressing derivation.
            MatterCodex::SHA2_256 => "I", // SHA2 256 bit digest self-addressing derivation.
            MatterCodex::ECDSA_256k1_Seed => "J", // ECDSA secp256k1 256 bit random Seed for private key
            MatterCodex::Ed448_Seed => "K",       // Ed448 448 bit random Seed for private key
            MatterCodex::X448 => "L", // X448 public encryption key, converted from Ed448
            MatterCodex::Short => "M", // Short 2 byte b2 number
            MatterCodex::Big => "N",  // Big 8 byte b2 number
            MatterCodex::X25519_Private => "O", // X25519 private decryption key converted from Ed25519
            MatterCodex::X25519_Cipher_Seed => "P", // X25519 124 char b64 Cipher of 44 char qb64 Seed
            MatterCodex::Salt_128 => "0A", // 128 bit random salt or 128 bit number (see Huge)
            MatterCodex::Ed25519_Sig => "0B", // Ed25519 signature.
            MatterCodex::ECDSA_256k1_Sig => "0C", // ECDSA secp256k1 signature.
            MatterCodex::Blake3_512 => "0D", // Blake3 512 bit digest self-addressing derivation.
            MatterCodex::Blake2b_512 => "0E", // Blake2b 512 bit digest self-addressing derivation.
            MatterCodex::SHA3_512 => "0F", // SHA3 512 bit digest self-addressing derivation.
            MatterCodex::SHA2_512 => "0G", // SHA2 512 bit digest self-addressing derivation.
            MatterCodex::Long => "0H",     // Long 4 byte b2 number
            MatterCodex::ECDSA_256k1N => "1AAA", // ECDSA secp256k1 verification key non-transferable, basic derivation.
            MatterCodex::ECDSA_256k1 => "1AAB", // Ed25519 public verification or encryption key, basic derivation
            MatterCodex::Ed448N => "1AAC", // Ed448 non-transferable prefix public signing verification key. Basic derivation.
            MatterCodex::Ed448 => "1AAD", // Ed448 public signing verification key. Basic derivation.
            MatterCodex::Ed448_Sig => "1AAE", // Ed448 signature. Self-signing derivation.
            MatterCodex::Tern => "1AAF",  // 3 byte b2 number or 4 char B64 str.
            MatterCodex::DateTime => "1AAG", // Base64 custom encoded 32 char ISO-8601 DateTime
            MatterCodex::X25519_Cipher_Salt => "1AAH", // X25519 100 char b64 Cipher of 24 char qb64 Salt
            MatterCodex::TBD1 => "2AAA", // Testing purposes only fixed with lead size 1
            MatterCodex::TBD2 => "3AAA", // Testing purposes only of fixed with lead size 2
            MatterCodex::StrB64_L0 => "4A", // String Base64 Only Lead Size 0 (4095 * 3 | 4)
            MatterCodex::StrB64_L1 => "5A", // String Base64 Only Lead Size 1
            MatterCodex::StrB64_L2 => "6A", // String Base64 Only Lead Size 2
            MatterCodex::StrB64_Big_L0 => "7AAA", // String Base64 Only Big Lead Size 0 (16777215 * 3 | 4)
            MatterCodex::StrB64_Big_L1 => "8AAA", // String Base64 Only Big Lead Size 1
            MatterCodex::StrB64_Big_L2 => "9AAA", // String Base64 Only Big Lead Size 2
            MatterCodex::Bytes_L0 => "4B",        // Byte String Leader Size 0
            MatterCodex::Bytes_L1 => "5B",        // Byte String Leader Size 1
            MatterCodex::Bytes_L2 => "6B",        // Byte String Leader Size 2
            MatterCodex::Bytes_Big_L0 => "7AAB",  // Byte String Big Leader Size 0
            MatterCodex::Bytes_Big_L1 => "8AAB",  // Byte String Big Leader Size 1
            MatterCodex::Bytes_Big_L2 => "9AAB",  // Byte String Big Leader Size 2
        }
    }
}

#[cfg(test)]
mod matter_codex_tests {
    use crate::core::{matter::Matter, matter_codex::MatterCodex};

    #[test]
    fn test_codes() {
        assert_eq!(MatterCodex::Ed25519_Seed.code(), "A");
        assert_eq!(MatterCodex::Ed25519N.code(), "B");
        assert_eq!(MatterCodex::X25519.code(), "C");
        assert_eq!(MatterCodex::Ed25519.code(), "D");
        assert_eq!(MatterCodex::Blake3_256.code(), "E");
        assert_eq!(MatterCodex::Blake2b_256.code(), "F");
        assert_eq!(MatterCodex::Blake2s_256.code(), "G");
        assert_eq!(MatterCodex::SHA3_256.code(), "H");
        assert_eq!(MatterCodex::SHA2_256.code(), "I");
        assert_eq!(MatterCodex::ECDSA_256k1_Seed.code(), "J");
        assert_eq!(MatterCodex::Ed448_Seed.code(), "K");
        assert_eq!(MatterCodex::X448.code(), "L");
        assert_eq!(MatterCodex::Short.code(), "M");
        assert_eq!(MatterCodex::Big.code(), "N");
        assert_eq!(MatterCodex::X25519_Private.code(), "O");
        assert_eq!(MatterCodex::X25519_Cipher_Seed.code(), "P");
        assert_eq!(MatterCodex::Salt_128.code(), "0A");
        assert_eq!(MatterCodex::Ed25519_Sig.code(), "0B");
        assert_eq!(MatterCodex::ECDSA_256k1_Sig.code(), "0C");
        assert_eq!(MatterCodex::Blake3_512.code(), "0D");
        assert_eq!(MatterCodex::Blake2b_512.code(), "0E");
        assert_eq!(MatterCodex::SHA3_512.code(), "0F");
        assert_eq!(MatterCodex::SHA2_512.code(), "0G");
        assert_eq!(MatterCodex::Long.code(), "0H");
        assert_eq!(MatterCodex::ECDSA_256k1N.code(), "1AAA");
        assert_eq!(MatterCodex::ECDSA_256k1.code(), "1AAB");
        assert_eq!(MatterCodex::Ed448N.code(), "1AAC");
        assert_eq!(MatterCodex::Ed448.code(), "1AAD");
        assert_eq!(MatterCodex::Ed448_Sig.code(), "1AAE");
        assert_eq!(MatterCodex::Tern.code(), "1AAF");
        assert_eq!(MatterCodex::DateTime.code(), "1AAG");
        assert_eq!(MatterCodex::X25519_Cipher_Salt.code(), "1AAH");
        assert_eq!(MatterCodex::TBD1.code(), "2AAA");
        assert_eq!(MatterCodex::TBD2.code(), "3AAA");
        assert_eq!(MatterCodex::StrB64_L0.code(), "4A");
        assert_eq!(MatterCodex::StrB64_L1.code(), "5A");
        assert_eq!(MatterCodex::StrB64_L2.code(), "6A");
        assert_eq!(MatterCodex::StrB64_Big_L0.code(), "7AAA");
        assert_eq!(MatterCodex::StrB64_Big_L1.code(), "8AAA");
        assert_eq!(MatterCodex::StrB64_Big_L2.code(), "9AAA");
        assert_eq!(MatterCodex::Bytes_L0.code(), "4B");
        assert_eq!(MatterCodex::Bytes_L1.code(), "5B");
        assert_eq!(MatterCodex::Bytes_L2.code(), "6B");
        assert_eq!(MatterCodex::Bytes_Big_L0.code(), "7AAB");
        assert_eq!(MatterCodex::Bytes_Big_L1.code(), "8AAB");
        assert_eq!(MatterCodex::Bytes_Big_L2.code(), "9AAB");
    }
}
