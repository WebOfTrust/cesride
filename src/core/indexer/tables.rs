use crate::error::{Error, Result};
/// Codex is codex hard (stable) part of all indexer derivation codes.
///
/// Codes indicate which list of keys, current and/or prior next, index is for:
///
/// Indices in code may appear in both current signing and
/// prior next key lists when event has both current and prior
/// next key lists. Two character code table has only one index
/// so must be the same for both lists. Other index if for
/// prior next.
/// The indices may be different in those code tables which
/// have two sets of indices.
///
/// _Crt: Index in code for current signing key list only.
///
/// _Big: Big index values
///

pub(crate) const SMALL_VRZ_BYTES: u32 = 3;
pub(crate) const LARGE_VRZ_BYTES: u32 = 6;

#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
pub mod Codex {
    pub const Ed25519: &str = "A"; // Ed25519 sig appears same in both lists if any.
    pub const Ed25519_Crt: &str = "B"; // Ed25519 sig appears in current list only.
    pub const ECDSA_256k1: &str = "C"; // ECDSA secp256k1 sig appears same in both lists if any.
    pub const ECDSA_256k1_Crt: &str = "D"; // ECDSA secp256k1 sig appears in current list.
    pub const Ed448: &str = "0A"; // Ed448 signature appears in both lists.
    pub const Ed448_Crt: &str = "0B"; // Ed448 signature appears in current list only.
    pub const Ed25519_Big: &str = "2A"; // Ed25519 sig appears in both lists.
    pub const Ed25519_Big_Crt: &str = "2B"; // Ed25519 sig appears in current list only.
    pub const ECDSA_256k1_Big: &str = "2C"; // ECDSA secp256k1 sig appears in both lists.
    pub const ECDSA_256k1_Big_Crt: &str = "2D"; // ECDSA secp256k1 sig appears in current list only.
    pub const Ed448_Big: &str = "3A"; // Ed448 signature appears in both lists.
    pub const Ed448_Big_Crt: &str = "3B"; // Ed448 signature appears in current list only.
    pub const TBD0: &str = "0z"; // Test of Var len label L=N*4 <= 4095 char quadlets includes code
    pub const TBD1: &str = "1z"; // Test of index sig lead 1
    pub const TBD4: &str = "4z"; // Test of index sig lead 1 big
}

/// SigCodex is all indexed signature derivation codes
#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
pub mod SigCodex {
    pub const Ed25519: &str = "A"; // Ed25519 sig appears same in both lists if any.
    pub const Ed25519_Crt: &str = "B"; // Ed25519 sig appears in current list only.
    pub const ECDSA_256k1: &str = "C"; // ECDSA secp256k1 sig appears same in both lists if any.
    pub const ECDSA_256k1_Crt: &str = "D"; // ECDSA secp256k1 sig appears in current list.
    pub const Ed448: &str = "0A"; // Ed448 signature appears in both lists.
    pub const Ed448_Crt: &str = "0B"; // Ed448 signature appears in current list only.
    pub const Ed25519_Big: &str = "2A"; // Ed25519 sig appears in both lists.
    pub const Ed25519_Big_Crt: &str = "2B"; // Ed25519 sig appears in current list only.
    pub const ECDSA_256k1_Big: &str = "2C"; // ECDSA secp256k1 sig appears in both lists.
    pub const ECDSA_256k1_Big_Crt: &str = "2D"; // ECDSA secp256k1 sig appears in current list only.
    pub const Ed448_Big: &str = "3A"; // Ed448 signature appears in both lists.
    pub const Ed448_Big_Crt: &str = "3B"; // Ed448 signature appears in current list only.
}

/// CurrentSigCodex is codex indexed signature codes for current list.
#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
pub mod CurrentSigCodex {
    use lazy_static::lazy_static;

    pub const Ed25519_Crt: &str = "B"; // Ed25519 sig appears in current list only.
    pub const ECDSA_256k1_Crt: &str = "D"; // ECDSA secp256k1 sig appears in current list only.
    pub const Ed448_Crt: &str = "0B"; // Ed448 signature appears in current list only.
    pub const Ed25519_Big_Crt: &str = "2B"; // Ed25519 sig appears in current list only.
    pub const ECDSA_256k1_Big_Crt: &str = "2D"; // ECDSA secp256k1 sig appears in current list only.
    pub const Ed448_Big_Crt: &str = "3B"; // Ed448 signature appears in current list only.

    pub(crate) fn has_code(code: &str) -> bool {
        lazy_static! {
            static ref CODES: Vec<&'static str> = vec![
                Ed25519_Crt,
                ECDSA_256k1_Crt,
                Ed448_Crt,
                Ed25519_Big_Crt,
                ECDSA_256k1_Big_Crt,
                Ed448_Big_Crt
            ];
        }

        CODES.contains(&code)
    }
}

#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
pub mod BothSigCodex {
    use lazy_static::lazy_static;

    pub const Ed25519: &str = "A"; // Ed25519 sig appears same in both lists if any.
    pub const ECDSA_256k1: &str = "C"; // ECDSA secp256k1 sig appears same in both lists if any.
    pub const Ed448: &str = "0A"; // Ed448 signature appears in both lists.
    pub const Ed25519_Big: &str = "2A"; // Ed25519 sig appears in both listsy.
    pub const ECDSA_256k1_Big: &str = "2C"; // ECDSA secp256k1 sig appears in both lists.
    pub const Ed448_Big: &str = "3A"; // Ed448 signature appears in both lists.

    pub(crate) fn has_code(code: &str) -> bool {
        lazy_static! {
            static ref CODES: Vec<&'static str> =
                vec![Ed25519, ECDSA_256k1, Ed448, Ed25519_Big, ECDSA_256k1_Big, Ed448_Big];
        }

        CODES.contains(&code)
    }
}

/// Sizes table maps hs chars of code to Sizage (hs), ss, os, fs, ls)
/// where hs is hard size, ss is soft size, os is other index size,
/// and fs is full size, ls is lead size.
/// where ss includes os, so main index size ms = ss - os
/// soft size, ss, should always be  > 0 for Indexer
#[derive(Debug, PartialEq)]
pub(crate) struct Sizage {
    pub hs: u32,
    pub ss: u32,
    pub os: u32,
    pub ls: u32,
    pub fs: u32,
}

pub(crate) fn sizage(s: &str) -> Result<Sizage> {
    Ok(match s {
        "A" => Sizage { hs: 1, ss: 1, os: 0, fs: 88, ls: 0 },
        "B" => Sizage { hs: 1, ss: 1, os: 0, fs: 88, ls: 0 },
        "C" => Sizage { hs: 1, ss: 1, os: 0, fs: 88, ls: 0 },
        "D" => Sizage { hs: 1, ss: 1, os: 0, fs: 88, ls: 0 },
        "0A" => Sizage { hs: 2, ss: 2, os: 1, fs: 156, ls: 0 },
        "0B" => Sizage { hs: 2, ss: 2, os: 1, fs: 156, ls: 0 },
        "2A" => Sizage { hs: 2, ss: 4, os: 2, fs: 92, ls: 0 },
        "2B" => Sizage { hs: 2, ss: 4, os: 2, fs: 92, ls: 0 },
        "2C" => Sizage { hs: 2, ss: 4, os: 2, fs: 92, ls: 0 },
        "2D" => Sizage { hs: 2, ss: 4, os: 2, fs: 92, ls: 0 },
        "3A" => Sizage { hs: 2, ss: 6, os: 3, fs: 160, ls: 0 },
        "3B" => Sizage { hs: 2, ss: 6, os: 3, fs: 160, ls: 0 },
        "0z" => Sizage { hs: 2, ss: 2, os: 0, fs: 0, ls: 0 },
        "1z" => Sizage { hs: 2, ss: 2, os: 1, fs: 76, ls: 1 },
        "4z" => Sizage { hs: 2, ss: 6, os: 3, fs: 80, ls: 1 },
        _ => return Err(Box::new(Error::UnknownSizage(s.to_string()))),
    })
}

pub(crate) fn hardage(c: char) -> Result<u32> {
    match c {
        'A'..='Z' | 'a'..='z' => Ok(1),
        '0'..='4' => Ok(2),
        '-' => Err(Box::new(Error::UnexpectedCode("count code start".to_owned()))),
        '_' => Err(Box::new(Error::UnexpectedCode("op code start".to_owned()))),
        _ => Err(Box::new(Error::UnknownHardage(c.to_string()))),
    }
}

pub(crate) fn bardage(b: u8) -> Result<u32> {
    match b {
        b'\x00'..=b'\x33' => Ok(1),
        b'\x34'..=b'\x38' => Ok(2),
        b'\x3e' => Err(Box::new(Error::UnexpectedCode("count code start".to_owned()))),
        b'\x3f' => Err(Box::new(Error::UnexpectedCode("op code start".to_owned()))),
        _ => Err(Box::new(Error::UnknownBardage(b.to_string()))),
    }
}

#[cfg(test)]
mod index_tables_tests {
    use crate::core::indexer::tables::{
        bardage, hardage, sizage, BothSigCodex, Codex, CurrentSigCodex, SigCodex,
    };
    use rstest::rstest;

    #[rstest]
    #[case(Codex::Ed25519, "A")]
    #[case(Codex::Ed25519_Crt, "B")]
    #[case(Codex::ECDSA_256k1, "C")]
    #[case(Codex::ECDSA_256k1_Crt, "D")]
    #[case(Codex::Ed448, "0A")]
    #[case(Codex::Ed448_Crt, "0B")]
    #[case(Codex::Ed25519_Big, "2A")]
    #[case(Codex::Ed25519_Big_Crt, "2B")]
    #[case(Codex::ECDSA_256k1_Big, "2C")]
    #[case(Codex::ECDSA_256k1_Big_Crt, "2D")]
    #[case(Codex::Ed448_Big, "3A")]
    #[case(Codex::Ed448_Big_Crt, "3B")]
    #[case(Codex::TBD0, "0z")]
    #[case(Codex::TBD1, "1z")]
    #[case(Codex::TBD4, "4z")]
    fn test_codex(#[case] code: &str, #[case] value: &str) {
        assert_eq!(code, value);
    }

    #[rstest]
    #[case(SigCodex::Ed25519, "A")]
    #[case(SigCodex::Ed25519_Crt, "B")]
    #[case(SigCodex::ECDSA_256k1, "C")]
    #[case(SigCodex::ECDSA_256k1_Crt, "D")]
    #[case(SigCodex::Ed448, "0A")]
    #[case(SigCodex::Ed448_Crt, "0B")]
    #[case(SigCodex::Ed25519_Big, "2A")]
    #[case(SigCodex::Ed25519_Big_Crt, "2B")]
    #[case(SigCodex::ECDSA_256k1_Big, "2C")]
    #[case(SigCodex::ECDSA_256k1_Big_Crt, "2D")]
    #[case(SigCodex::Ed448_Big, "3A")]
    #[case(SigCodex::Ed448_Big_Crt, "3B")]
    fn test_sig_codex(#[case] code: &str, #[case] value: &str) {
        assert_eq!(code, value);
    }

    #[rstest]
    #[case(CurrentSigCodex::Ed25519_Crt, "B")]
    #[case(CurrentSigCodex::ECDSA_256k1_Crt, "D")]
    #[case(CurrentSigCodex::Ed448_Crt, "0B")]
    #[case(CurrentSigCodex::Ed25519_Big_Crt, "2B")]
    #[case(CurrentSigCodex::ECDSA_256k1_Big_Crt, "2D")]
    #[case(CurrentSigCodex::Ed448_Big_Crt, "3B")]
    fn test_current_sig_codex(#[case] code: &str, #[case] value: &str) {
        assert_eq!(code, value);
    }

    #[rstest]
    #[case(BothSigCodex::Ed25519, "A")]
    #[case(BothSigCodex::ECDSA_256k1, "C")]
    #[case(BothSigCodex::Ed448, "0A")]
    #[case(BothSigCodex::Ed25519_Big, "2A")]
    #[case(BothSigCodex::ECDSA_256k1_Big, "2C")]
    #[case(BothSigCodex::Ed448_Big, "3A")]
    fn test_both_sig_codex(#[case] code: &str, #[case] value: &str) {
        assert_eq!(code, value);
    }

    #[rstest]
    #[case("A", 1, 1, 0, 88, 0)]
    #[case("B", 1, 1, 0, 88, 0)]
    #[case("C", 1, 1, 0, 88, 0)]
    #[case("D", 1, 1, 0, 88, 0)]
    #[case("0A", 2, 2, 1, 156, 0)]
    #[case("0B", 2, 2, 1, 156, 0)]
    #[case("2A", 2, 4, 2, 92, 0)]
    #[case("2B", 2, 4, 2, 92, 0)]
    #[case("2C", 2, 4, 2, 92, 0)]
    #[case("2D", 2, 4, 2, 92, 0)]
    #[case("3A", 2, 6, 3, 160, 0)]
    #[case("3B", 2, 6, 3, 160, 0)]
    #[case("0z", 2, 2, 0, 0, 0)]
    #[case("1z", 2, 2, 1, 76, 1)]
    #[case("4z", 2, 6, 3, 80, 1)]
    fn test_sizage(
        #[case] code: &str,
        #[case] hs: u32,
        #[case] ss: u32,
        #[case] os: u32,
        #[case] fs: u32,
        #[case] ls: u32,
    ) {
        let s = sizage(code).unwrap();
        assert_eq!(s.hs, hs);
        assert_eq!(s.ss, ss);
        assert_eq!(s.os, os);
        assert_eq!(s.fs, fs);
        assert_eq!(s.ls, ls);
    }

    #[test]
    fn test_unkown_size() {
        assert!(sizage("z").is_err());
    }

    #[rstest]
    #[case('A', 1)]
    #[case('G', 1)]
    #[case('b', 1)]
    #[case('z', 1)]
    #[case('0', 2)]
    #[case('1', 2)]
    #[case('2', 2)]
    #[case('3', 2)]
    #[case('4', 2)]
    fn test_hardage(#[case] code: char, #[case] hdg: u32) {
        assert_eq!(hardage(code).unwrap(), hdg);
    }

    #[test]
    fn test_unexpected_count_code() {
        assert!(hardage('-').is_err());
    }

    #[test]
    fn test_unexpected_op_code() {
        assert!(hardage('_').is_err());
    }

    #[test]
    fn test_unknown_hardage() {
        assert!(hardage('8').is_err());
    }

    #[rstest]
    #[case(0x00, 1)]
    #[case(0x01, 1)]
    #[case(0x02, 1)]
    #[case(0x03, 1)]
    #[case(0x04, 1)]
    #[case(0x05, 1)]
    #[case(0x06, 1)]
    #[case(0x07, 1)]
    #[case(0x08, 1)]
    #[case(0x09, 1)]
    #[case(0x0a, 1)]
    #[case(0x0b, 1)]
    #[case(0x0c, 1)]
    #[case(0x0d, 1)]
    #[case(0x0e, 1)]
    #[case(0x0f, 1)]
    #[case(0x10, 1)]
    #[case(0x11, 1)]
    #[case(0x12, 1)]
    #[case(0x13, 1)]
    #[case(0x14, 1)]
    #[case(0x15, 1)]
    #[case(0x16, 1)]
    #[case(0x17, 1)]
    #[case(0x18, 1)]
    #[case(0x19, 1)]
    #[case(0x1a, 1)]
    #[case(0x1b, 1)]
    #[case(0x1c, 1)]
    #[case(0x1d, 1)]
    #[case(0x1e, 1)]
    #[case(0x1f, 1)]
    #[case(0x20, 1)]
    #[case(0x21, 1)]
    #[case(0x22, 1)]
    #[case(0x23, 1)]
    #[case(0x24, 1)]
    #[case(0x25, 1)]
    #[case(0x26, 1)]
    #[case(0x27, 1)]
    #[case(0x28, 1)]
    #[case(0x29, 1)]
    #[case(0x2a, 1)]
    #[case(0x2b, 1)]
    #[case(0x2c, 1)]
    #[case(0x2d, 1)]
    #[case(0x2e, 1)]
    #[case(0x2f, 1)]
    #[case(0x30, 1)]
    #[case(0x31, 1)]
    #[case(0x32, 1)]
    #[case(0x33, 1)]
    #[case(0x34, 2)]
    #[case(0x35, 2)]
    #[case(0x36, 2)]
    #[case(0x37, 2)]
    #[case(0x38, 2)]
    fn test_bardage(#[case] code: u8, #[case] bdg: u32) {
        assert_eq!(bardage(code).unwrap(), bdg);
    }

    #[test]
    fn test_unexpected_bardage_count_code() {
        assert!(bardage(0x3e).is_err());
    }

    #[test]
    fn test_unexpected_bardage_op_code() {
        assert!(bardage(0x3f).is_err());
    }

    #[test]
    fn test_unknown_bardage() {
        assert!(bardage(0x39).is_err());
    }
}
