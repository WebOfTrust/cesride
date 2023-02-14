use lazy_static::lazy_static;

use crate::error::{err, Error, Result};
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

#[allow(non_camel_case_types)]
#[derive(Debug, Eq, PartialEq, Clone)]
pub(crate) enum Codex {
    Ed25519,
    Ed25519_Crt,
    ECDSA_256k1,
    ECDSA_256k1_Crt,
    Ed448,
    Ed448_Crt,
    Ed25519_Big,
    Ed25519_Big_Crt,
    ECDSA_256k1_Big,
    ECDSA_256k1_Big_Crt,
    Ed448_Big,
    Ed448_Big_Crt,
    TBD0,
    TBD1,
    TBD4,
}

impl Codex {
    pub(crate) fn code(&self) -> &'static str {
        match self {
            Codex::Ed25519 => "A",     // Ed25519 sig appears same in both lists if any.
            Codex::Ed25519_Crt => "B", // Ed25519 sig appears in current list only.
            Codex::ECDSA_256k1 => "C", // ECDSA secp256k1 sig appears same in both lists if any.
            Codex::ECDSA_256k1_Crt => "D", // ECDSA secp256k1 sig appears in current list.
            Codex::Ed448 => "0A",      // Ed448 signature appears in both lists.
            Codex::Ed448_Crt => "0B",  // Ed448 signature appears in current list only.
            Codex::Ed25519_Big => "2A", // Ed25519 sig appears in both lists.
            Codex::Ed25519_Big_Crt => "2B", // Ed25519 sig appears in current list only.
            Codex::ECDSA_256k1_Big => "2C", // ECDSA secp256k1 sig appears in both lists.
            Codex::ECDSA_256k1_Big_Crt => "2D", // ECDSA secp256k1 sig appears in current list only.
            Codex::Ed448_Big => "3A",  // Ed448 signature appears in both lists.
            Codex::Ed448_Big_Crt => "3B", // Ed448 signature appears in current list only.
            Codex::TBD0 => "0z", // Test of Var len label L=N*4 <= 4095 char quadlets includes code
            Codex::TBD1 => "1z", // Test of index sig lead 1
            Codex::TBD4 => "4z", // Test of index sig lead 1 big
        }
    }

    pub(crate) fn from_code(code: &str) -> Result<Self> {
        Ok(match code {
            "A" => Codex::Ed25519,
            "B" => Codex::Ed25519_Crt,
            "C" => Codex::ECDSA_256k1,
            "D" => Codex::ECDSA_256k1_Crt,
            "0A" => Codex::Ed448,
            "0B" => Codex::Ed448_Crt,
            "2A" => Codex::Ed25519_Big,
            "2B" => Codex::Ed25519_Big_Crt,
            "2C" => Codex::ECDSA_256k1_Big,
            "2D" => Codex::ECDSA_256k1_Big_Crt,
            "3A" => Codex::Ed448_Big,
            "3B" => Codex::Ed448_Big_Crt,
            "0z" => Codex::TBD0,
            "1z" => Codex::TBD1,
            "4z" => Codex::TBD4,
            _ => return err!(Error::UnexpectedCode(code.to_string())),
        })
    }
}

/// SigCodex is all indexed signature derivation codes
#[allow(non_camel_case_types, clippy::enum_variant_names)]
#[derive(Debug, Eq, PartialEq, Clone)]
pub(crate) enum SigCodex {
    Ed25519,
    Ed25519_Crt,
    ECDSA_256k1,
    ECDSA_256k1_Crt,
    Ed448,
    Ed448_Crt,
    Ed25519_Big,
    Ed25519_Big_Crt,
    ECDSA_256k1_Big,
    ECDSA_256k1_Big_Crt,
    Ed448_Big,
    Ed448_Big_Crt,
}

impl SigCodex {
    pub(crate) fn code(&self) -> &'static str {
        match self {
            SigCodex::Ed25519 => "A", // Ed25519 sig appears same in both lists if any.
            SigCodex::Ed25519_Crt => "B", // Ed25519 sig appears in current list only.
            SigCodex::ECDSA_256k1 => "C", // ECDSA secp256k1 sig appears same in both lists if any.
            SigCodex::ECDSA_256k1_Crt => "D", // ECDSA secp256k1 sig appears in current list.
            SigCodex::Ed448 => "0A",  // Ed448 signature appears in both lists.
            SigCodex::Ed448_Crt => "0B", // Ed448 signature appears in current list only.
            SigCodex::Ed25519_Big => "2A", // Ed25519 sig appears in both lists.
            SigCodex::Ed25519_Big_Crt => "2B", // Ed25519 sig appears in current list only.
            SigCodex::ECDSA_256k1_Big => "2C", // ECDSA secp256k1 sig appears in both lists.
            SigCodex::ECDSA_256k1_Big_Crt => "2D", // ECDSA secp256k1 sig appears in current list only.
            SigCodex::Ed448_Big => "3A",           // Ed448 signature appears in both lists.
            SigCodex::Ed448_Big_Crt => "3B",       // Ed448 signature appears in current list only.
        }
    }

    pub(crate) fn from_code(code: &str) -> Result<Self> {
        Ok(match code {
            "A" => SigCodex::Ed25519,
            "B" => SigCodex::Ed25519_Crt,
            "C" => SigCodex::ECDSA_256k1,
            "D" => SigCodex::ECDSA_256k1_Crt,
            "0A" => SigCodex::Ed448,
            "0B" => SigCodex::Ed448_Crt,
            "2A" => SigCodex::Ed25519_Big,
            "2B" => SigCodex::Ed25519_Big_Crt,
            "2C" => SigCodex::ECDSA_256k1_Big,
            "2D" => SigCodex::ECDSA_256k1_Big_Crt,
            "3A" => SigCodex::Ed448_Big,
            "3B" => SigCodex::Ed448_Big_Crt,
            _ => return err!(Error::UnexpectedCode(code.to_string())),
        })
    }
}

/// CurrentSigCodex is codex indexed signature codes for current list.
#[allow(non_camel_case_types, clippy::enum_variant_names)]
#[derive(Debug, Eq, PartialEq, Clone)]
pub(crate) enum CurrentSigCodex {
    Ed25519_Crt,
    ECDSA_256k1_Crt,
    Ed448_Crt,
    Ed25519_Big_Crt,
    ECDSA_256k1_Big_Crt,
    Ed448_Big_Crt,
}

impl CurrentSigCodex {
    pub(crate) fn code(&self) -> &'static str {
        match self {
            CurrentSigCodex::Ed25519_Crt => "B", // Ed25519 sig appears in current list only.
            CurrentSigCodex::ECDSA_256k1_Crt => "D", // ECDSA secp256k1 sig appears in current list only.
            CurrentSigCodex::Ed448_Crt => "0B", // Ed448 signature appears in current list only.
            CurrentSigCodex::Ed25519_Big_Crt => "2B", // Ed25519 sig appears in current list only.
            CurrentSigCodex::ECDSA_256k1_Big_Crt => "2D", // ECDSA secp256k1 sig appears in current list only.
            CurrentSigCodex::Ed448_Big_Crt => "3B", // Ed448 signature appears in current list only.
        }
    }

    pub(crate) fn from_code(code: &str) -> Result<Self> {
        Ok(match code {
            "B" => CurrentSigCodex::Ed25519_Crt,
            "D" => CurrentSigCodex::ECDSA_256k1_Crt,
            "0B" => CurrentSigCodex::Ed448_Crt,
            "2B" => CurrentSigCodex::Ed25519_Big_Crt,
            "2D" => CurrentSigCodex::ECDSA_256k1_Big_Crt,
            "3B" => CurrentSigCodex::Ed448_Big_Crt,
            _ => return Err(Box::new(Error::UnexpectedCode(code.to_string()))),
        })
    }

    pub(crate) fn has_code(code: &str) -> bool {
        lazy_static! {
            static ref CODES: Vec<&'static str> = vec![
                CurrentSigCodex::Ed25519_Crt.code(),
                CurrentSigCodex::ECDSA_256k1_Crt.code(),
                CurrentSigCodex::Ed448_Crt.code(),
                CurrentSigCodex::Ed25519_Big_Crt.code(),
                CurrentSigCodex::ECDSA_256k1_Big_Crt.code(),
                CurrentSigCodex::Ed448_Big_Crt.code(),
            ];
        }

        CODES.contains(&code)
    }
}

/// BothSigCodex is codex indexed signature codes for both lists.
#[allow(non_camel_case_types, clippy::enum_variant_names)]
#[derive(Debug, Eq, PartialEq, Clone)]
pub(crate) enum BothSigCodex {
    Ed25519,
    ECDSA_256k1,
    Ed448,
    Ed25519_Big,
    ECDSA_256k1_Big,
    Ed448_Big,
}

impl BothSigCodex {
    pub(crate) fn code(&self) -> &'static str {
        match self {
            BothSigCodex::Ed25519 => "A", // Ed25519 sig appears same in both lists if any.
            BothSigCodex::ECDSA_256k1 => "C", // ECDSA secp256k1 sig appears same in both lists if any.
            BothSigCodex::Ed448 => "0A",      // Ed448 signature appears in both lists.
            BothSigCodex::Ed25519_Big => "2A", // Ed25519 sig appears in both listsy.
            BothSigCodex::ECDSA_256k1_Big => "2C", // ECDSA secp256k1 sig appears in both lists.
            BothSigCodex::Ed448_Big => "3A",  // Ed448 signature appears in both lists.
        }
    }

    pub(crate) fn from_code(code: &str) -> Result<Self> {
        Ok(match code {
            "A" => BothSigCodex::Ed25519,
            "C" => BothSigCodex::ECDSA_256k1,
            "0A" => BothSigCodex::Ed448,
            "2A" => BothSigCodex::Ed25519_Big,
            "2C" => BothSigCodex::ECDSA_256k1_Big,
            "3A" => BothSigCodex::Ed448_Big,
            _ => return Err(Box::new(Error::UnexpectedCode(code.to_string()))),
        })
    }

    pub(crate) fn has_code(code: &str) -> bool {
        lazy_static! {
            static ref CODES: Vec<&'static str> = vec![
                BothSigCodex::Ed25519.code(),
                BothSigCodex::ECDSA_256k1.code(),
                BothSigCodex::Ed448.code(),
                BothSigCodex::Ed25519_Big.code(),
                BothSigCodex::ECDSA_256k1_Big.code(),
                BothSigCodex::Ed448_Big.code(),
            ];
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

#[cfg(test)]
mod index_tables_tests {
    use crate::core::indexer::tables::{
        hardage, sizage, BothSigCodex, Codex, CurrentSigCodex, SigCodex,
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
    fn test_codex(#[case] variant: Codex, #[case] code: &str) {
        assert_eq!(variant.code(), code);
        assert_eq!(Codex::from_code(code).unwrap(), variant);
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
    fn test_sig_code(#[case] variant: SigCodex, #[case] code: &str) {
        assert_eq!(variant.code(), code);
        assert_eq!(SigCodex::from_code(code).unwrap(), variant);
    }

    #[rstest]
    #[case(CurrentSigCodex::Ed25519_Crt, "B")]
    #[case(CurrentSigCodex::ECDSA_256k1_Crt, "D")]
    #[case(CurrentSigCodex::Ed448_Crt, "0B")]
    #[case(CurrentSigCodex::Ed25519_Big_Crt, "2B")]
    #[case(CurrentSigCodex::ECDSA_256k1_Big_Crt, "2D")]
    #[case(CurrentSigCodex::Ed448_Big_Crt, "3B")]
    fn test_current_code(#[case] variant: CurrentSigCodex, #[case] code: &str) {
        assert_eq!(variant.code(), code);
        assert_eq!(CurrentSigCodex::from_code(code).unwrap(), variant);
    }

    #[rstest]
    #[case(BothSigCodex::Ed25519, "A")]
    #[case(BothSigCodex::ECDSA_256k1, "C")]
    #[case(BothSigCodex::Ed448, "0A")]
    #[case(BothSigCodex::Ed25519_Big, "2A")]
    #[case(BothSigCodex::ECDSA_256k1_Big, "2C")]
    #[case(BothSigCodex::Ed448_Big, "3A")]
    fn test_both_code(#[case] variant: BothSigCodex, #[case] code: &str) {
        assert_eq!(variant.code(), code);
        assert_eq!(BothSigCodex::from_code(code).unwrap(), variant);
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

    #[test]
    fn test_sig_codex_from_code() {
        assert!(SigCodex::from_code("ZZ").is_err());
    }

    #[test]
    fn test_codex_from_code() {
        assert!(Codex::from_code("ZZ").is_err());
    }

    #[test]
    fn test_current_sig_from_code() {
        assert!(CurrentSigCodex::from_code("ZZ").is_err());
    }

    #[test]
    fn test_both_sig_from_code() {
        assert!(BothSigCodex::from_code("ZZ").is_err());
    }
}
