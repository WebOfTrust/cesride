use lazy_static::lazy_static;

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

pub(crate) fn hardage(c: char) -> Result<i32> {
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
        hardage, sizage, BothSigCodex, Codex, CurrentSigCodex, SigCodex, Sizage,
    };

    #[test]
    fn test_codex() {
        assert_eq!(Codex::Ed25519.code(), "A");
        assert_eq!(Codex::Ed25519_Crt.code(), "B");
        assert_eq!(Codex::ECDSA_256k1.code(), "C");
        assert_eq!(Codex::ECDSA_256k1_Crt.code(), "D");
        assert_eq!(Codex::Ed448.code(), "0A");
        assert_eq!(Codex::Ed448_Crt.code(), "0B");
        assert_eq!(Codex::Ed25519_Big.code(), "2A");
        assert_eq!(Codex::Ed25519_Big_Crt.code(), "2B");
        assert_eq!(Codex::ECDSA_256k1_Big.code(), "2C");
        assert_eq!(Codex::ECDSA_256k1_Big_Crt.code(), "2D");
        assert_eq!(Codex::Ed448_Big.code(), "3A");
        assert_eq!(Codex::Ed448_Big_Crt.code(), "3B");
        assert_eq!(Codex::TBD0.code(), "0z");
        assert_eq!(Codex::TBD1.code(), "1z");
        assert_eq!(Codex::TBD4.code(), "4z");
    }

    #[test]
    fn test_code() {
        assert_eq!(SigCodex::Ed25519.code(), "A");
        assert_eq!(SigCodex::Ed25519_Crt.code(), "B");
        assert_eq!(SigCodex::ECDSA_256k1.code(), "C");
        assert_eq!(SigCodex::ECDSA_256k1_Crt.code(), "D");
        assert_eq!(SigCodex::Ed448.code(), "0A");
        assert_eq!(SigCodex::Ed448_Crt.code(), "0B");
        assert_eq!(SigCodex::Ed25519_Big.code(), "2A");
        assert_eq!(SigCodex::Ed25519_Big_Crt.code(), "2B");
        assert_eq!(SigCodex::ECDSA_256k1_Big.code(), "2C");
        assert_eq!(SigCodex::ECDSA_256k1_Big_Crt.code(), "2D");
        assert_eq!(SigCodex::Ed448_Big.code(), "3A");
        assert_eq!(SigCodex::Ed448_Big_Crt.code(), "3B");
    }

    #[test]
    fn test_current_code() {
        assert_eq!(CurrentSigCodex::Ed25519_Crt.code(), "B");
        assert_eq!(CurrentSigCodex::ECDSA_256k1_Crt.code(), "D");
        assert_eq!(CurrentSigCodex::Ed448_Crt.code(), "0B");
        assert_eq!(CurrentSigCodex::Ed25519_Big_Crt.code(), "2B");
        assert_eq!(CurrentSigCodex::ECDSA_256k1_Big_Crt.code(), "2D");
        assert_eq!(CurrentSigCodex::Ed448_Big_Crt.code(), "3B");
    }

    #[test]
    fn test_both_code() {
        assert_eq!(BothSigCodex::Ed25519.code(), "A");
        assert_eq!(BothSigCodex::ECDSA_256k1.code(), "C");
        assert_eq!(BothSigCodex::Ed448.code(), "0A");
        assert_eq!(BothSigCodex::Ed25519_Big.code(), "2A");
        assert_eq!(BothSigCodex::ECDSA_256k1_Big.code(), "2C");
        assert_eq!(BothSigCodex::Ed448_Big.code(), "3A");
    }

    #[test]
    fn test_sizage() {
        let mut s: Sizage;

        s = sizage(Codex::Ed25519.code()).unwrap();
        assert_eq!(s.hs, 1);
        assert_eq!(s.ss, 1);
        assert_eq!(s.os, 0);
        assert_eq!(s.fs, 88);
        assert_eq!(s.ls, 0);

        s = sizage(Codex::Ed25519_Crt.code()).unwrap();
        assert_eq!(s.hs, 1);
        assert_eq!(s.ss, 1);
        assert_eq!(s.os, 0);
        assert_eq!(s.fs, 88);
        assert_eq!(s.ls, 0);

        s = sizage(Codex::ECDSA_256k1.code()).unwrap();
        assert_eq!(s.hs, 1);
        assert_eq!(s.ss, 1);
        assert_eq!(s.os, 0);
        assert_eq!(s.fs, 88);
        assert_eq!(s.ls, 0);

        s = sizage(Codex::ECDSA_256k1_Crt.code()).unwrap();
        assert_eq!(s.hs, 1);
        assert_eq!(s.ss, 1);
        assert_eq!(s.os, 0);
        assert_eq!(s.fs, 88);
        assert_eq!(s.ls, 0);

        s = sizage(Codex::Ed448.code()).unwrap();
        assert_eq!(s.hs, 2);
        assert_eq!(s.ss, 2);
        assert_eq!(s.os, 1);
        assert_eq!(s.fs, 156);
        assert_eq!(s.ls, 0);

        s = sizage(Codex::Ed448_Crt.code()).unwrap();
        assert_eq!(s.hs, 2);
        assert_eq!(s.ss, 2);
        assert_eq!(s.os, 1);
        assert_eq!(s.fs, 156);
        assert_eq!(s.ls, 0);

        s = sizage(Codex::Ed25519_Big.code()).unwrap();
        assert_eq!(s.hs, 2);
        assert_eq!(s.ss, 4);
        assert_eq!(s.os, 2);
        assert_eq!(s.fs, 92);
        assert_eq!(s.ls, 0);

        s = sizage(Codex::Ed25519_Big_Crt.code()).unwrap();
        assert_eq!(s.hs, 2);
        assert_eq!(s.ss, 4);
        assert_eq!(s.os, 2);
        assert_eq!(s.fs, 92);
        assert_eq!(s.ls, 0);

        s = sizage(Codex::ECDSA_256k1_Big.code()).unwrap();
        assert_eq!(s.hs, 2);
        assert_eq!(s.ss, 4);
        assert_eq!(s.os, 2);
        assert_eq!(s.fs, 92);
        assert_eq!(s.ls, 0);

        s = sizage(Codex::ECDSA_256k1_Big_Crt.code()).unwrap();
        assert_eq!(s.hs, 2);
        assert_eq!(s.ss, 4);
        assert_eq!(s.os, 2);
        assert_eq!(s.fs, 92);
        assert_eq!(s.ls, 0);

        s = sizage(Codex::Ed448_Big.code()).unwrap();
        assert_eq!(s.hs, 2);
        assert_eq!(s.ss, 6);
        assert_eq!(s.os, 3);
        assert_eq!(s.fs, 160);
        assert_eq!(s.ls, 0);

        s = sizage(Codex::Ed448_Big_Crt.code()).unwrap();
        assert_eq!(s.hs, 2);
        assert_eq!(s.ss, 6);
        assert_eq!(s.os, 3);
        assert_eq!(s.fs, 160);
        assert_eq!(s.ls, 0);

        s = sizage(Codex::TBD0.code()).unwrap();
        assert_eq!(s.hs, 2);
        assert_eq!(s.ss, 2);
        assert_eq!(s.os, 0);
        assert_eq!(s.fs, 0);
        assert_eq!(s.ls, 0);

        s = sizage(Codex::TBD1.code()).unwrap();
        assert_eq!(s.hs, 2);
        assert_eq!(s.ss, 2);
        assert_eq!(s.os, 1);
        assert_eq!(s.fs, 76);
        assert_eq!(s.ls, 1);

        s = sizage(Codex::TBD4.code()).unwrap();
        assert_eq!(s.hs, 2);
        assert_eq!(s.ss, 6);
        assert_eq!(s.os, 3);
        assert_eq!(s.fs, 80);
        assert_eq!(s.ls, 1);
    }

    #[test]
    fn test_unkown_size() {
        assert!(sizage("z").is_err());
    }

    #[test]
    fn test_hardage() {
        assert_eq!(hardage('A').unwrap(), 1);
        assert_eq!(hardage('G').unwrap(), 1);
        assert_eq!(hardage('b').unwrap(), 1);
        assert_eq!(hardage('z').unwrap(), 1);
        assert_eq!(hardage('0').unwrap(), 2);
        assert_eq!(hardage('1').unwrap(), 2);
        assert_eq!(hardage('2').unwrap(), 2);
        assert_eq!(hardage('3').unwrap(), 2);
        assert_eq!(hardage('4').unwrap(), 2);
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
    fn test_current_sig_from_code() {
        assert_eq!(CurrentSigCodex::from_code("B").unwrap(), CurrentSigCodex::Ed25519_Crt);
        assert_eq!(CurrentSigCodex::from_code("D").unwrap(), CurrentSigCodex::ECDSA_256k1_Crt);
        assert_eq!(CurrentSigCodex::from_code("0B").unwrap(), CurrentSigCodex::Ed448_Crt);
        assert_eq!(CurrentSigCodex::from_code("2B").unwrap(), CurrentSigCodex::Ed25519_Big_Crt);
        assert_eq!(CurrentSigCodex::from_code("2D").unwrap(), CurrentSigCodex::ECDSA_256k1_Big_Crt);
        assert_eq!(CurrentSigCodex::from_code("3B").unwrap(), CurrentSigCodex::Ed448_Big_Crt);

        assert!(CurrentSigCodex::from_code("ZZ").is_err());
    }

    #[test]
    fn test_both_sig_from_code() {
        assert_eq!(BothSigCodex::from_code("A").unwrap(), BothSigCodex::Ed25519);
        assert_eq!(BothSigCodex::from_code("C").unwrap(), BothSigCodex::ECDSA_256k1);
        assert_eq!(BothSigCodex::from_code("0A").unwrap(), BothSigCodex::Ed448);
        assert_eq!(BothSigCodex::from_code("2A").unwrap(), BothSigCodex::Ed25519_Big);
        assert_eq!(BothSigCodex::from_code("2C").unwrap(), BothSigCodex::ECDSA_256k1_Big);
        assert_eq!(BothSigCodex::from_code("3A").unwrap(), BothSigCodex::Ed448_Big);

        assert!(BothSigCodex::from_code("ZZ").is_err());
    }
}
