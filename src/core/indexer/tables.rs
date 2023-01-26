use crate::error::{self, Error};
/// Codex is codex hard (stable) part of all indexer derivation codes.
///
/// Codes indicate which list of keys, current and/or prior next, index is for:
///
/// _Sig:           Indices in code may appear in both current signing and
///                 prior next key lists when event has both current and prior
///                 next key lists. Two character code table has only one index
///                 so must be the same for both lists. Other index if for
///                 prior next.
///                 The indices may be different in those code tables which
///                 have two sets of indices.
///
/// _Crt_Sig:       Index in code for current signing key list only.
///
/// _Big_:          Big index values
#[allow(non_camel_case_types)]
#[derive(Debug, Eq, PartialEq, Clone)]
pub(crate) enum Codex {
    Ed25519_Sig,
    Ed25519_Crt_Sig,
    ECDSA_256k1_Sig,
    ECDSA_256k1_Crt_Sig,
    Ed448_Sig,
    Ed448_Crt_Sig,
    Ed25519_Big_Sig,
    Ed25519_Big_Crt_Sig,
    ECDSA_256k1_Big_Sig,
    ECDSA_256k1_Big_Crt_Sig,
    Ed448_Big_Sig,
    Ed448_Big_Crt_Sig,
    TBD0,
    TBD1,
    TBD4,
}

impl Codex {
    pub(crate) fn code(&self) -> &'static str {
        match self {
            Codex::Ed25519_Sig => "A", // Ed25519 sig appears same in both lists if any.
            Codex::Ed25519_Crt_Sig => "B", // Ed25519 sig appears in current list only.
            Codex::ECDSA_256k1_Sig => "C", // ECDSA secp256k1 sig appears same in both lists if any.
            Codex::ECDSA_256k1_Crt_Sig => "D", // ECDSA secp256k1 sig appears in current list.
            Codex::Ed448_Sig => "0A",  // Ed448 signature appears in both lists.
            Codex::Ed448_Crt_Sig => "0B", // Ed448 signature appears in current list only.
            Codex::Ed25519_Big_Sig => "2A", // Ed25519 sig appears in both lists.
            Codex::Ed25519_Big_Crt_Sig => "2B", // Ed25519 sig appears in current list only.
            Codex::ECDSA_256k1_Big_Sig => "2C", // ECDSA secp256k1 sig appears in both lists.
            Codex::ECDSA_256k1_Big_Crt_Sig => "2D", // ECDSA secp256k1 sig appears in current list only.
            Codex::Ed448_Big_Sig => "3A",           // Ed448 signature appears in both lists.
            Codex::Ed448_Big_Crt_Sig => "3B",       // Ed448 signature appears in current list only.
            Codex::TBD0 => "0z", // Test of Var len label L=N*4 <= 4095 char quadlets includes code
            Codex::TBD1 => "1z", // Test of index sig lead 1
            Codex::TBD4 => "4z", // Test of index sig lead 1 big
        }
    }
}

/// SigCodex is all indexed signature derivation codes
#[allow(non_camel_case_types)]
#[derive(Debug, Eq, PartialEq, Clone)]
pub(crate) enum SigCodex {
    Ed25519_Sig,
    Ed25519_Crt_Sig,
    ECDSA_256k1_Sig,
    ECDSA_256k1_Crt_Sig,
    Ed448_Sig,
    Ed448_Crt_Sig,
    Ed25519_Big_Sig,
    Ed25519_Big_Crt_Sig,
    ECDSA_256k1_Big_Sig,
    ECDSA_256k1_Big_Crt_Sig,
    Ed448_Big_Sig,
    Ed448_Big_Crt_Sig,
}

impl SigCodex {
    pub(crate) fn code(&self) -> &'static str {
        match self {
            SigCodex::Ed25519_Sig => "A", // Ed25519 sig appears same in both lists if any.
            SigCodex::Ed25519_Crt_Sig => "B", // Ed25519 sig appears in current list only.
            SigCodex::ECDSA_256k1_Sig => "C", // ECDSA secp256k1 sig appears same in both lists if any.
            SigCodex::ECDSA_256k1_Crt_Sig => "D", // ECDSA secp256k1 sig appears in current list.
            SigCodex::Ed448_Sig => "0A",      // Ed448 signature appears in both lists.
            SigCodex::Ed448_Crt_Sig => "0B",  // Ed448 signature appears in current list only.
            SigCodex::Ed25519_Big_Sig => "2A", // Ed25519 sig appears in both lists.
            SigCodex::Ed25519_Big_Crt_Sig => "2B", // Ed25519 sig appears in current list only.
            SigCodex::ECDSA_256k1_Big_Sig => "2C", // ECDSA secp256k1 sig appears in both lists.
            SigCodex::ECDSA_256k1_Big_Crt_Sig => "2D", // ECDSA secp256k1 sig appears in current list only.
            SigCodex::Ed448_Big_Sig => "3A",           // Ed448 signature appears in both lists.
            SigCodex::Ed448_Big_Crt_Sig => "3B", // Ed448 signature appears in current list only.
        }
    }
}

/// CurrentSigCodex is codex indexed signature codes for current list.
#[allow(non_camel_case_types)]
pub(crate) enum CurrentSigCodex {
    Ed25519_Crt_Sig,
    ECDSA_256k1_Crt_Sig,
    Ed448_Crt_Sig,
    Ed25519_Big_Crt_Sig,
    ECDSA_256k1_Big_Crt_Sig,
    Ed448_Big_Crt_Sig,
}

impl CurrentSigCodex {
    pub(crate) fn code(&self) -> &'static str {
        match self {
            CurrentSigCodex::Ed25519_Crt_Sig => "B", // Ed25519 sig appears in current list only.
            CurrentSigCodex::ECDSA_256k1_Crt_Sig => "D", // ECDSA secp256k1 sig appears in current list only.
            CurrentSigCodex::Ed448_Crt_Sig => "0B", // Ed448 signature appears in current list only.
            CurrentSigCodex::Ed25519_Big_Crt_Sig => "2B", // Ed25519 sig appears in current list only.
            CurrentSigCodex::ECDSA_256k1_Big_Crt_Sig => "2D", // ECDSA secp256k1 sig appears in current list only.
            CurrentSigCodex::Ed448_Big_Crt_Sig => "3B", // Ed448 signature appears in current list only.
        }
    }
}

/// BothSigCodex is codex indexed signature codes for both lists.
#[allow(non_camel_case_types)]
pub(crate) enum BothSigCodex {
    Ed25519_Sig,
    ECDSA_256k1_Sig,
    Ed448_Sig,
    Ed25519_Big_Sig,
    ECDSA_256k1_Big_Sig,
    Ed448_Big_Sig,
}

impl BothSigCodex {
    pub(crate) fn code(&self) -> &'static str {
        match self {
            BothSigCodex::Ed25519_Sig => "A", // Ed25519 sig appears same in both lists if any.
            BothSigCodex::ECDSA_256k1_Sig => "C", // ECDSA secp256k1 sig appears same in both lists if any.
            BothSigCodex::Ed448_Sig => "0A",      // Ed448 signature appears in both lists.
            BothSigCodex::Ed25519_Big_Sig => "2A", // Ed25519 sig appears in both listsy.
            BothSigCodex::ECDSA_256k1_Big_Sig => "2C", // ECDSA secp256k1 sig appears in both lists.
            BothSigCodex::Ed448_Big_Sig => "3A",  // Ed448 signature appears in both lists.
        }
    }
}

/// Sizes table maps hs chars of code to Sizage (hs), ss, os, fs, ls)
/// where hs is hard size, ss is soft size, os is other index size,
/// and fs is full size, ls is lead size.
/// where ss includes os, so main index size ms = ss - os
/// soft size, ss, should always be  > 0 for Indexer
#[derive(Debug, PartialEq)]
pub struct Sizage {
    pub hs: u32,
    pub ss: u32,
    pub os: u32,
    pub ls: u32,
    pub fs: u32,
}

impl Sizage {
    pub fn new(hs: u32, ss: u32, os: u32, fs: u32, ls: u32) -> Sizage {
        Self { hs, ss, os, ls, fs }
    }
}

pub(crate) fn sizage(s: &str) -> error::Result<Sizage> {
    match s {
        "A" => Ok(Sizage::new(1, 1, 0, 88, 0)),
        "B" => Ok(Sizage::new(1, 1, 0, 88, 0)),
        "C" => Ok(Sizage::new(1, 1, 0, 88, 0)),
        "D" => Ok(Sizage::new(1, 1, 0, 88, 0)),
        "0A" => Ok(Sizage::new(2, 2, 1, 156, 0)),
        "0B" => Ok(Sizage::new(2, 2, 1, 156, 0)),
        "2A" => Ok(Sizage::new(2, 4, 2, 92, 0)),
        "2B" => Ok(Sizage::new(2, 4, 2, 92, 0)),
        "2C" => Ok(Sizage::new(2, 4, 2, 92, 0)),
        "2D" => Ok(Sizage::new(2, 4, 2, 92, 0)),

        "3A" => Ok(Sizage::new(2, 6, 3, 160, 0)),
        "3B" => Ok(Sizage::new(2, 6, 3, 160, 0)),

        "0z" => Ok(Sizage::new(2, 2, 0, u32::MAX, 0)),
        "1z" => Ok(Sizage::new(2, 2, 1, 76, 1)),
        "4z" => Ok(Sizage::new(2, 6, 3, 80, 1)),
        _ => Err(Box::new(Error::UnknownSizage(s.to_string()))),
    }
}

pub(crate) fn hardage(c: char) -> error::Result<i32> {
    match c {
        'A'..='Z' | 'a'..='z' => Ok(1),
        '0'..='4' => Ok(2),
        '-' => Err(Box::new(error::Error::UnexpectedCode(
            "count code start".to_owned(),
        ))),
        '_' => Err(Box::new(error::Error::UnexpectedCode(
            "op code start".to_owned(),
        ))),
        _ => Err(Box::new(error::Error::UnknownHardage(c.to_string()))),
    }
}

#[cfg(test)]
mod index_tables_tests {
    use crate::core::indexer::tables::{
        hardage, sizage, BothSigCodex, Codex, CurrentSigCodex, SigCodex, Sizage,
    };

    #[test]
    fn test_codex() {
        assert_eq!(Codex::Ed25519_Sig.code(), "A");
        assert_eq!(Codex::Ed25519_Crt_Sig.code(), "B");
        assert_eq!(Codex::ECDSA_256k1_Sig.code(), "C");
        assert_eq!(Codex::ECDSA_256k1_Crt_Sig.code(), "D");
        assert_eq!(Codex::Ed448_Sig.code(), "0A");
        assert_eq!(Codex::Ed448_Crt_Sig.code(), "0B");
        assert_eq!(Codex::Ed25519_Big_Sig.code(), "2A");
        assert_eq!(Codex::Ed25519_Big_Crt_Sig.code(), "2B");
        assert_eq!(Codex::ECDSA_256k1_Big_Sig.code(), "2C");
        assert_eq!(Codex::ECDSA_256k1_Big_Crt_Sig.code(), "2D");
        assert_eq!(Codex::Ed448_Big_Sig.code(), "3A");
        assert_eq!(Codex::Ed448_Big_Crt_Sig.code(), "3B");
        assert_eq!(Codex::TBD0.code(), "0z");
        assert_eq!(Codex::TBD1.code(), "1z");
        assert_eq!(Codex::TBD4.code(), "4z");
    }

    #[test]
    fn test_sig_code() {
        assert_eq!(SigCodex::Ed25519_Sig.code(), "A");
        assert_eq!(SigCodex::Ed25519_Crt_Sig.code(), "B");
        assert_eq!(SigCodex::ECDSA_256k1_Sig.code(), "C");
        assert_eq!(SigCodex::ECDSA_256k1_Crt_Sig.code(), "D");
        assert_eq!(SigCodex::Ed448_Sig.code(), "0A");
        assert_eq!(SigCodex::Ed448_Crt_Sig.code(), "0B");
        assert_eq!(SigCodex::Ed25519_Big_Sig.code(), "2A");
        assert_eq!(SigCodex::Ed25519_Big_Crt_Sig.code(), "2B");
        assert_eq!(SigCodex::ECDSA_256k1_Big_Sig.code(), "2C");
        assert_eq!(SigCodex::ECDSA_256k1_Big_Crt_Sig.code(), "2D");
        assert_eq!(SigCodex::Ed448_Big_Sig.code(), "3A");
        assert_eq!(SigCodex::Ed448_Big_Crt_Sig.code(), "3B");
    }

    #[test]
    fn test_current_sig_code() {
        assert_eq!(CurrentSigCodex::Ed25519_Crt_Sig.code(), "B");
        assert_eq!(CurrentSigCodex::ECDSA_256k1_Crt_Sig.code(), "D");
        assert_eq!(CurrentSigCodex::Ed448_Crt_Sig.code(), "0B");
        assert_eq!(CurrentSigCodex::Ed25519_Big_Crt_Sig.code(), "2B");
        assert_eq!(CurrentSigCodex::ECDSA_256k1_Big_Crt_Sig.code(), "2D");
        assert_eq!(CurrentSigCodex::Ed448_Big_Crt_Sig.code(), "3B");
    }

    #[test]
    fn test_both_sig_code() {
        assert_eq!(BothSigCodex::Ed25519_Sig.code(), "A");
        assert_eq!(BothSigCodex::ECDSA_256k1_Sig.code(), "C");
        assert_eq!(BothSigCodex::Ed448_Sig.code(), "0A");
        assert_eq!(BothSigCodex::Ed25519_Big_Sig.code(), "2A");
        assert_eq!(BothSigCodex::ECDSA_256k1_Big_Sig.code(), "2C");
        assert_eq!(BothSigCodex::Ed448_Big_Sig.code(), "3A");
    }

    #[test]
    fn test_sizage() {
        let mut s: Sizage;

        s = sizage(Codex::Ed25519_Sig.code()).unwrap();
        assert_eq!(s.hs, 1);
        assert_eq!(s.ss, 1);
        assert_eq!(s.os, 0);
        assert_eq!(s.fs, 88);
        assert_eq!(s.ls, 0);

        s = sizage(Codex::Ed25519_Crt_Sig.code()).unwrap();
        assert_eq!(s.hs, 1);
        assert_eq!(s.ss, 1);
        assert_eq!(s.os, 0);
        assert_eq!(s.fs, 88);
        assert_eq!(s.ls, 0);

        s = sizage(Codex::ECDSA_256k1_Sig.code()).unwrap();
        assert_eq!(s.hs, 1);
        assert_eq!(s.ss, 1);
        assert_eq!(s.os, 0);
        assert_eq!(s.fs, 88);
        assert_eq!(s.ls, 0);

        s = sizage(Codex::ECDSA_256k1_Crt_Sig.code()).unwrap();
        assert_eq!(s.hs, 1);
        assert_eq!(s.ss, 1);
        assert_eq!(s.os, 0);
        assert_eq!(s.fs, 88);
        assert_eq!(s.ls, 0);

        s = sizage(Codex::Ed448_Sig.code()).unwrap();
        assert_eq!(s.hs, 2);
        assert_eq!(s.ss, 2);
        assert_eq!(s.os, 1);
        assert_eq!(s.fs, 156);
        assert_eq!(s.ls, 0);

        s = sizage(Codex::Ed448_Crt_Sig.code()).unwrap();
        assert_eq!(s.hs, 2);
        assert_eq!(s.ss, 2);
        assert_eq!(s.os, 1);
        assert_eq!(s.fs, 156);
        assert_eq!(s.ls, 0);

        s = sizage(Codex::Ed25519_Big_Sig.code()).unwrap();
        assert_eq!(s.hs, 2);
        assert_eq!(s.ss, 4);
        assert_eq!(s.os, 2);
        assert_eq!(s.fs, 92);
        assert_eq!(s.ls, 0);

        s = sizage(Codex::Ed25519_Big_Crt_Sig.code()).unwrap();
        assert_eq!(s.hs, 2);
        assert_eq!(s.ss, 4);
        assert_eq!(s.os, 2);
        assert_eq!(s.fs, 92);
        assert_eq!(s.ls, 0);

        s = sizage(Codex::ECDSA_256k1_Big_Sig.code()).unwrap();
        assert_eq!(s.hs, 2);
        assert_eq!(s.ss, 4);
        assert_eq!(s.os, 2);
        assert_eq!(s.fs, 92);
        assert_eq!(s.ls, 0);

        s = sizage(Codex::ECDSA_256k1_Big_Crt_Sig.code()).unwrap();
        assert_eq!(s.hs, 2);
        assert_eq!(s.ss, 4);
        assert_eq!(s.os, 2);
        assert_eq!(s.fs, 92);
        assert_eq!(s.ls, 0);

        s = sizage(Codex::Ed448_Big_Sig.code()).unwrap();
        assert_eq!(s.hs, 2);
        assert_eq!(s.ss, 6);
        assert_eq!(s.os, 3);
        assert_eq!(s.fs, 160);
        assert_eq!(s.ls, 0);

        s = sizage(Codex::Ed448_Big_Crt_Sig.code()).unwrap();
        assert_eq!(s.hs, 2);
        assert_eq!(s.ss, 6);
        assert_eq!(s.os, 3);
        assert_eq!(s.fs, 160);
        assert_eq!(s.ls, 0);

        s = sizage(Codex::TBD0.code()).unwrap();
        assert_eq!(s.hs, 2);
        assert_eq!(s.ss, 2);
        assert_eq!(s.os, 0);
        assert_eq!(s.fs, u32::MAX);
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
    #[should_panic(expected = "UnknownSizage(\"z\")")]
    fn test_unkown_size() {
        sizage("z").unwrap();
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
    #[should_panic(expected = "UnexpectedCode(\"count code start\")")]
    fn test_unexpected_count_code() {
        hardage('-').unwrap();
    }

    #[test]
    #[should_panic(expected = "UnexpectedCode(\"op code start\")")]
    fn test_unexpected_op_code() {
        hardage('_').unwrap();
    }

    #[test]
    #[should_panic(expected = "UnknownHardage(\"8\")")]
    fn test_unknown_hardage() {
        hardage('8').unwrap();
    }
}
