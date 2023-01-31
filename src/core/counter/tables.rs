use crate::core::sizage::Sizage;
use crate::error::{Error, Result};

pub(crate) fn sizage(s: &str) -> Result<Sizage> {
    Ok(match s {
        "-A" => Sizage { hs: 2, ss: 2, fs: 4, ls: 0 },
        "-B" => Sizage { hs: 2, ss: 2, fs: 4, ls: 0 },
        "-C" => Sizage { hs: 2, ss: 2, fs: 4, ls: 0 },
        "-D" => Sizage { hs: 2, ss: 2, fs: 4, ls: 0 },
        "-E" => Sizage { hs: 2, ss: 2, fs: 4, ls: 0 },
        "-F" => Sizage { hs: 2, ss: 2, fs: 4, ls: 0 },
        "-G" => Sizage { hs: 2, ss: 2, fs: 4, ls: 0 },
        "-H" => Sizage { hs: 2, ss: 2, fs: 4, ls: 0 },
        "-I" => Sizage { hs: 2, ss: 2, fs: 4, ls: 0 },
        "-J" => Sizage { hs: 2, ss: 2, fs: 4, ls: 0 },
        "-K" => Sizage { hs: 2, ss: 2, fs: 4, ls: 0 },
        "-L" => Sizage { hs: 2, ss: 2, fs: 4, ls: 0 },
        "-V" => Sizage { hs: 2, ss: 2, fs: 4, ls: 0 },
        "-0V" => Sizage { hs: 3, ss: 5, fs: 8, ls: 0 },
        "--AAA" => Sizage { hs: 5, ss: 3, fs: 8, ls: 0 },
        _ => return Err(Box::new(Error::UnknownSizage(s.to_string()))),
    })
}

pub(crate) fn hardage(s: &str) -> Result<u32> {
    match s {
        "-A" | "-B" | "-C" | "-D" | "-E" | "-F" | "-G" | "-H" | "-I" | "-J" | "-K" | "-L"
        | "-V" => Ok(2),
        "-0" => Ok(3),
        "--" => Ok(5),
        _ => Err(Box::new(Error::UnknownHardage(s.to_string()))),
    }
}

pub(crate) fn bardage(b: &[u8]) -> Result<u32> {
    match b {
        [62, 0]
        | [62, 1]
        | [62, 2]
        | [62, 3]
        | [62, 4]
        | [62, 5]
        | [62, 6]
        | [62, 7]
        | [62, 8]
        | [62, 9]
        | [62, 10]
        | [62, 11]
        | [62, 21] => Ok(2),
        [62, 52] => Ok(3),
        [62, 62] => Ok(5),
        _ => Err(Box::new(Error::UnknownBardage(format!("{b:?}")))),
    }
}

#[derive(Debug, Eq, PartialEq, Clone)]
pub enum Codex {
    ControllerIdxSigs,
    WitnessIdxSigs,
    NonTransReceiptCouples,
    TransReceiptQuadruples,
    FirstSeenReplayCouples,
    TransIdxSigGroups,
    SealSourceCouples,
    TransLastIdxSigGroups,
    SealSourceTriples,
    SadPathSig,
    SadPathSigGroup,
    PathedMaterialQuadlets,
    AttachedMaterialQuadlets,
    BigAttachedMaterialQuadlets,
    KERIProtocolStack,
}

impl Codex {
    pub(crate) fn code(&self) -> &'static str {
        match self {
            Codex::ControllerIdxSigs => "-A", // Qualified Base64 Indexed Signature.
            Codex::WitnessIdxSigs => "-B",    // Qualified Base64 Indexed Signature.
            Codex::NonTransReceiptCouples => "-C", // Composed Base64 Couple, pre+cig.
            Codex::TransReceiptQuadruples => "-D", // Composed Base64 Quadruple, pre+snu+dig+sig.
            Codex::FirstSeenReplayCouples => "-E", // Composed Base64 Couple, fnu+dts.
            Codex::TransIdxSigGroups => "-F", // Composed Base64 Group, pre+snu+dig+ControllerIdxSigs group.
            Codex::SealSourceCouples => "-G", // Composed Base64 couple, snu+dig of given delegators or issuers event
            Codex::TransLastIdxSigGroups => "-H", // Composed Base64 Group, pre+ControllerIdxSigs group.
            Codex::SealSourceTriples => "-I", // Composed Base64 triple, pre+snu+dig of anchoring source event
            Codex::SadPathSig => "-J", // Composed Base64 Group path+TransIdxSigGroup of SAID of content
            Codex::SadPathSigGroup => "-K", // Composed Base64 Group, root(path)+SaidPathCouples
            Codex::PathedMaterialQuadlets => "-L", // Composed Grouped Pathed Material Quadlet (4 char each)
            Codex::AttachedMaterialQuadlets => "-V", // Composed Grouped Attached Material Quadlet (4 char each)
            Codex::BigAttachedMaterialQuadlets => "-0V", // Composed Grouped Attached Material Quadlet (4 char each)
            Codex::KERIProtocolStack => "--AAA",         // KERI ACDC Protocol Stack CESR Version
        }
    }

    pub(crate) fn from_code(code: &str) -> Result<Self> {
        Ok(match code {
            "-A" => Codex::ControllerIdxSigs,
            "-B" => Codex::WitnessIdxSigs,
            "-C" => Codex::NonTransReceiptCouples,
            "-D" => Codex::TransReceiptQuadruples,
            "-E" => Codex::FirstSeenReplayCouples,
            "-F" => Codex::TransIdxSigGroups,
            "-G" => Codex::SealSourceCouples,
            "-H" => Codex::TransLastIdxSigGroups,
            "-I" => Codex::SealSourceTriples,
            "-J" => Codex::SadPathSig,
            "-K" => Codex::SadPathSigGroup,
            "-L" => Codex::PathedMaterialQuadlets,
            "-V" => Codex::AttachedMaterialQuadlets,
            "-0V" => Codex::BigAttachedMaterialQuadlets,
            "--AAA" => Codex::KERIProtocolStack,
            _ => return Err(Box::new(Error::UnexpectedCode(code.to_string()))),
        })
    }
}

#[cfg(test)]
mod tables_tests {
    use super::{bardage, hardage, sizage, Codex, Sizage};

    #[test]
    fn test_hardage() {
        assert_eq!(hardage("-A").unwrap(), 2);
        assert_eq!(hardage("-G").unwrap(), 2);
        assert_eq!(hardage("-V").unwrap(), 2);
        assert_eq!(hardage("-0").unwrap(), 3);
        assert_eq!(hardage("--").unwrap(), 5);
    }

    #[test]
    fn test_sizage() {
        let mut s: Sizage;

        s = sizage("-A").unwrap();
        assert_eq!(s.hs, 2);
        assert_eq!(s.ss, 2);
        assert_eq!(s.fs, 4);
        assert_eq!(s.ls, 0);

        s = sizage("-B").unwrap();
        assert_eq!(s.hs, 2);
        assert_eq!(s.ss, 2);
        assert_eq!(s.fs, 4);
        assert_eq!(s.ls, 0);

        s = sizage("-C").unwrap();
        assert_eq!(s.hs, 2);
        assert_eq!(s.ss, 2);
        assert_eq!(s.fs, 4);
        assert_eq!(s.ls, 0);

        s = sizage("-D").unwrap();
        assert_eq!(s.hs, 2);
        assert_eq!(s.ss, 2);
        assert_eq!(s.fs, 4);
        assert_eq!(s.ls, 0);

        s = sizage("-E").unwrap();
        assert_eq!(s.hs, 2);
        assert_eq!(s.ss, 2);
        assert_eq!(s.fs, 4);
        assert_eq!(s.ls, 0);

        s = sizage("-F").unwrap();
        assert_eq!(s.hs, 2);
        assert_eq!(s.ss, 2);
        assert_eq!(s.fs, 4);
        assert_eq!(s.ls, 0);

        s = sizage("-G").unwrap();
        assert_eq!(s.hs, 2);
        assert_eq!(s.ss, 2);
        assert_eq!(s.fs, 4);
        assert_eq!(s.ls, 0);

        s = sizage("-H").unwrap();
        assert_eq!(s.hs, 2);
        assert_eq!(s.ss, 2);
        assert_eq!(s.fs, 4);
        assert_eq!(s.ls, 0);

        s = sizage("-I").unwrap();
        assert_eq!(s.hs, 2);
        assert_eq!(s.ss, 2);
        assert_eq!(s.fs, 4);
        assert_eq!(s.ls, 0);

        s = sizage("-J").unwrap();
        assert_eq!(s.hs, 2);
        assert_eq!(s.ss, 2);
        assert_eq!(s.fs, 4);
        assert_eq!(s.ls, 0);

        s = sizage("-K").unwrap();
        assert_eq!(s.hs, 2);
        assert_eq!(s.ss, 2);
        assert_eq!(s.fs, 4);
        assert_eq!(s.ls, 0);

        s = sizage("-L").unwrap();
        assert_eq!(s.hs, 2);
        assert_eq!(s.ss, 2);
        assert_eq!(s.fs, 4);
        assert_eq!(s.ls, 0);

        s = sizage("-V").unwrap();
        assert_eq!(s.hs, 2);
        assert_eq!(s.ss, 2);
        assert_eq!(s.fs, 4);
        assert_eq!(s.ls, 0);

        s = sizage("-0V").unwrap();
        assert_eq!(s.hs, 3);
        assert_eq!(s.ss, 5);
        assert_eq!(s.fs, 8);
        assert_eq!(s.ls, 0);

        s = sizage("--AAA").unwrap();
        assert_eq!(s.hs, 5);
        assert_eq!(s.ss, 3);
        assert_eq!(s.fs, 8);
        assert_eq!(s.ls, 0);
    }

    #[test]
    fn test_codex() {
        assert_eq!(Codex::ControllerIdxSigs.code(), "-A");
        assert_eq!(Codex::WitnessIdxSigs.code(), "-B");
        assert_eq!(Codex::NonTransReceiptCouples.code(), "-C");
        assert_eq!(Codex::TransReceiptQuadruples.code(), "-D");
        assert_eq!(Codex::FirstSeenReplayCouples.code(), "-E");
        assert_eq!(Codex::TransIdxSigGroups.code(), "-F");
        assert_eq!(Codex::SealSourceCouples.code(), "-G");
        assert_eq!(Codex::TransLastIdxSigGroups.code(), "-H");
        assert_eq!(Codex::SealSourceTriples.code(), "-I");
        assert_eq!(Codex::SadPathSig.code(), "-J");
        assert_eq!(Codex::SadPathSigGroup.code(), "-K");
        assert_eq!(Codex::PathedMaterialQuadlets.code(), "-L");
        assert_eq!(Codex::AttachedMaterialQuadlets.code(), "-V");
        assert_eq!(Codex::BigAttachedMaterialQuadlets.code(), "-0V");
        assert_eq!(Codex::KERIProtocolStack.code(), "--AAA");

        assert_eq!(Codex::from_code("-A").unwrap(), Codex::ControllerIdxSigs);
        assert_eq!(Codex::from_code("-B").unwrap(), Codex::WitnessIdxSigs);
        assert_eq!(Codex::from_code("-C").unwrap(), Codex::NonTransReceiptCouples);
        assert_eq!(Codex::from_code("-D").unwrap(), Codex::TransReceiptQuadruples);
        assert_eq!(Codex::from_code("-E").unwrap(), Codex::FirstSeenReplayCouples);
        assert_eq!(Codex::from_code("-F").unwrap(), Codex::TransIdxSigGroups);
        assert_eq!(Codex::from_code("-G").unwrap(), Codex::SealSourceCouples);
        assert_eq!(Codex::from_code("-H").unwrap(), Codex::TransLastIdxSigGroups);
        assert_eq!(Codex::from_code("-I").unwrap(), Codex::SealSourceTriples);
        assert_eq!(Codex::from_code("-J").unwrap(), Codex::SadPathSig);
        assert_eq!(Codex::from_code("-K").unwrap(), Codex::SadPathSigGroup);
        assert_eq!(Codex::from_code("-L").unwrap(), Codex::PathedMaterialQuadlets);
        assert_eq!(Codex::from_code("-V").unwrap(), Codex::AttachedMaterialQuadlets);
        assert_eq!(Codex::from_code("-0V").unwrap(), Codex::BigAttachedMaterialQuadlets);
        assert_eq!(Codex::from_code("--AAA").unwrap(), Codex::KERIProtocolStack);
    }

    #[test]
    fn test_unhappy_paths() {
        assert!(sizage("CESR").is_err());
        assert!(bardage(&[63, 0]).is_err());
        assert!(Codex::from_code("CESR").is_err());
    }
}
