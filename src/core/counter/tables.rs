use crate::error::{err, Error, Result};

#[derive(Debug, PartialEq)]
pub(crate) struct Sizage {
    pub hs: u32,
    pub ss: u32,
    pub ls: u32,
    pub fs: u32,
}

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
        _ => return err!(Error::UnknownSizage(s.to_string())),
    })
}

pub(crate) fn hardage(s: &str) -> Result<u32> {
    match s {
        "-A" | "-B" | "-C" | "-D" | "-E" | "-F" | "-G" | "-H" | "-I" | "-J" | "-K" | "-L"
        | "-V" => Ok(2),
        "-0" => Ok(3),
        "--" => Ok(5),
        _ => err!(Error::UnknownHardage(s.to_string())),
    }
}

pub(crate) fn bardage(b: &[u8]) -> Result<u32> {
    match b {
        b">\x00" | b">\x01" | b">\x02" | b">\x03" | b">\x04" | b">\x05" | b">\x06" | b">\x07"
        | b">\x08" | b">\x09" | b">\x0a" | b">\x0b" | b">\x15" => Ok(2),
        b">4" => Ok(3),
        b">>" => Ok(5),
        _ => err!(Error::UnknownBardage(format!("{b:?}"))),
    }
}

#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
pub mod Codex {
    pub const ControllerIdxSigs: &str = "-A"; // Qualified Base64 Indexed Signature.
    pub const WitnessIdxSigs: &str = "-B"; // Qualified Base64 Indexed Signature.
    pub const NonTransReceiptCouples: &str = "-C"; // Composed Base64 Couple, pre+cig.
    pub const TransReceiptQuadruples: &str = "-D"; // Composed Base64 Quadruple, pre+snu+dig+sig.
    pub const FirstSeenReplayCouples: &str = "-E"; // Composed Base64 Couple, fnu+dts.
    pub const TransIdxSigGroups: &str = "-F"; // Composed Base64 Group, pre+snu+dig+ControllerIdxSigs group.
    pub const SealSourceCouples: &str = "-G"; // Composed Base64 couple, snu+dig of given delegators or issuers event
    pub const TransLastIdxSigGroups: &str = "-H"; // Composed Base64 Group, pre+ControllerIdxSigs group.
    pub const SealSourceTriples: &str = "-I"; // Composed Base64 triple, pre+snu+dig of anchoring source event
    pub const SadPathSig: &str = "-J"; // Composed Base64 Group path+TransIdxSigGroup of SAID of content
    pub const SadPathSigGroup: &str = "-K"; // Composed Base64 Group, root(path)+SaidPathCouples
    pub const PathedMaterialQuadlets: &str = "-L"; // Composed Grouped Pathed Material Quadlet (4 char each)
    pub const AttachedMaterialQuadlets: &str = "-V"; // Composed Grouped Attached Material Quadlet (4 char each)
    pub const BigAttachedMaterialQuadlets: &str = "-0V"; // Composed Grouped Attached Material Quadlet (4 char each)
    pub const KERIProtocolStack: &str = "--AAA"; // KERI ACDC Protocol Stack CESR Version
}

#[cfg(test)]
mod tables_tests {
    use crate::core::counter::tables::{bardage, hardage, sizage, Codex};
    use rstest::rstest;

    #[rstest]
    #[case("-A", 2)]
    #[case("-B", 2)]
    #[case("-C", 2)]
    #[case("-D", 2)]
    #[case("-E", 2)]
    #[case("-F", 2)]
    #[case("-G", 2)]
    #[case("-H", 2)]
    #[case("-I", 2)]
    #[case("-J", 2)]
    #[case("-K", 2)]
    #[case("-L", 2)]
    #[case("-V", 2)]
    #[case("-0", 3)]
    #[case("--", 5)]
    fn test_hardage(#[case] code: &str, #[case] hdg: u32) {
        assert_eq!(hardage(code).unwrap(), hdg);
    }

    #[rstest]
    #[case(&[62, 0], 2)]
    #[case(&[62, 1], 2)]
    #[case(&[62, 2], 2)]
    #[case(&[62, 3], 2)]
    #[case(&[62, 4], 2)]
    #[case(&[62, 5], 2)]
    #[case(&[62, 6], 2)]
    #[case(&[62, 7], 2)]
    #[case(&[62, 8], 2)]
    #[case(&[62, 9], 2)]
    #[case(&[62, 10], 2)]
    #[case(&[62, 11], 2)]
    #[case(&[62, 21], 2)]
    #[case(&[62, 52], 3)]
    #[case(&[62, 62], 5)]
    fn test_bardage(#[case] bard: &[u8], #[case] bdg: u32) {
        assert_eq!(bardage(bard).unwrap(), bdg);
    }

    #[rstest]
    #[case("-A", 2, 2, 4, 0)]
    #[case("-B", 2, 2, 4, 0)]
    #[case("-C", 2, 2, 4, 0)]
    #[case("-D", 2, 2, 4, 0)]
    #[case("-E", 2, 2, 4, 0)]
    #[case("-F", 2, 2, 4, 0)]
    #[case("-G", 2, 2, 4, 0)]
    #[case("-H", 2, 2, 4, 0)]
    #[case("-I", 2, 2, 4, 0)]
    #[case("-J", 2, 2, 4, 0)]
    #[case("-K", 2, 2, 4, 0)]
    #[case("-L", 2, 2, 4, 0)]
    #[case("-V", 2, 2, 4, 0)]
    #[case("-0V", 3, 5, 8, 0)]
    #[case("--AAA", 5, 3, 8, 0)]
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
    #[case(Codex::ControllerIdxSigs, "-A")]
    #[case(Codex::WitnessIdxSigs, "-B")]
    #[case(Codex::NonTransReceiptCouples, "-C")]
    #[case(Codex::TransReceiptQuadruples, "-D")]
    #[case(Codex::FirstSeenReplayCouples, "-E")]
    #[case(Codex::TransIdxSigGroups, "-F")]
    #[case(Codex::SealSourceCouples, "-G")]
    #[case(Codex::TransLastIdxSigGroups, "-H")]
    #[case(Codex::SealSourceTriples, "-I")]
    #[case(Codex::SadPathSig, "-J")]
    #[case(Codex::SadPathSigGroup, "-K")]
    #[case(Codex::PathedMaterialQuadlets, "-L")]
    #[case(Codex::AttachedMaterialQuadlets, "-V")]
    #[case(Codex::BigAttachedMaterialQuadlets, "-0V")]
    #[case(Codex::KERIProtocolStack, "--AAA")]
    fn test_codex(#[case] code: &str, #[case] value: &str) {
        assert_eq!(code, value);
    }

    #[test]
    fn test_unhappy_paths() {
        assert!(sizage("CESR").is_err());
        assert!(bardage(&[63, 0]).is_err());
    }
}
