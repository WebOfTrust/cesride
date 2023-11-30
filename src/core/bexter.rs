use crate::{
    core::{
        matter::{tables as matter, Matter},
        util::REB64_STRING,
    },
    error::{err, Error, Result},
};

use base64::{engine::general_purpose::URL_SAFE as b64_engine, Engine};
use lazy_static::lazy_static;
use regex::Regex;

pub trait Bext: Matter {
    fn bext(&self) -> Result<String> {
        let szg = matter::sizage(&self.code())?;

        let mut full_raw: Vec<u8> = vec![0; szg.ls as usize];
        full_raw.append(&mut self.raw());
        let bext = b64_engine.encode(&full_raw);

        let ws = if szg.ls == 0 {
            usize::from(!bext.is_empty() && bext[0..1] == *"A")
        } else {
            (szg.ls as usize + 1) % 4
        };

        Ok(bext[ws..].to_string())
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Bexter {
    code: String,
    raw: Vec<u8>,
    size: u32,
}

impl Default for Bexter {
    fn default() -> Self {
        Bexter { code: matter::Codex::StrB64_L0.to_string(), raw: vec![], size: 0 }
    }
}

pub mod tables {
    #[allow(non_snake_case)]
    #[allow(non_upper_case_globals)]
    pub mod Codex {
        use crate::core::matter::tables as matter;

        const StrB64_L0: &str = matter::Codex::StrB64_L0;
        const StrB64_L1: &str = matter::Codex::StrB64_L1;
        const StrB64_L2: &str = matter::Codex::StrB64_L2;
        const StrB64_Big_L0: &str = matter::Codex::StrB64_Big_L0;
        const StrB64_Big_L1: &str = matter::Codex::StrB64_Big_L1;
        const StrB64_Big_L2: &str = matter::Codex::StrB64_Big_L2;

        pub fn has_code(code: &str) -> bool {
            const CODES: &[&str] =
                &[StrB64_L0, StrB64_L1, StrB64_L2, StrB64_Big_L0, StrB64_Big_L1, StrB64_Big_L2];

            CODES.contains(&code)
        }
    }
}

fn validate_code(code: &str) -> Result<()> {
    if !tables::Codex::has_code(code) {
        return err!(Error::UnexpectedCode(code.to_string()));
    }

    Ok(())
}

pub(crate) fn rawify(bext: &str) -> Result<Vec<u8>> {
    let ts = bext.len() % 4;
    let ws = (4 - ts) % 4;
    let ls = (3 - ts) % 3;
    let base = vec!["A"; ws].join("") + bext;
    Ok(b64_engine.decode(base)?[ls..].to_vec())
}

impl Bexter {
    pub fn new(
        bext: Option<&str>,
        code: Option<&str>,
        raw: Option<&[u8]>,
        qb64b: Option<&[u8]>,
        qb64: Option<&str>,
        qb2: Option<&[u8]>,
    ) -> Result<Self> {
        lazy_static! {
            static ref REB64: Regex = Regex::new(REB64_STRING).unwrap();
        }

        let code = code.unwrap_or(matter::Codex::StrB64_L0);

        let bexter: Bexter = if bext.is_none()
            && raw.is_none()
            && qb64b.is_none()
            && qb64.is_none()
            && qb2.is_none()
        {
            return err!(Error::EmptyMaterial("missing bext string".to_string()));
        } else if let Some(bext) = bext {
            if !REB64.is_match(bext) {
                return err!(Error::Value("invalid base64".to_string()));
            }

            let raw = rawify(bext)?;

            Matter::new(Some(code), Some(&raw), None, None, None)?
        } else {
            Matter::new(Some(code), raw, qb64b, qb64, qb2)?
        };

        validate_code(&bexter.code())?;

        Ok(bexter)
    }

    pub fn new_with_bext(bext: &str) -> Result<Self> {
        Self::new(Some(bext), None, None, None, None, None)
    }

    pub fn new_with_raw(raw: &[u8], code: Option<&str>) -> Result<Self> {
        Self::new(None, code, Some(raw), None, None, None)
    }

    pub fn new_with_qb64b(qb64b: &[u8]) -> Result<Self> {
        Self::new(None, None, None, Some(qb64b), None, None)
    }

    pub fn new_with_qb64(qb64: &str) -> Result<Self> {
        Self::new(None, None, None, None, Some(qb64), None)
    }

    pub fn new_with_qb2(qb2: &[u8]) -> Result<Self> {
        Self::new(None, None, None, None, None, Some(qb2))
    }
}

impl Bext for Bexter {}

impl Matter for Bexter {
    fn code(&self) -> String {
        self.code.clone()
    }

    fn raw(&self) -> Vec<u8> {
        self.raw.clone()
    }

    fn size(&self) -> u32 {
        self.size
    }

    fn set_code(&mut self, code: &str) {
        self.code = code.to_string();
    }

    fn set_raw(&mut self, raw: &[u8]) {
        self.raw = raw.to_vec();
    }

    fn set_size(&mut self, size: u32) {
        self.size = size;
    }
}

#[cfg(test)]
mod test {
    use crate::core::bexter::{Bext, Bexter};
    use crate::core::matter::{tables as matter, Matter};

    use rstest::rstest;

    #[test]
    fn convenience() {
        assert!(Bexter::new_with_bext("A").is_ok());
        assert!(Bexter::new_with_raw(b"\x00\x00\x00", Some(matter::Codex::StrB64_L0)).is_ok());
        assert!(Bexter::new_with_qb64b(b"4AABAAAA").is_ok());
        assert!(Bexter::new_with_qb64("4AABAAAA").is_ok());
        assert!(Bexter::new_with_qb2(b"\xe0\x00\x01\x00\x00\x00").is_ok());
    }

    #[test]
    fn python_interop() {
        assert!(Bexter::new(None, None, None, None, None, None).is_err());

        let bext = "@!";
        assert!(Bexter::new(Some(bext), None, None, None, None, None).is_err());
    }

    #[rstest]
    #[case(
        "AAAA",
        matter::Codex::StrB64_L0,
        b"\x00\x00\x00",
        b"4AABAAAA",
        "4AABAAAA",
        b"\xe0\x00\x01\x00\x00\x00",
        "AAA"
    )]
    #[case(
        "ABBB",
        matter::Codex::StrB64_L0,
        b"\x00\x10A",
        b"4AABABBB",
        "4AABABBB",
        b"\xe0\x00\x01\x00\x10A",
        "BBB"
    )]
    fn snowflakes(
        #[case] bext: &str,
        #[case] code: &str,
        #[case] raw: &[u8],
        #[case] qb64b: &[u8],
        #[case] qb64: &str,
        #[case] qb2: &[u8],
        #[case] returned_bext: &str,
    ) {
        let bexter = Bexter::new(Some(bext), None, None, None, None, None).unwrap();
        assert_eq!(bexter.code(), code);
        assert_eq!(bexter.raw(), raw);
        assert_eq!(bexter.qb64b().unwrap(), qb64b);
        assert_eq!(bexter.qb64().unwrap(), qb64);
        assert_eq!(bexter.qb2().unwrap(), qb2);
        assert_eq!(bexter.bext().unwrap(), returned_bext);
    }

    #[rstest]
    #[case("", matter::Codex::StrB64_L0, b"", b"4AAA", "4AAA", b"\xe0\x00\x00")]
    #[case("-", matter::Codex::StrB64_L2, b">", b"6AABAAA-", "6AABAAA-", b"\xe8\x00\x01\x00\x00>")]
    #[case(
        "-A",
        matter::Codex::StrB64_L1,
        b"\x0f\x80",
        b"5AABAA-A",
        "5AABAA-A",
        b"\xe4\x00\x01\x00\x0f\x80"
    )]
    #[case(
        "-A-",
        matter::Codex::StrB64_L0,
        b"\x03\xe0>",
        b"4AABA-A-",
        "4AABA-A-",
        b"\xe0\x00\x01\x03\xe0>"
    )]
    #[case(
        "-A-B",
        matter::Codex::StrB64_L0,
        b"\xf8\x0f\x81",
        b"4AAB-A-B",
        "4AAB-A-B",
        b"\xe0\x00\x01\xf8\x0f\x81"
    )]
    #[case(
        "A",
        matter::Codex::StrB64_L2,
        b"\x00",
        b"6AABAAAA",
        "6AABAAAA",
        b"\xe8\x00\x01\x00\x00\x00"
    )]
    #[case(
        "AA",
        matter::Codex::StrB64_L1,
        b"\x00\x00",
        b"5AABAAAA",
        "5AABAAAA",
        b"\xe4\x00\x01\x00\x00\x00"
    )]
    #[case(
        "AAA",
        matter::Codex::StrB64_L0,
        b"\x00\x00\x00",
        b"4AABAAAA",
        "4AABAAAA",
        b"\xe0\x00\x01\x00\x00\x00"
    )]
    #[case(
        "ABB",
        matter::Codex::StrB64_L0,
        b"\x00\x00A",
        b"4AABAABB",
        "4AABAABB",
        b"\xe0\x00\x01\x00\x00A"
    )]
    #[case(
        "BBB",
        matter::Codex::StrB64_L0,
        b"\x00\x10A",
        b"4AABABBB",
        "4AABABBB",
        b"\xe0\x00\x01\x00\x10A"
    )]
    fn creation(
        #[case] bext: &str,
        #[case] code: &str,
        #[case] raw: &[u8],
        #[case] qb64b: &[u8],
        #[case] qb64: &str,
        #[case] qb2: &[u8],
    ) {
        let bexter = Bexter::new(Some(bext), None, None, None, None, None).unwrap();
        assert_eq!(bexter.code(), code);
        assert_eq!(bexter.raw(), raw);
        assert_eq!(bexter.qb64b().unwrap(), qb64b);
        assert_eq!(bexter.qb64().unwrap(), qb64);
        assert_eq!(bexter.qb2().unwrap(), qb2);
        assert_eq!(bexter.bext().unwrap(), bext);
    }

    #[rstest]
    fn unhappy() {
        assert!(Bexter::new(
            None,
            None,
            None,
            None,
            Some("DKxy2sgzfplyr-tgwIxS19f2OchFHtLwPWD3v4oYimBx"),
            None
        )
        .is_err());
    }
}
