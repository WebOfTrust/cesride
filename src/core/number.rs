use crate::core::matter::{tables as matter, Matter};
use crate::error::{err, Error, Result};

#[derive(Debug, Clone, PartialEq)]
pub struct Number {
    raw: Vec<u8>,
    code: String,
    size: u32,
}

#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
pub mod tables {
    pub mod Codex {
        use crate::core::matter::tables as matter;

        pub const Short: &str = matter::Codex::Short; // Short 2 octet unsigned integer
        pub const Long: &str = matter::Codex::Long; // Long 4 octet unsigned integer
        pub const Big: &str = matter::Codex::Big; // Big 8 byte octet unsigned integer
        pub const Huge: &str = matter::Codex::Salt_128; // Huge 16 byte octet unsigned integer
    }
}

impl Default for Number {
    fn default() -> Self {
        Number { raw: vec![], code: matter::Codex::Short.to_string(), size: 0 }
    }
}

fn validate_code(code: &str) -> Result<()> {
    const CODES: &[&str] =
        &[tables::Codex::Short, tables::Codex::Long, tables::Codex::Big, tables::Codex::Huge];

    if !CODES.contains(&code) {
        return err!(Error::UnexpectedCode(code.to_string()));
    }

    Ok(())
}

impl Number {
    pub fn new(
        num: Option<u128>,
        numh: Option<&str>,
        code: Option<&str>,
        raw: Option<&[u8]>,
        qb64b: Option<&[u8]>,
        qb64: Option<&str>,
        qb2: Option<&[u8]>,
    ) -> Result<Self> {
        let number: Number = if raw.is_none() && qb64b.is_none() && qb64.is_none() && qb2.is_none()
        {
            let num = if let Some(num) = num {
                num
            } else if let Some(numh) = numh {
                if numh.is_empty() {
                    0
                } else {
                    u128::from_str_radix(numh, 16)?
                }
            } else {
                0
            };

            let code = if num < 256_u128.pow(2) {
                tables::Codex::Short
            } else if num < 256_u128.pow(4) {
                tables::Codex::Long
            } else if num < 256_u128.pow(8) {
                tables::Codex::Big
            } else {
                tables::Codex::Huge
            };

            let raw = match code {
                tables::Codex::Short => (num as u16).to_be_bytes().to_vec(),
                tables::Codex::Long => (num as u32).to_be_bytes().to_vec(),
                tables::Codex::Big => (num as u64).to_be_bytes().to_vec(),
                tables::Codex::Huge => num.to_be_bytes().to_vec(),
                // unreachable
                _ => return err!(Error::UnexpectedCode(code.to_string())),
            };

            Matter::new(Some(code), Some(&raw), None, qb64, None)?
        } else {
            let code = code.unwrap_or(tables::Codex::Short);
            validate_code(code)?;
            Matter::new(Some(code), raw, qb64b, qb64, qb2)?
        };

        Ok(number)
    }

    pub fn new_with_num(num: u128) -> Result<Self> {
        Self::new(Some(num), None, None, None, None, None, None)
    }

    pub fn new_with_numh(numh: &str) -> Result<Self> {
        Self::new(None, Some(numh), None, None, None, None, None)
    }

    pub fn new_with_raw(raw: &[u8], code: Option<&str>) -> Result<Self> {
        Self::new(None, None, code, Some(raw), None, None, None)
    }

    pub fn new_with_qb64b(qb64b: &[u8]) -> Result<Self> {
        Self::new(None, None, None, None, Some(qb64b), None, None)
    }

    pub fn new_with_qb64(qb64: &str) -> Result<Self> {
        Self::new(None, None, None, None, None, Some(qb64), None)
    }

    pub fn new_with_qb2(qb2: &[u8]) -> Result<Self> {
        Self::new(None, None, None, None, None, None, Some(qb2))
    }

    pub fn num(&self) -> Result<u128> {
        let num = match self.code().as_str() {
            tables::Codex::Short => {
                let mut bytes: [u8; 2] = [0; 2];
                bytes.copy_from_slice(self.raw().as_slice());
                u16::from_be_bytes(bytes) as u128
            }
            tables::Codex::Long => {
                let mut bytes: [u8; 4] = [0; 4];
                bytes.copy_from_slice(self.raw().as_slice());
                u32::from_be_bytes(bytes) as u128
            }
            tables::Codex::Big => {
                let mut bytes: [u8; 8] = [0; 8];
                bytes.copy_from_slice(self.raw().as_slice());
                u64::from_be_bytes(bytes) as u128
            }
            tables::Codex::Huge => {
                let mut bytes: [u8; 16] = [0; 16];
                bytes.copy_from_slice(self.raw().as_slice());
                u128::from_be_bytes(bytes)
            }
            // unreachable when using api
            _ => return err!(Error::UnexpectedCode(self.code())),
        };

        Ok(num)
    }

    pub fn numh(&self) -> Result<String> {
        let num = self.num()?;
        Ok(format!("{num:x}"))
    }

    pub fn positive(&self) -> Result<bool> {
        Ok(self.num()? > 0)
    }
}

impl Matter for Number {
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
    use crate::core::{
        matter::Matter,
        number::{tables as number, Number},
    };
    use rstest::rstest;

    #[test]
    fn convenience() {
        let num: u128 = 1;
        let numh = "1";
        let code = number::Codex::Short;
        let raw = b"\x00\x01";
        let nqb64 = "MAAB";
        let nqb64b = b"MAAB";
        let nqb2 = b"0\x00\x01";

        assert!(Number::new_with_num(num).is_ok());
        assert!(Number::new_with_numh(numh).is_ok());
        assert!(Number::new_with_raw(raw, Some(code)).is_ok());
        assert!(Number::new_with_qb64b(nqb64b).is_ok());
        assert!(Number::new_with_qb64(nqb64).is_ok());
        assert!(Number::new_with_qb2(nqb2).is_ok());
    }

    #[test]
    fn python_interop() {
        assert!(Number::new(None, None, None, Some(&[]), None, None, None).is_err());

        // defaults to 0
        let number = Number::new(None, None, None, None, None, None, None).unwrap();
        assert_eq!(number.code(), number::Codex::Short);
        assert_eq!(number.raw(), b"\x00\x00");
        assert_eq!(number.qb64().unwrap(), "MAAA");
        assert_eq!(number.qb64b().unwrap(), b"MAAA");
        assert_eq!(number.qb2().unwrap(), b"0\x00\x00");
        assert_eq!(number.num().unwrap(), 0);
        assert_eq!(number.numh().unwrap(), "0");
        assert!(!number.positive().unwrap());

        // empty string for numh defaults to 0
        let number = Number::new(None, Some(""), None, None, None, None, None).unwrap();
        assert_eq!(number.num().unwrap(), 0);

        assert!(Number::new(None, Some("invalid"), None, None, None, None, None).is_err());

        let num: u128 = 1;
        let numh = "1";
        let code = number::Codex::Short;
        let raw = b"\x00\x01";
        let nqb64 = "MAAB";
        let nqb64b = b"MAAB";
        let nqb2 = b"0\x00\x01";

        let number = Number::new(Some(num), None, None, None, None, None, None).unwrap();

        assert_eq!(number.code(), code);
        assert_eq!(number.raw(), raw);
        assert_eq!(number.qb64b().unwrap(), nqb64b);
        assert_eq!(number.qb64().unwrap(), nqb64);
        assert_eq!(number.qb2().unwrap(), nqb2);
        assert_eq!(number.num().unwrap(), num);
        assert_eq!(number.numh().unwrap(), numh);
        assert!(number.positive().unwrap());
    }

    #[test]
    fn unhappy_paths() {
        assert!(Number::new(None, None, Some("CESR"), Some(&[]), None, None, None).is_err());
    }

    #[rstest]
    #[case(0xffff, "ffff", number::Codex::Short, b"\xff\xff", "MP__", b"MP__", b"0\xff\xff", true)]
    #[case(
        0xffffffff,
        "ffffffff",
        number::Codex::Long,
        b"\xff\xff\xff\xff",
        "0HD_____",
        b"0HD_____",
        b"\xd0p\xff\xff\xff\xff",
        true
    )]
    #[case(
        0xffffffffffffffff,
        "ffffffffffffffff",
        number::Codex::Big,
        b"\xff\xff\xff\xff\xff\xff\xff\xff",
        "NP__________",
        b"NP__________",
        b"4\xff\xff\xff\xff\xff\xff\xff\xff",
        true
    )]
    #[case(
        0xffffffffffffffffffffffffffffffff,
        "ffffffffffffffffffffffffffffffff",
        number::Codex::Huge,
        b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff",
        "0AD_____________________",
        b"0AD_____________________",
        b"\xd0\x00\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff",
        true
    )]
    fn happy(
        #[case] num: u128,
        #[case] numh: &str,
        #[case] code: &str,
        #[case] raw: &[u8],
        #[case] nqb64: &str,
        #[case] nqb64b: &[u8],
        #[case] nqb2: &[u8],
        #[case] positive: bool,
        #[values(
            Number::new(Some(num), None, None, None, None, None, None).unwrap(),
            Number::new(None, Some(numh), None, None, None, None, None).unwrap(),
            Number::new(None, None, Some(code), Some(raw), None, None, None).unwrap(),
            Number::new(None, None, None, None, Some(nqb64b), None, None).unwrap(),
            Number::new(None, None, None, None, None, Some(nqb64), None).unwrap(),
            Number::new(None, None, None, None, None, None, Some(nqb2)).unwrap(),
        )]
        number: Number,
    ) {
        assert_eq!(number.code(), code);
        assert_eq!(number.raw(), raw);
        assert_eq!(number.qb64b().unwrap(), nqb64b);
        assert_eq!(number.qb64().unwrap(), nqb64);
        assert_eq!(number.qb2().unwrap(), nqb2);
        assert_eq!(number.num().unwrap(), num);
        assert_eq!(number.numh().unwrap(), numh);
        assert_eq!(number.positive().unwrap(), positive);
    }

    #[rstest]
    #[case(
        0xffff,
        "ffff",
        number::Codex::Short,
        b"\xff\xff",
        b"\xff\xff\xff",
        "MP__",
        b"MP__",
        b"0\xff\xff",
        true
    )]
    #[case(
        0xffffffff,
        "ffffffff",
        number::Codex::Long,
        b"\xff\xff\xff\xff",
        b"\xff\xff\xff\xff\xff",
        "0HD_____",
        b"0HD_____",
        b"\xd0p\xff\xff\xff\xff",
        true
    )]
    #[case(
        0xffffffffffffffff,
        "ffffffffffffffff",
        number::Codex::Big,
        b"\xff\xff\xff\xff\xff\xff\xff\xff",
        b"\xff\xff\xff\xff\xff\xff\xff\xff\xff",
        "NP__________",
        b"NP__________",
        b"4\xff\xff\xff\xff\xff\xff\xff\xff",
        true
    )]
    #[case(
        0xffffffffffffffffffffffffffffffff,
        "ffffffffffffffffffffffffffffffff",
        number::Codex::Huge,
        b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff",
        b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff",
        "0AD_____________________",
        b"0AD_____________________",
        b"\xd0\x00\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff",
        true
    )]
    fn truncates(
        #[case] num: u128,
        #[case] numh: &str,
        #[case] code: &str,
        #[case] raw: &[u8],
        #[case] raw_long: &[u8],
        #[case] nqb64: &str,
        #[case] nqb64b: &[u8],
        #[case] nqb2: &[u8],
        #[case] positive: bool,
    ) {
        let number = Number::new(None, None, Some(code), Some(raw_long), None, None, None).unwrap();

        assert_ne!(raw, raw_long);
        assert_eq!(number.code(), code);
        // this is the important assertion
        assert_eq!(number.raw(), raw);
        assert_eq!(number.qb64b().unwrap(), nqb64b);
        assert_eq!(number.qb64().unwrap(), nqb64);
        assert_eq!(number.qb2().unwrap(), nqb2);
        assert_eq!(number.num().unwrap(), num);
        assert_eq!(number.numh().unwrap(), numh);
        assert_eq!(number.positive().unwrap(), positive);

        // we also test that when raw is too short, an error is thrown
        assert!(Number::new(None, None, Some(code), Some(b"\xff"), None, None, None).is_err());
    }
}
