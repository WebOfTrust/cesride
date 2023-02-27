use crate::core::matter::{tables as matter, Matter};
use crate::error::{err, Error, Result};

#[derive(Debug, Clone, PartialEq)]
pub struct Seqner {
    raw: Vec<u8>,
    code: String,
    size: u32,
}

impl Default for Seqner {
    fn default() -> Self {
        Seqner { raw: vec![], code: matter::Codex::Salt_128.to_string(), size: 0 }
    }
}

fn validate_code(code: &str) -> Result<()> {
    if code != matter::Codex::Salt_128 {
        return err!(Error::UnexpectedCode(code.to_string()));
    }

    Ok(())
}

impl Seqner {
    pub fn new(
        sn: Option<u128>,
        snh: Option<&str>,
        code: Option<&str>,
        raw: Option<&[u8]>,
        qb64b: Option<&[u8]>,
        qb64: Option<&str>,
        qb2: Option<&[u8]>,
    ) -> Result<Self> {
        let buf;
        let code = code.unwrap_or(matter::Codex::Salt_128);

        let raw: Option<&[u8]> =
            if raw.is_none() && qb64b.is_none() && qb64.is_none() && qb2.is_none() {
                let sn = if let Some(sn) = sn {
                    sn
                } else if let Some(snh) = snh {
                    u128::from_str_radix(snh, 16)?
                } else {
                    0_u128
                };
                buf = sn.to_be_bytes();
                Some(&buf)
            } else {
                raw
            };
        let seqner: Seqner = Matter::new(Some(code), raw, qb64b, qb64, qb2)?;
        validate_code(&seqner.code)?;
        Ok(seqner)
    }

    pub fn new_with_sn(sn: u128) -> Result<Self> {
        Self::new(Some(sn), None, None, None, None, None, None)
    }

    pub fn new_with_snh(snh: &str) -> Result<Self> {
        Self::new(None, Some(snh), None, None, None, None, None)
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

    pub fn sn(&self) -> Result<u128> {
        Ok(u128::from_be_bytes(self.raw[0..16].try_into()?))
    }

    pub fn snh(&self) -> Result<String> {
        Ok(format!("{:x}", self.sn()?))
    }
}

impl Matter for Seqner {
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
    use super::{matter, Matter, Seqner};
    use rstest::rstest;

    #[test]
    fn convenience() {
        let raw = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0A";

        let seqner = Seqner::new(None, None, None, Some(raw), None, None, None).unwrap();

        assert!(Seqner::new_with_sn(seqner.sn().unwrap()).is_ok());
        assert!(Seqner::new_with_snh(&seqner.snh().unwrap()).is_ok());
        assert!(Seqner::new_with_raw(&seqner.raw(), Some(&seqner.code())).is_ok());
        assert!(Seqner::new_with_qb64b(&seqner.qb64b().unwrap()).is_ok());
        assert!(Seqner::new_with_qb64(&seqner.qb64().unwrap()).is_ok());
        assert!(Seqner::new_with_qb2(&seqner.qb2().unwrap()).is_ok());
    }

    #[rstest]
    #[case(
        "0AAAAAAAAAAAAAAAAAAAAAAA",
        b"\xd0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    )]
    fn new_default_and_zero(
        #[case] qb64: &str,
        #[case] qb2: &[u8],
        #[values(
            &Seqner::new(None, None, Some(matter::Codex::Salt_128), None, None, None, None).unwrap(),
            &Seqner::new(None, None, Some(matter::Codex::Salt_128), Some(b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"), None, None, None).unwrap(),
            &Seqner::new(Some(0), None, Some(matter::Codex::Salt_128), None, None, None, None).unwrap(),
            &Seqner::new(None, Some("0"), Some(matter::Codex::Salt_128), None, None, None, None).unwrap(),
            &Seqner::new(None, Some("00"), Some(matter::Codex::Salt_128), None, None, None, None).unwrap(),
            &Seqner::new(None, None, None, None, Some(qb64.as_bytes()), None, None).unwrap(),
            &Seqner::new(None, None, None, None, None, Some(qb64), None).unwrap(),
            &Seqner::new(None, None, None, None, None, None, Some(&mut qb2.to_vec())).unwrap(),
        )]
        seqner: &Seqner,
    ) {
        assert_eq!(seqner.raw, qb2[2..]);
        assert_eq!(seqner.code, matter::Codex::Salt_128);
        assert_eq!(seqner.sn().unwrap(), 0);
        assert_eq!(seqner.snh().unwrap(), "0");
        assert_eq!(seqner.qb64().unwrap(), qb64);
        assert_eq!(seqner.qb64b().unwrap(), qb64.as_bytes());
        assert_eq!(seqner.qb2().unwrap(), qb2);
    }

    #[rstest]
    #[case(
        "0AAAAAAAAAAAAAAAAAAAAAAK",
        b"\xd0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0A"
    )]
    fn new_with_data(
        #[case] qb64: &str,
        #[case] qb2: &[u8],
        #[values(
            &Seqner::new(None, None, Some(matter::Codex::Salt_128), Some(b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0A"), None, None, None).unwrap(),
            &Seqner::new(Some(10), None, Some(matter::Codex::Salt_128), None, None, None, None).unwrap(),
            &Seqner::new(None, Some("A"), Some(matter::Codex::Salt_128), None, None, None, None).unwrap(),
            &Seqner::new(None, Some("0A"), Some(matter::Codex::Salt_128), None, None, None, None).unwrap(),
            &Seqner::new(None, None, None, None, Some(qb64.as_bytes()), None, None).unwrap(),
            &Seqner::new(None, None, None, None, None, Some(qb64), None).unwrap(),
            &Seqner::new(None, None, None, None, None, None, Some(qb2)).unwrap(),
        )]
        seqner: &Seqner,
    ) {
        assert_eq!(seqner.raw, qb2[2..]);
        assert_eq!(seqner.code, matter::Codex::Salt_128);
        assert_eq!(seqner.sn().unwrap(), 10);
        assert_eq!(seqner.snh().unwrap(), "a");
        assert_eq!(seqner.qb64().unwrap(), qb64);
        assert_eq!(seqner.qb64b().unwrap(), qb64.as_bytes());
        assert_eq!(seqner.qb2().unwrap(), qb2);
    }

    #[rstest]
    #[case(
        "0AD_____________________",
        b"\xd0\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"
    )]
    fn new_max(
        #[case] qb64: &str,
        #[case] qb2: &[u8],
        #[values(
            &Seqner::new(None, None, Some(matter::Codex::Salt_128), Some(b"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"), None, None, None).unwrap(),
            &Seqner::new(Some(0xffffffffffffffffffffffffffffffff_u128), None, Some(matter::Codex::Salt_128), None, None, None, None).unwrap(),
            &Seqner::new(None, Some("ffffffffffffffffffffffffffffffff"), Some(matter::Codex::Salt_128), None, None, None, None).unwrap(),
            &Seqner::new(None, None, None, None, Some(qb64.as_bytes()), None, None).unwrap(),
            &Seqner::new(None, None, None, None, None, Some(qb64), None).unwrap(),
            &Seqner::new(None, None, None, None, None, None, Some(qb2)).unwrap(),
        )]
        seqner: &Seqner,
    ) {
        assert_eq!(seqner.raw, qb2[2..]);
        assert_eq!(seqner.code, matter::Codex::Salt_128);
        assert_eq!(seqner.sn().unwrap(), 340282366920938463463374607431768211455);
        assert_eq!(seqner.snh().unwrap(), "ffffffffffffffffffffffffffffffff");
        assert_eq!(seqner.qb64().unwrap(), qb64);
        assert_eq!(seqner.qb64b().unwrap(), qb64.as_bytes());
        assert_eq!(seqner.qb2().unwrap(), qb2);
    }

    #[rstest]
    #[case(
        // Empty code with empty raw is highly likely a programming error
        "",
        b""
    )]
    #[case(
        // Empty code with non-empty raw is highly likely a programming error
        "",
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0A"
    )]
    #[case(
        // Bad code
        matter::Codex::Big,
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0A"
    )]
    #[case(
        // Short Raw value
        matter::Codex::Salt_128,
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    )]
    fn unhappy_new_with_code_and_raw(#[case] code: &str, #[case] snraw: &[u8]) {
        assert!(Seqner::new(None, None, Some(code), Some(snraw), None, None, None).is_err());
    }

    #[rstest]
    fn unhappy_new_with_snh(
        #[values(
            // Bad values
            "",
            "not a hex",
            // Longer than the max one
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
        )]
        sns: &str,
    ) {
        assert!(Seqner::new(None, Some(sns), None, None, None, None, None).is_err());
    }

    #[rstest]
    fn unhappy_new_with_qb64(
        #[values(
            // Wrong code
            "0BAAAAAAAAAAAAAAAAAAAAAA",
            // Wrong code
            "0A_AAAAAAAAAAAAAAAAAAAAA",
            // Shortage
            "0AAAAAAAAAAAAAAAAAAAAAA",
        )]
        qb64: &str,
    ) {
        assert!(Seqner::new(None, None, None, None, Some(&qb64.as_bytes()), None, None).is_err());
        assert!(Seqner::new(None, None, None, None, None, Some(qb64), None).is_err());
    }

    #[rstest]
    fn unhappy_new_with_qb2(
        #[values(
            // Wrong code
            b"\xe0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            // Wrong code
            b"\xd0\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            // Wrong code
            b"\xd0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        )]
        qb2: &[u8],
    ) {
        assert!(Seqner::new(None, None, None, None, None, None, Some(qb2)).is_err());
    }
}
