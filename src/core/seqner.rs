use lazy_static::lazy_static;

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
    lazy_static! {
        static ref CODES: Vec<&'static str> = vec![matter::Codex::Salt_128,];
    }

    if !CODES.contains(&code) {
        return err!(Error::UnexpectedCode(code.to_string()));
    }

    Ok(())
}

impl Seqner {
    pub fn new_with_code_and_raw(code: &str, raw: &[u8]) -> Result<Self> {
        if !code.is_empty() {
            validate_code(code)?;
        }
        if raw.is_empty() {
            Matter::new_with_code_and_raw(matter::Codex::Salt_128, &[0u8; 16])
        } else {
            Matter::new_with_code_and_raw(code, raw)
        }
    }

    pub fn new_with_sn(sn: u128) -> Result<Self> {
        let ssn = sn.to_be_bytes();
        let seqner: Seqner = Matter::new_with_code_and_raw(matter::Codex::Salt_128, &ssn)?;
        validate_code(&seqner.code())?;
        Ok(seqner)
    }

    pub fn new_with_snh(snh: &str) -> Result<Self> {
        let seqner = if snh.is_empty() {
            Seqner::new_with_sn(0)?
        } else {
            let ssn = u128::from_str_radix(snh, 16)?.to_be_bytes();
            Matter::new_with_code_and_raw(matter::Codex::Salt_128, &ssn)?
        };
        validate_code(&seqner.code())?;
        Ok(seqner)
    }

    pub fn new_with_qb64(qb64: &str) -> Result<Self> {
        let seqner: Seqner = Matter::new_with_qb64(qb64)?;
        validate_code(&seqner.code())?;
        Ok(seqner)
    }

    pub fn new_with_qb64b(qb64b: &[u8]) -> Result<Self> {
        let seqner: Seqner = Matter::new_with_qb64b(qb64b)?;
        validate_code(&seqner.code())?;
        Ok(seqner)
    }

    pub fn new_with_qb2(qb2: &[u8]) -> Result<Self> {
        let seqner: Seqner = Matter::new_with_qb2(qb2)?;
        validate_code(&seqner.code())?;
        Ok(seqner)
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

    #[rstest]
    fn new_default_and_zero(
        #[values(
            &Seqner::new_with_code_and_raw("", &[]).unwrap(),
            &Seqner::new_with_code_and_raw(matter::Codex::Salt_128, b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00").unwrap(),
            &Seqner::new_with_sn(0).unwrap(),
            &Seqner::new_with_snh("").unwrap(),
            &Seqner::new_with_snh("0").unwrap(),
            &Seqner::new_with_snh("00").unwrap(),
            &Seqner::new_with_qb64("0AAAAAAAAAAAAAAAAAAAAAAA").unwrap(),
            &Seqner::new_with_qb64b(b"0AAAAAAAAAAAAAAAAAAAAAAA").unwrap(),
            &Seqner::new_with_qb2(b"\xd0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00").unwrap(),
        )]
        seqner: &Seqner,
    ) {
        assert_eq!(seqner.raw, b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00");
        assert_eq!(seqner.code, matter::Codex::Salt_128);
        assert_eq!(seqner.sn().unwrap(), 0);
        assert_eq!(seqner.snh().unwrap(), "0");
        assert_eq!(seqner.qb64().unwrap(), "0AAAAAAAAAAAAAAAAAAAAAAA");
        assert_eq!(seqner.qb64b().unwrap(), b"0AAAAAAAAAAAAAAAAAAAAAAA");
        assert_eq!(
            seqner.qb2().unwrap(),
            b"\xd0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        );
    }

    #[rstest]
    fn new_with_data(
        #[values(
            &Seqner::new_with_code_and_raw(matter::Codex::Salt_128, b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0A").unwrap(),
            &Seqner::new_with_sn(10).unwrap(),
            &Seqner::new_with_snh("A").unwrap(),
            &Seqner::new_with_snh("0A").unwrap(),
            &Seqner::new_with_qb64("0AAAAAAAAAAAAAAAAAAAAAAK").unwrap(),
            &Seqner::new_with_qb64b(b"0AAAAAAAAAAAAAAAAAAAAAAK").unwrap(),
            &Seqner::new_with_qb2(b"\xd0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0A").unwrap(),
        )]
        seqner: &Seqner,
    ) {
        assert_eq!(seqner.raw, b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0A");
        assert_eq!(seqner.code, matter::Codex::Salt_128);
        assert_eq!(seqner.sn().unwrap(), 10);
        assert_eq!(seqner.snh().unwrap(), "a");
        assert_eq!(seqner.qb64().unwrap(), "0AAAAAAAAAAAAAAAAAAAAAAK");
        assert_eq!(seqner.qb64b().unwrap(), b"0AAAAAAAAAAAAAAAAAAAAAAK");
        assert_eq!(
            seqner.qb2().unwrap(),
            b"\xd0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0A"
        );
    }

    #[rstest]
    fn new_max(
        #[values(
            &Seqner::new_with_code_and_raw(matter::Codex::Salt_128, b"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF").unwrap(),
            &Seqner::new_with_sn(0xffffffffffffffffffffffffffffffff_u128).unwrap(),
            &Seqner::new_with_snh("ffffffffffffffffffffffffffffffff").unwrap(),
            &Seqner::new_with_qb64("0AD_____________________").unwrap(),
            &Seqner::new_with_qb64b(b"0AD_____________________").unwrap(),
            &Seqner::new_with_qb2(b"\xd0\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF").unwrap(),
        )]
        seqner: &Seqner,
    ) {
        assert_eq!(seqner.raw, b"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF");
        assert_eq!(seqner.code, matter::Codex::Salt_128);
        assert_eq!(seqner.sn().unwrap(), 340282366920938463463374607431768211455);
        assert_eq!(seqner.snh().unwrap(), "ffffffffffffffffffffffffffffffff");
        assert_eq!(seqner.qb64().unwrap(), "0AD_____________________");
        assert_eq!(seqner.qb64b().unwrap(), b"0AD_____________________");
        assert_eq!(
            seqner.qb2().unwrap(),
            b"\xd0\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"
        );
    }

    #[rstest]
    #[case(
        // Bad code
        matter::Codex::Big,
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0A"
    )]
    #[case(
        // Empty code with non-empty raw is highly likely a programming error
        "",
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0A"
    )]
    #[case(
        // Short Raw value
        matter::Codex::Salt_128,
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    )]
    fn unhappy_new_with_code_and_raw(#[case] code: &str, #[case] snraw: &[u8]) {
        assert!(Seqner::new_with_code_and_raw(code, snraw).is_err());
    }

    #[rstest]
    fn unhappy_new_with_snh(
        #[values(
            "not a hex",
            // Longer than the max one
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
        )]
        sns: &str,
    ) {
        assert!(Seqner::new_with_snh(sns).is_err());
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
        assert!(Seqner::new_with_qb64(qb64).is_err());
        assert!(Seqner::new_with_qb64b(qb64.as_bytes()).is_err());
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
        assert!(Seqner::new_with_qb2(qb2).is_err());
    }
}
