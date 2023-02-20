use crate::core::matter::{tables as matter, Matter};
use crate::crypto::hash;
use crate::error::{err, Error, Result};

#[derive(Debug, Clone, PartialEq)]
pub struct Diger {
    pub raw: Vec<u8>,
    pub code: String,
    pub size: u32,
}

impl Default for Diger {
    fn default() -> Self {
        Diger { raw: vec![], code: matter::Codex::Blake3_256.to_string(), size: 0 }
    }
}

fn validate_code(code: &str) -> Result<()> {
    const CODES: &[&str] = &[
        matter::Codex::Blake3_256,
        matter::Codex::Blake3_512,
        matter::Codex::Blake2b_256,
        matter::Codex::Blake2b_512,
        matter::Codex::Blake2s_256,
        matter::Codex::SHA3_256,
        matter::Codex::SHA3_512,
        matter::Codex::SHA2_256,
        matter::Codex::SHA2_512,
    ];

    if !CODES.contains(&code) {
        return err!(Error::UnexpectedCode(code.to_string()));
    }

    Ok(())
}

impl Diger {
    pub fn new(
        ser: Option<&[u8]>,
        code: Option<&str>,
        raw: Option<&[u8]>,
        qb64b: Option<&[u8]>,
        qb64: Option<&str>,
        qb2: Option<&[u8]>,
    ) -> Result<Self> {
        let result = Matter::new(code, raw, qb64b, qb64, qb2);
        if result.is_ok() {
            let diger: Self = result?;
            validate_code(&diger.code())?;
            Ok(diger)
        } else if let Some(ser) = ser {
            let code = code.unwrap_or(matter::Codex::Blake3_256);
            validate_code(code)?;
            let dig = hash::digest(code, ser)?;
            Matter::new(Some(code), Some(&dig), None, None, None)
        } else {
            err!(Error::Validation("failure creating diger".to_string()))
        }
    }

    pub fn new_with_ser(ser: &[u8], code: Option<&str>) -> Result<Self> {
        Self::new(Some(ser), code, None, None, None, None)
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

    pub fn verify(&self, ser: &[u8]) -> Result<bool> {
        let dig = hash::digest(&self.code(), ser)?;
        Ok(dig == self.raw())
    }

    pub fn compare(&self, ser: &[u8], dig: Option<&[u8]>, diger: Option<&Diger>) -> Result<bool> {
        if let Some(dig) = dig {
            self.compare_dig(ser, dig)
        } else if let Some(diger) = diger {
            self.compare_diger(ser, diger)
        } else {
            err!(Error::Value("both dig and diger may not be none".to_string()))
        }
    }

    fn compare_dig(&self, ser: &[u8], dig: &[u8]) -> Result<bool> {
        if dig == self.qb64b()? {
            return Ok(true);
        }

        let diger = <Diger as Matter>::new(None, None, Some(dig), None, None)?;

        if diger.code() == self.code() {
            return Ok(false);
        }

        if diger.verify(ser)? && self.verify(ser)? {
            return Ok(true);
        }

        Ok(false)
    }

    fn compare_diger(&self, ser: &[u8], diger: &Diger) -> Result<bool> {
        // reference implementation uses qb64b() but that's an extra conversion here
        if diger.qb64()? == self.qb64()? {
            return Ok(true);
        }

        if diger.code() == self.code() {
            return Ok(false);
        }

        if diger.verify(ser)? && self.verify(ser)? {
            return Ok(true);
        }

        Ok(false)
    }
}

impl Matter for Diger {
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
    use crate::core::diger::Diger;
    use crate::core::matter::{tables as matter, Matter};
    use crate::crypto::hash;
    use hex_literal::hex;
    use rstest::rstest;

    #[test]
    fn convenience() {
        let ser = b"abcdefg";

        let diger = Diger::new(Some(ser), None, None, None, None, None).unwrap();

        assert!(Diger::new_with_ser(ser, None).is_ok());
        assert!(Diger::new_with_raw(&diger.raw(), Some(&diger.code())).is_ok());
        assert!(Diger::new_with_qb64b(&diger.qb64b().unwrap()).is_ok());
        assert!(Diger::new_with_qb64(&diger.qb64().unwrap()).is_ok());
        assert!(Diger::new_with_qb2(&diger.qb2().unwrap()).is_ok());
    }

    #[rstest]
    fn conversions(
        #[values(matter::Codex::Blake3_256)] _code: &str,
        #[values(b"abcdefghijklmnopqrstuvwxyz0123456789")] _ser: &[u8],
        #[values(Diger::new(Some(_ser), Some(_code), None, None, None, None).unwrap())]
        control: Diger,
        #[values(
            Diger::new(None, Some(_code), Some(&control.raw()), None, None, None).unwrap(),
            Diger::new(None, None, None, Some(&control.qb64b().unwrap()), None, None).unwrap(),
            Diger::new(None, None, None, None, Some(&control.qb64().unwrap()), None).unwrap(),
            Diger::new(None, None, None, None, None, Some(&control.qb2().unwrap())).unwrap()
        )]
        diger: Diger,
    ) {
        assert_eq!(diger.qb64().unwrap(), control.qb64().unwrap());
        assert_eq!(diger.qb64b().unwrap(), control.qb64b().unwrap());
        assert_eq!(diger.qb2().unwrap(), control.qb2().unwrap());
        assert_eq!(diger.code(), control.code());
    }

    #[rstest]
    fn invalid(
        #[values(matter::Codex::Blake3_256)] _code: &str,
        #[values(b"abcdefghijklmnopqrstuvwxyz0123456789")] _raw: &[u8],
        #[values(<Diger as Matter>::new(Some(matter::Codex::Ed25519), Some(_raw), None, None, None).unwrap())]
        _control: Diger,
        #[values(
            Diger::new(None, None, None, Some(&_control.qb64b().unwrap()), None, None).is_err(),
            Diger::new(None, None, None, None, Some(&_control.qb64().unwrap()), None).is_err(),
            Diger::new(None, None, None, None, None, Some(&_control.qb2().unwrap())).is_err()
        )]
        result: bool,
    ) {
        assert!(result);
    }

    #[test]
    fn compare() {
        let code = matter::Codex::Blake3_256;
        let raw = hex!("e1be4d7a8ab5560aa4199eea339849ba8e293d55ca0a81006726d184519e647f");
        let ser = vec![0, 1, 2];

        // dig == self.qb64b() - should return true
        let diger = Diger::new(None, Some(code), Some(&raw), None, None, None).unwrap();
        let qb64b = diger.qb64b().unwrap();
        assert!(diger.compare(&ser, Some(&qb64b), None).unwrap());
        assert!(diger.compare(&ser, None, Some(&diger)).unwrap());
        assert!(diger.compare(&ser, None, None).is_err());
    }

    #[test]
    fn verify() {
        let raw = hex!("e1be4d7a8ab5560aa4199eea339849ba8e293d55ca0a81006726d184519e647f"
                                 "5b49b82f805a538c68915c1ae8035c900fd1d4b13902920fd05e1450822f36de");

        let diger = Diger::new(None, Some(matter::Codex::Blake3_512), Some(&raw), None, None, None)
            .unwrap();
        assert!(diger.verify(&vec![0, 1, 2]).unwrap());
    }

    #[test]
    fn compare_dig() {
        let code = matter::Codex::Blake3_256;
        let raw = hex!("e1be4d7a8ab5560aa4199eea339849ba8e293d55ca0a81006726d184519e647f");
        let ser = vec![0, 1, 2];

        // dig == self.qb64b() - should return true
        let diger = Diger::new(None, Some(code), Some(&raw), None, None, None).unwrap();
        let mut qb64b = diger.qb64b().unwrap();
        assert!(diger.compare(&ser, Some(&qb64b), None).unwrap());

        // diger.code == self.code, dig != qb64b - should return false
        let mut x = qb64b[30]; // break a piece of the value, without breaking encoding
        x = if x == 0 { 63 } else { x - 1 };
        qb64b[30] = x;
        assert!(!diger.compare(&ser, Some(&qb64b), None).unwrap());

        // same ser, different algorithm - should return true
        let code = matter::Codex::Blake2b_256;
        let raw = hash::digest(code, &ser).unwrap();
        let matter: Diger = Matter::new(Some(code), Some(&raw), None, None, None).unwrap();
        assert!(diger.compare(&ser, Some(&matter.qb64b().unwrap()), None).unwrap());

        // different ser, different algorithm - should return false
        let raw = hash::digest(code, &vec![0, 1, 2, 3]).unwrap();
        let matter: Diger = Matter::new(Some(code), Some(&raw), None, None, None).unwrap();
        assert!(!diger.compare(&ser, Some(&matter.qb64b().unwrap()), None).unwrap());
    }

    #[test]
    fn compare_diger() {
        let code = matter::Codex::Blake3_256;
        let raw = hex!("e1be4d7a8ab5560aa4199eea339849ba8e293d55ca0a81006726d184519e647f");
        let ser = vec![0, 1, 2];

        // diger.qb64b() == self.qb64b() - should return true
        let diger = Diger::new(None, Some(code), Some(&raw), None, None, None).unwrap();
        let mut qb64b = diger.qb64b().unwrap();
        let d2 = Diger::new(None, None, None, Some(&qb64b), None, None).unwrap();
        assert!(diger.compare(&ser, None, Some(&d2)).unwrap());

        // diger.code == self.code, diger.qb64() != self.qb64b() - should return false
        let mut x = qb64b[30]; // break a piece of the value, without breaking encoding
        x = if x == 0 { 63 } else { x - 1 };
        qb64b[30] = x;
        let d2 = Diger::new(None, None, None, Some(&qb64b), None, None).unwrap();
        assert!(!diger.compare(&ser, None, Some(&d2)).unwrap());

        // same ser, different algorithm - should return true
        let code2 = matter::Codex::Blake2b_256;
        let raw2 = hash::digest(code2, &ser).unwrap();
        let d2 = Diger::new(None, Some(code2), Some(&raw2), None, None, None).unwrap();
        assert!(diger.compare(&ser, None, Some(&d2)).unwrap());

        // different ser, different algorithm - should return false
        let raw2 = hash::digest(code2, &vec![0, 1, 2, 3]).unwrap();
        let d2 = Diger::new(None, Some(code2), Some(&raw2), None, None, None).unwrap();
        assert!(!diger.compare(&ser, None, Some(&d2)).unwrap());
    }

    #[test]
    fn python_interop() {
        // compare() will exercise the most code
        let ser = b"abcdefghijklmnopqrstuvwxyz0123456789";

        let diger0 =
            Diger::new(Some(ser), Some(matter::Codex::Blake3_256), None, None, None, None).unwrap();
        let diger1 =
            Diger::new(Some(ser), Some(matter::Codex::SHA3_256), None, None, None, None).unwrap();
        let diger2 =
            Diger::new(Some(ser), Some(matter::Codex::Blake2b_256), None, None, None, None)
                .unwrap();

        assert!(diger0.compare(ser, None, Some(&diger1)).unwrap());
        assert!(diger0.compare(ser, None, Some(&diger2)).unwrap());
        assert!(diger1.compare(ser, None, Some(&diger2)).unwrap());

        assert!(diger0.compare(ser, Some(&diger1.qb64b().unwrap()), None).unwrap());
        assert!(diger0.compare(ser, Some(&diger2.qb64b().unwrap()), None).unwrap());
        assert!(diger1.compare(ser, Some(&diger2.qb64b().unwrap()), None).unwrap());

        let ser1 = b"ABCDEFGHIJKLMNOPQSTUVWXYXZabcdefghijklmnopqrstuvwxyz0123456789";
        let diger = Diger::new(Some(ser1), Some(matter::Codex::Blake3_256), None, None, None, None)
            .unwrap();

        assert!(!diger0.compare(ser, None, Some(&diger)).unwrap());
        assert!(!diger0.compare(ser, Some(&diger.qb64b().unwrap()), None).unwrap());

        let diger =
            Diger::new(Some(ser1), Some(matter::Codex::SHA3_256), None, None, None, None).unwrap();

        assert!(!diger0.compare(ser, None, Some(&diger)).unwrap());
        assert!(!diger0.compare(ser, Some(&diger.qb64b().unwrap()), None).unwrap());
    }

    #[test]
    fn unhappy_paths() {
        assert!(Diger::new(None, None, None, None, None, None).is_err());
    }
}
