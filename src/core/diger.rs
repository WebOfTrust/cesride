use lazy_static::lazy_static;

use crate::core::matter::{tables as matter, Matter};
use crate::crypto::hash;
use crate::error::{err, Error, Result};

#[derive(Debug, Clone, PartialEq)]
pub struct Diger {
    raw: Vec<u8>,
    code: String,
    size: u32,
}

impl Default for Diger {
    fn default() -> Self {
        Diger { raw: vec![], code: matter::Codex::Blake3_256.to_string(), size: 0 }
    }
}

fn validate_code(code: &str) -> Result<()> {
    lazy_static! {
        static ref CODES: Vec<&'static str> = vec![
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
    }

    if !CODES.contains(&code) {
        return err!(Error::UnexpectedCode(code.to_string()));
    }

    Ok(())
}

impl Diger {
    fn new_with_code_and_raw(code: &str, raw: &[u8]) -> Result<Self> {
        validate_code(code)?;
        Matter::new_with_code_and_raw(code, raw)
    }

    fn new_with_qb64(qb64: &str) -> Result<Self> {
        let diger: Diger = Matter::new_with_qb64(qb64)?;
        validate_code(&diger.code)?;
        Ok(diger)
    }

    fn new_with_qb64b(qb64b: &[u8]) -> Result<Self> {
        let diger: Diger = Matter::new_with_qb64b(qb64b)?;
        validate_code(&diger.code)?;
        Ok(diger)
    }

    fn new_with_qb2(qb2: &[u8]) -> Result<Self> {
        let diger: Diger = Matter::new_with_qb2(qb2)?;
        validate_code(&diger.code)?;
        Ok(diger)
    }

    pub fn new_with_code_and_ser(code: &str, ser: &[u8]) -> Result<Self> {
        validate_code(code)?;
        let dig = hash::digest(code, ser)?;
        Matter::new_with_code_and_raw(code, &dig)
    }

    fn verify(&self, ser: &[u8]) -> Result<bool> {
        let dig = hash::digest(&self.code(), ser)?;
        Ok(dig == self.raw())
    }

    fn compare_dig(&self, ser: &[u8], dig: &[u8]) -> Result<bool> {
        if dig == self.qb64b()? {
            return Ok(true);
        }

        let diger = <Diger as Matter>::new_with_qb64b(dig)?;

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

    #[test]
    fn new_with_code_and_raw() {
        let raw = hex!("0123456789abcdef00001111222233334444555566667777888899990000aaaa");
        let code = matter::Codex::Blake3_256;

        let d = Diger::new_with_code_and_raw(code, &raw).unwrap();
        assert_eq!(d.raw(), raw);
    }

    #[test]
    fn new_with_qb64() {
        let raw = b"abcdefghijklmnopqrstuvwxyz012345";

        let valid_diger: Diger =
            Matter::new_with_code_and_raw(matter::Codex::Blake3_256, raw).unwrap();
        let invalid_diger: Diger =
            Matter::new_with_code_and_raw(matter::Codex::Ed25519, raw).unwrap();

        assert!(Diger::new_with_qb64(&valid_diger.qb64().unwrap()).is_ok());
        assert!(Diger::new_with_qb64(&invalid_diger.qb64().unwrap()).is_err());
    }

    #[test]
    fn new_with_qb64b() {
        let raw = b"abcdefghijklmnopqrstuvwxyz012345";

        let valid_diger: Diger =
            Matter::new_with_code_and_raw(matter::Codex::Blake3_256, raw).unwrap();
        let invalid_diger: Diger =
            Matter::new_with_code_and_raw(matter::Codex::Ed25519, raw).unwrap();

        assert!(Diger::new_with_qb64b(&valid_diger.qb64b().unwrap()).is_ok());
        assert!(Diger::new_with_qb64b(&invalid_diger.qb64b().unwrap()).is_err());
    }

    #[test]
    fn new_with_qb2() {
        let raw = b"abcdefghijklmnopqrstuvwxyz012345";

        let valid_diger: Diger =
            Matter::new_with_code_and_raw(matter::Codex::Blake3_256, raw).unwrap();
        let invalid_diger: Diger =
            Matter::new_with_code_and_raw(matter::Codex::Ed25519, raw).unwrap();

        assert!(Diger::new_with_qb2(&valid_diger.qb2().unwrap()).is_ok());
        assert!(Diger::new_with_qb2(&invalid_diger.qb2().unwrap()).is_err());
    }

    #[test]
    fn verify() {
        let raw = hex!("e1be4d7a8ab5560aa4199eea339849ba8e293d55ca0a81006726d184519e647f"
                                 "5b49b82f805a538c68915c1ae8035c900fd1d4b13902920fd05e1450822f36de");

        let d = Diger::new_with_code_and_raw(matter::Codex::Blake3_512, &raw).unwrap();
        assert!(d.verify(&vec![0, 1, 2]).unwrap());
    }

    #[test]
    fn compare_dig() {
        let code = matter::Codex::Blake3_256;
        let raw = hex!("e1be4d7a8ab5560aa4199eea339849ba8e293d55ca0a81006726d184519e647f");
        let ser = vec![0, 1, 2];

        // dig == self.qb64b() - should return true
        let d = Diger::new_with_code_and_raw(code, &raw).unwrap();
        let mut qb64b = d.qb64b().unwrap();
        assert!(d.compare_dig(&ser, &qb64b).unwrap());

        // diger.code == self.code, dig != qb64b - should return false
        let mut x = qb64b[30]; // break a piece of the value, without breaking encoding
        x = if x == 0 { 63 } else { x - 1 };
        qb64b[30] = x;
        assert!(!d.compare_dig(&ser, &qb64b).unwrap());

        // same ser, different algorithm - should return true
        let code2 = matter::Codex::Blake2b_256;
        let raw2 = hash::digest(code2, &ser).unwrap();
        let m2: Diger = Matter::new_with_code_and_raw(code2, &raw2).unwrap();
        assert!(d.compare_dig(&ser, &m2.qb64b().unwrap()).unwrap());

        // different ser, different algorithm - should return false
        let raw2 = hash::digest(code2, &vec![0, 1, 2, 3]).unwrap();
        let m2: Diger = Matter::new_with_code_and_raw(code2, &raw2).unwrap();
        assert!(!d.compare_dig(&ser, &m2.qb64b().unwrap()).unwrap());
    }

    #[test]
    fn compare_diger() {
        let code = matter::Codex::Blake3_256;
        let raw = hex!("e1be4d7a8ab5560aa4199eea339849ba8e293d55ca0a81006726d184519e647f");
        let ser = vec![0, 1, 2];

        // diger.qb64b() == self.qb64b() - should return true
        let d = Diger::new_with_code_and_raw(code, &raw).unwrap();
        let mut qb64b = d.qb64b().unwrap();
        let d2 = Diger::new_with_qb64b(&qb64b).unwrap();
        assert!(d.compare_diger(&ser, &d2).unwrap());

        // diger.code == self.code, diger.qb64() != self.qb64b() - should return false
        let mut x = qb64b[30]; // break a piece of the value, without breaking encoding
        x = if x == 0 { 63 } else { x - 1 };
        qb64b[30] = x;
        let d2 = Diger::new_with_qb64b(&qb64b).unwrap();
        assert!(!d.compare_diger(&ser, &d2).unwrap());

        // same ser, different algorithm - should return true
        let code2 = matter::Codex::Blake2b_256;
        let raw2 = hash::digest(code2, &ser).unwrap();
        let d2 = Diger::new_with_code_and_raw(code2, &raw2).unwrap();
        assert!(d.compare_diger(&ser, &d2).unwrap());

        // different ser, different algorithm - should return false
        let raw2 = hash::digest(code2, &vec![0, 1, 2, 3]).unwrap();
        let d2 = Diger::new_with_code_and_raw(code2, &raw2).unwrap();
        assert!(!d.compare_diger(&ser, &d2).unwrap());
    }

    #[test]
    fn python_interop() {
        // compare() will exercise the most code
        let ser = b"abcdefghijklmnopqrstuvwxyz0123456789";

        let diger0 = Diger::new_with_code_and_ser(matter::Codex::Blake3_256, ser).unwrap();
        let diger1 = Diger::new_with_code_and_ser(matter::Codex::SHA3_256, ser).unwrap();
        let diger2 = Diger::new_with_code_and_ser(matter::Codex::Blake2b_256, ser).unwrap();

        assert!(diger0.compare_diger(ser, &diger1).unwrap());
        assert!(diger0.compare_diger(ser, &diger2).unwrap());
        assert!(diger1.compare_diger(ser, &diger2).unwrap());

        assert!(diger0.compare_dig(ser, &diger1.qb64b().unwrap()).unwrap());
        assert!(diger0.compare_dig(ser, &diger2.qb64b().unwrap()).unwrap());
        assert!(diger1.compare_dig(ser, &diger2.qb64b().unwrap()).unwrap());

        let ser1 = b"ABCDEFGHIJKLMNOPQSTUVWXYXZabcdefghijklmnopqrstuvwxyz0123456789";
        let diger = Diger::new_with_code_and_ser(matter::Codex::Blake3_256, ser1).unwrap();

        assert!(!diger0.compare_diger(ser, &diger).unwrap()); // codes match
        assert!(!diger0.compare_dig(ser, &diger.qb64b().unwrap()).unwrap()); // codes match

        let diger = Diger::new_with_code_and_ser(matter::Codex::SHA3_256, ser1).unwrap();

        assert!(!diger0.compare_diger(ser, &diger).unwrap()); // codes match
        assert!(!diger0.compare_dig(ser, &diger.qb64b().unwrap()).unwrap());
        // codes match
    }

    #[test]
    fn unhappy_paths() {
        assert!(hash::digest(matter::Codex::Big, &[]).is_err());
    }
}
