pub mod tables;

use crate::core::util;
use crate::error::{err, Error, Result};

#[derive(Debug, Clone, PartialEq)]
pub struct Counter {
    pub(crate) code: String,
    pub(crate) count: u32,
}

impl Counter {
    pub fn new_with_code_and_count_b64(code: &str, count_b64: &str) -> Result<Counter> {
        let count = if count_b64.is_empty() { 1_u32 } else { util::b64_to_u32(count_b64)? };

        Counter::new_with_code_and_count(code, count)
    }

    pub fn new_with_code_and_count(code: &str, count: u32) -> Result<Counter> {
        if code.is_empty() {
            return err!(Error::EmptyMaterial("empty code".to_string()));
        }

        let szg = tables::sizage(code)?;
        let cs = szg.hs + szg.ss;
        if szg.fs != cs || cs % 4 != 0 {
            // unreachable
            // code validated and unless sizages are broken this cannot be reached
            return err!(Error::InvalidCodeSize(format!(
                "whole code size not a multiple of 4: cs = {cs}, fs = {}",
                szg.fs
            )));
        }

        if count > 64_u32.pow(szg.ss) - 1 {
            return err!(Error::InvalidVarIndex(format!(
                "invalid count for code: count = {count}, code = '{code}'"
            )));
        }

        Ok(Counter { code: code.to_string(), count })
    }

    pub fn new_with_qb64(qb64: &str) -> Result<Counter> {
        let mut counter: Counter = Default::default();
        counter.exfil(qb64)?;
        Ok(counter)
    }

    pub fn new_with_qb64b(qb64b: &[u8]) -> Result<Counter> {
        let qb64 = String::from_utf8(qb64b.to_vec())?;

        let mut counter: Counter = Default::default();
        counter.exfil(&qb64)?;
        Ok(counter)
    }

    pub fn new_with_qb2(qb2: &[u8]) -> Result<Counter> {
        let mut counter: Counter = Default::default();
        counter.bexfil(qb2)?;
        Ok(counter)
    }

    pub fn code(&self) -> String {
        self.code.clone()
    }

    pub fn count(&self) -> u32 {
        self.count
    }

    pub fn count_as_b64(&self, length: usize) -> Result<String> {
        let length = if length == 0 { tables::sizage(&self.code)?.ss as usize } else { length };
        util::u32_to_b64(self.count, length)
    }

    fn sem_ver_parts_to_b64(parts: &[u8]) -> Result<String> {
        for p in parts.iter().copied() {
            if p > 63 {
                return err!(Error::Parsing(format!(
                    "semantic version out of bounds: parts = {parts:?}"
                )));
            }
        }

        Ok(parts
            .iter()
            .map(|p| {
                match util::u32_to_b64(*p as u32, 1) {
                    Ok(s) => s,
                    Err(_) => unreachable!(), // this is programmer error, since *p < 64
                }
            })
            .collect::<Vec<String>>()
            .join(""))
    }

    pub fn sem_ver_str_to_b64(version: &str) -> Result<String> {
        let strings = version.split('.').collect::<Vec<_>>();
        let mut parts = Vec::new();

        if strings.len() > 3 {
            return err!(Error::Conversion(format!(
                "invalid semantic version: version = '{version}'"
            )));
        }

        for s in strings {
            let n = match s.parse::<i8>() {
                Ok(n) => {
                    if n < 0 {
                        return err!(Error::Conversion(format!(
                            "invalid semantic version: version = '{version}'"
                        )));
                    } else {
                        n as u8
                    }
                }
                Err(_) => {
                    if s.is_empty() {
                        0
                    } else {
                        return err!(Error::Conversion(format!(
                            "invalid semantic version: version = '{version}'"
                        )));
                    }
                }
            };
            parts.push(n);
        }

        parts.resize(3, 0);

        Counter::sem_ver_parts_to_b64(&parts)
    }

    pub fn sem_ver_to_b64(major: u8, minor: u8, patch: u8) -> Result<String> {
        let parts = &vec![major, minor, patch];
        Counter::sem_ver_parts_to_b64(parts)
    }

    pub fn qb64(&self) -> Result<String> {
        self.infil()
    }

    pub fn qb64b(&self) -> Result<Vec<u8>> {
        Ok(self.qb64()?.as_bytes().to_vec())
    }

    pub fn qb2(&self) -> Result<Vec<u8>> {
        self.binfil()
    }

    fn infil(&self) -> Result<String> {
        let code = &self.code;
        let count = self.count;

        let szg = tables::sizage(code)?;
        let cs = szg.hs + szg.ss;

        if szg.fs != cs || cs % 4 != 0 {
            // unreachable
            // unless sizages are broken this cannot happen
            return err!(Error::InvalidCodeSize(format!(
                "whole code size not complete or not a multiple of 4: cs = {cs}, fs = {}",
                szg.fs
            )));
        }

        if count > 64_u32.pow(szg.ss) - 1 {
            return err!(Error::InvalidVarIndex(format!(
                "invalid count for code: count = {count}, code = '{code}'"
            )));
        }

        let both = format!("{code}{}", util::u32_to_b64(count, szg.ss as usize)?);
        if both.len() != cs as usize {
            // unreachable
            // unless sizages are broken, we constructed both to be of length cs
            return err!(Error::InvalidCodeSize(format!(
                "mismatched code size: size = {}, code = '{both}'",
                both.len()
            )));
        }

        Ok(both)
    }

    fn binfil(&self) -> Result<Vec<u8>> {
        let both = self.infil()?;
        util::code_b64_to_b2(&both)
    }

    fn exfil(&mut self, qb64: &str) -> Result<()> {
        if qb64.is_empty() {
            return err!(Error::EmptyMaterial("empty qb64".to_string()));
        }

        // we validated there will be a char here, above.
        let first = &qb64[..2];

        let hs = tables::hardage(first)? as usize;
        if qb64.len() < hs {
            return err!(Error::Shortage(format!(
                "insufficient material for hard part of code: qb64 size = {}, hs = {hs}",
                qb64.len()
            )));
        }

        // bounds already checked
        let hard = &qb64[..hs];
        let szg = tables::sizage(hard)?;
        let cs = szg.hs + szg.ss;

        if qb64.len() < cs as usize {
            return err!(Error::Shortage(format!(
                "insufficient material for code: qb64 size = {}, cs = {cs}",
                qb64.len()
            )));
        }

        let count_b64 = &qb64[szg.hs as usize..cs as usize];
        let count = util::b64_to_u64(count_b64)? as u32;

        self.code = hard.to_string();
        self.count = count;

        Ok(())
    }

    fn bexfil(&mut self, qb2: &[u8]) -> Result<()> {
        if qb2.is_empty() {
            return err!(Error::EmptyMaterial("empty qualified base2".to_string()));
        }

        let first = util::nab_sextets(qb2, 2)?;
        if first[0] > 0x3e {
            if first[0] == 0x3f {
                return err!(Error::UnexpectedOpCode(
                    "unexpected start during extraction".to_string(),
                ));
            } else {
                // unreachable
                // programmer error - nab_sextets ensures values fall below 0x40. the only possible
                // value is 0x3f, and we handle it
                return err!(Error::UnexpectedCode(format!(
                    "unexpected code start: sextets = {first:?}"
                )));
            }
        }

        let hs = tables::bardage(&first)?;
        let bhs = ((hs + 1) * 3) / 4;
        if qb2.len() < bhs as usize {
            return err!(Error::Shortage(format!(
                "need more bytes: qb2 size = {}, bhs = {bhs}",
                qb2.len()
            )));
        }

        let hard = util::code_b2_to_b64(qb2, hs as usize)?;
        let szg = tables::sizage(&hard)?;
        let cs = szg.hs + szg.ss;
        let bcs = ((cs + 1) * 3) / 4;
        if qb2.len() < bcs as usize {
            return err!(Error::Shortage(format!(
                "need more bytes: qb2 size = {}, bcs = {bcs}",
                qb2.len()
            )));
        }

        let both = util::code_b2_to_b64(qb2, cs as usize)?;
        let mut count = 0;
        for c in both[hs as usize..cs as usize].chars() {
            count <<= 6;
            count += util::b64_char_to_index(c)? as u32;
        }

        self.code = hard;
        self.count = count;

        Ok(())
    }
}

impl Default for Counter {
    fn default() -> Self {
        Counter { code: "".to_string(), count: 0 }
    }
}

#[cfg(test)]
mod counter_tests {
    use crate::core::counter::{tables as counter, Counter};
    use base64::{engine::general_purpose as b64_engine, Engine};
    use rstest::rstest;

    #[rstest]
    #[case("-AAB", 1, "B", counter::Codex::ControllerIdxSigs.code())]
    #[case("-AAF", 5, "F", counter::Codex::ControllerIdxSigs.code())]
    #[case("-0VAAAQA", 1024, "QA", counter::Codex::BigAttachedMaterialQuadlets.code())]
    fn test_creation(
        #[case] qsc: &str,
        #[case] count: u32,
        #[case] count_b64: &str,
        #[case] code: &str,
    ) {
        let qscb = qsc.as_bytes();
        let qscb2 = &b64_engine::URL_SAFE.decode(qsc).unwrap();

        let counter1 = Counter::new_with_code_and_count(code, count).unwrap();
        let counter2 = Counter::new_with_code_and_count_b64(code, count_b64).unwrap();
        let counter3 = Counter::new_with_qb64(qsc).unwrap();
        let counter4 = Counter::new_with_qb64b(qscb).unwrap();
        let counter5 = Counter::new_with_qb2(qscb2).unwrap();

        assert_eq!(counter1.code(), counter2.code());
        assert_eq!(counter1.count(), counter2.count());
        assert_eq!(counter1.code(), counter3.code());
        assert_eq!(counter1.count(), counter3.count());
        assert_eq!(counter1.code(), counter4.code());
        assert_eq!(counter1.count(), counter4.count());
        assert_eq!(counter1.code(), counter5.code());
        assert_eq!(counter1.count(), counter5.count());
    }

    #[rstest]
    #[case(0, "AAA", 0, "AAA", counter::Codex::KERIProtocolStack.code())]
    fn test_versioned_creation(
        #[case] verint: u32,
        #[case] version: &str,
        #[case] count: u32,
        #[case] count_b64: &str,
        #[case] code: &str,
    ) {
        let qsc = &format!("{code}{version}");
        let qscb = qsc.as_bytes();
        let qscb2 = &b64_engine::URL_SAFE.decode(qsc).unwrap();

        let counter1 = Counter::new_with_code_and_count(code, count).unwrap();
        let counter2 = Counter::new_with_code_and_count_b64(code, count_b64).unwrap();
        let counter3 = Counter::new_with_qb64(qsc).unwrap();
        let counter4 = Counter::new_with_qb64b(qscb).unwrap();
        let counter5 = Counter::new_with_qb2(qscb2).unwrap();

        assert_eq!(counter1.code(), code);
        assert_eq!(counter1.count(), verint);
        assert_eq!(counter1.code(), counter2.code());
        assert_eq!(counter1.count(), counter2.count());
        assert_eq!(counter1.code(), counter3.code());
        assert_eq!(counter1.count(), counter3.count());
        assert_eq!(counter1.code(), counter4.code());
        assert_eq!(counter1.count(), counter4.count());
        assert_eq!(counter1.code(), counter5.code());
        assert_eq!(counter1.count(), counter5.count());

        assert_eq!(counter1.count_as_b64(3).unwrap(), version);

        // when 0 is an argument, we use a default
        assert_eq!(counter1.count_as_b64(0).unwrap(), version);
    }

    #[rstest]
    fn test_b64_overflow_and_underflow(#[values("-AAB")] qsc: &str) {
        // add some chars
        let longqsc64 = &format!("{qsc}ABCD");
        let counter = Counter::new_with_qb64(longqsc64).unwrap();
        assert_eq!(
            counter.qb64().unwrap().len() as u32,
            counter::sizage(&counter.code()).unwrap().fs
        );

        // remove a char
        let shortqsc64 = &qsc[..qsc.len() - 1];
        assert!(Counter::new_with_qb64(shortqsc64).is_err());
    }

    #[rstest]
    fn test_binary_overflow_and_underflow(#[values(vec![248, 0, 1])] qscb2: Vec<u8>) {
        // add some bytes
        let mut longqscb2 = qscb2.clone();
        longqscb2.resize(longqscb2.len() + 5, 1);
        let counter = Counter::new_with_qb2(&longqscb2).unwrap();
        assert_eq!(counter.qb2().unwrap(), *qscb2);
        assert_eq!(
            counter.qb64().unwrap().len() as u32,
            counter::sizage(&counter.code()).unwrap().fs
        );

        // remove a bytes
        let shortqscb2 = &qscb2[..qscb2.len() - 1];
        assert!(Counter::new_with_qb2(shortqscb2).is_err());
    }

    #[rstest]
    fn test_exfil_infil_bexfil_binfil(#[values("-0VAAAQA")] qsc: &str) {
        let counter1 = Counter::new_with_qb64(qsc).unwrap();
        let counter2 = Counter::new_with_qb2(&counter1.qb2().unwrap()).unwrap();
        assert_eq!(counter1.code(), counter2.code());
        assert_eq!(counter1.count(), counter2.count());
        assert_eq!(counter1.qb2().unwrap(), counter2.qb2().unwrap());
        assert_eq!(qsc, counter2.qb64().unwrap());
    }

    #[rstest]
    #[case("1.2.3", "BCD")]
    #[case("1.1", "BBA")]
    #[case("1.", "BAA")]
    #[case("1", "BAA")]
    #[case("1.2.", "BCA")]
    #[case("..", "AAA")]
    #[case("1..3", "BAD")]
    fn test_semantic_versioning_strings(#[case] version: &str, #[case] b64: &str) {
        assert_eq!(Counter::sem_ver_str_to_b64(version).unwrap(), b64);
    }

    #[rstest]
    #[case(1, 0, 0, "BAA")]
    #[case(0, 1, 0, "ABA")]
    #[case(0, 0, 1, "AAB")]
    #[case(3, 4, 5, "DEF")]
    fn test_semantic_versioning_u8s(
        #[case] major: u8,
        #[case] minor: u8,
        #[case] patch: u8,
        #[case] b64: &str,
    ) {
        assert_eq!(Counter::sem_ver_to_b64(major, minor, patch).unwrap(), b64);
    }

    #[rstest]
    fn test_semantic_versioning_unhappy_strings(
        #[values("64.0.1", "-1.0.1", "0.0.64")] version: &str,
    ) {
        assert!(Counter::sem_ver_str_to_b64(version).is_err());
    }

    #[rstest]
    #[case(64, 0, 0)]
    fn test_semantic_versioning_unhappy_u32s(
        #[case] major: u8,
        #[case] minor: u8,
        #[case] patch: u8,
    ) {
        assert!(Counter::sem_ver_to_b64(major, minor, patch).is_err());
    }

    #[test]
    fn test_unhappy_paths() {
        assert!(Counter::new_with_code_and_count("", 1).is_err());
        assert!(Counter::new_with_code_and_count(
            counter::Codex::ControllerIdxSigs.code(),
            64 * 64
        )
        .is_err());
        assert!(Counter::sem_ver_str_to_b64("1.2.3.4").is_err());
        assert!(Counter::sem_ver_str_to_b64("bad.semantic.version").is_err());
        assert!((Counter {
            code: counter::Codex::ControllerIdxSigs.code().to_string(),
            count: 64 * 64
        })
        .qb64()
        .is_err());
        assert!(Counter::new_with_qb64("").is_err());
        assert!(Counter::new_with_qb64("--").is_err());
        assert!(Counter::new_with_qb64("__").is_err());
        assert!(Counter::new_with_qb64(counter::Codex::ControllerIdxSigs.code()).is_err());
        assert!(Counter::new_with_qb64b(&[]).is_err());
        assert!(Counter::new_with_qb2(&[]).is_err());
        assert!(Counter::new_with_qb2(&[0xf8, 0]).is_err());
        assert!(Counter::new_with_qb2(&[0xfc, 0]).is_err());
        assert!(Counter::new_with_qb2(&[0xfb, 0xe0]).is_err());
    }

    #[rstest]
    #[case(counter::Codex::ControllerIdxSigs.code(), 1)]
    fn test_qb64b(#[case] code: &str, #[case] count: u32) {
        let c = Counter { code: code.to_string(), count };
        assert!(Counter::new_with_qb64b(&c.qb64b().unwrap()).is_ok());
    }
}
