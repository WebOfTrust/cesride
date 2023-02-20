use crate::core::matter::{tables as matter, Matter};
use crate::error::{err, Error, Result};

#[derive(Debug, Clone, PartialEq)]
pub struct Dater {
    pub raw: Vec<u8>,
    pub code: String,
    pub size: u32,
}

impl Default for Dater {
    fn default() -> Self {
        Dater { raw: vec![], code: matter::Codex::DateTime.to_string(), size: 0 }
    }
}

fn validate_code(code: &str) -> Result<()> {
    if code != matter::Codex::DateTime {
        return err!(Error::UnexpectedCode(code.to_string()));
    }

    Ok(())
}

fn iso_8601_to_b64(dts: &str) -> String {
    dts.replace(':', "c").replace('.', "d").replace('+', "p")
}

fn b64_to_iso_8601(dts: &str) -> String {
    dts.replace('c', ":").replace('d', ".").replace('p', "+")
}

fn now_as_iso8601() -> String {
    let dt = chrono::offset::Utc::now();
    dt.to_rfc3339_opts(chrono::SecondsFormat::Micros, false)
}

fn now_as_b64() -> String {
    let dt = now_as_iso8601();
    iso_8601_to_b64(&dt)
}

impl Dater {
    pub fn new(
        dts: Option<&str>,
        code: Option<&str>,
        raw: Option<&[u8]>,
        qb64b: Option<&[u8]>,
        qb64: Option<&str>,
        qb2: Option<&[u8]>,
    ) -> Result<Self> {
        let code = if let Some(code) = code { Some(code) } else { Some(matter::Codex::DateTime) };

        let dater: Self = if raw.is_none() && qb64b.is_none() && qb64.is_none() && qb2.is_none() {
            let b64 = if let Some(dts) = dts { iso_8601_to_b64(dts) } else { now_as_b64() };
            let qb64 = format!("{}{}", matter::Codex::DateTime, &b64);
            Matter::new(code, raw, qb64b, Some(&qb64), qb2)?
        } else {
            Matter::new(code, raw, qb64b, qb64, qb2)?
        };

        validate_code(&dater.code())?;
        Ok(dater)
    }

    pub fn new_with_dts(dts: &str, code: Option<&str>) -> Result<Self> {
        Self::new(Some(dts), code, None, None, None, None)
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

    pub fn dts(&self) -> Result<String> {
        let hs = matter::sizage(&self.code())?.hs as usize;
        let qb64 = self.qb64()?;
        Ok(b64_to_iso_8601(&qb64[hs..]))
    }

    pub fn dtsb(&self) -> Result<Vec<u8>> {
        Ok(self.dts()?.as_bytes().to_vec())
    }
}

impl Matter for Dater {
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
    use super::{matter, Dater, Matter};
    use rstest::rstest;

    #[test]
    fn convenience() {
        let dts = "2020-08-22T17:50:09.988921-01:00";

        let dater = Dater::new(Some(dts), None, None, None, None, None).unwrap();

        assert!(Dater::new_with_dts(dts, None).is_ok());
        assert!(Dater::new_with_raw(&dater.raw(), Some(&dater.code())).is_ok());
        assert!(Dater::new_with_qb64b(&dater.qb64b().unwrap()).is_ok());
        assert!(Dater::new_with_qb64(&dater.qb64().unwrap()).is_ok());
        assert!(Dater::new_with_qb2(&dater.qb2().unwrap()).is_ok());
    }

    #[test]
    fn new() {
        let dts = "2020-08-22T17:50:09.988921-01:00";
        let qb64 = Dater::new(Some(dts), None, None, None, None, None).unwrap().qb64().unwrap();
        assert!(Dater::new(Some(dts), None, None, None, None, None,).is_ok());
        assert!(Dater::new(None, None, None, None, Some(&qb64), None,).is_ok());
    }

    #[rstest]
    fn new_default(
        #[values(
            &Dater::new(None, None, None, None, None, None,).unwrap(),
        )]
        dater: &Dater,
    ) {
        assert_eq!(dater.code(), matter::Codex::DateTime);
        assert_eq!(dater.raw.len(), 24);
        assert_eq!(dater.qb64().unwrap().len(), 36);
        assert_eq!(dater.qb2().unwrap().len(), 27);
        assert_eq!(dater.dts().unwrap().len(), 32);
    }

    #[rstest]
    #[case(
        "2020-08-22T17:50:09.988921+00:00",
        "1AAG2020-08-22T17c50c09d988921p00c00",
        b"\xdbM\xb4\xfbO>\xdbd\xf5\xed\xcetsO]\xf7\xcf=\xdbZt\xd1\xcd4",
        b"\xd4\x00\x06\xdbM\xb4\xfbO>\xdbd\xf5\xed\xcetsO]\xf7\xcf=\xdbZt\xd1\xcd4"
    )]
    #[case(
        "2020-08-22T17:50:09.988921-01:00",
        "1AAG2020-08-22T17c50c09d988921-01c00",
        b"\xdbM\xb4\xfbO>\xdbd\xf5\xed\xcetsO]\xf7\xcf=\xdb_\xb4\xd5\xcd4",
        b"\xd4\x00\x06\xdbM\xb4\xfbO>\xdbd\xf5\xed\xcetsO]\xf7\xcf=\xdb_\xb4\xd5\xcd4"
    )]
    fn new_with_data(
        #[case] dts: &str,
        #[case] dtqb64: &str,
        #[case] dtraw: &[u8],
        #[case] dtqb2: &[u8],
        #[values(
            &Dater::new(Some(dts), None, None, None, None, None,).unwrap(),
            &Dater::new(None, Some(matter::Codex::DateTime), Some(dtraw), None, None, None,).unwrap(),
            &Dater::new(None, None, Some(dtraw), None, None, None,).unwrap(),
            &Dater::new(None, None, None, Some(dtqb64.as_bytes()), None, None,).unwrap(),
            &Dater::new(None, None, None, None, Some(dtqb64), None,).unwrap(),
            &Dater::new(None, None, None, None, None, Some(dtqb2),).unwrap(),
        )]
        dater: &Dater,
    ) {
        assert_eq!(dater.code, matter::Codex::DateTime);
        assert_eq!(dater.dts().unwrap(), dts);
        assert_eq!(dater.dtsb().unwrap(), dts.as_bytes());
        assert_eq!(dater.raw, dtraw);
        assert_eq!(dater.qb64().unwrap(), dtqb64);
        assert_eq!(dater.qb64b().unwrap(), dtqb64.as_bytes());
        assert_eq!(dater.qb2().unwrap(), dtqb2);
    }

    #[rstest]
    #[case(matter::Codex::Big, b"\xdbM\xb4\xfbO>\xdbd\xf5\xed\xcetsO]\xf7\xcf=\xdb_\xb4\xd5\xcd4")]
    #[case(matter::Codex::DateTime, b"\xdbM\xb4\xfbO>\xdbd\xf5\xed\xcetsO]\xf7\xcf=\xdb_\xb4\xd5")]
    #[case(
        matter::Codex::DateTime,
        b"\xdbM\xb4\xfbO>\xdbd\xf5\xed\xcetsO]\xf7\xcf=\xdb_\xb4\xd5\xff"
    )]
    #[case("", b"\xdbM\xb4\xfbO>\xdbd\xf5\xed\xcetsO]\xf7\xcf=\xdb_\xb4\xd5\xcd4")]
    fn unhappy_new_with_code_and_raw(#[case] code: &str, #[case] dtraw: &[u8]) {
        assert!(Dater::new(None, Some(code), Some(dtraw), None, None, None,).is_err());
    }

    #[rstest]
    fn unhappy_new_with_dts(#[values("not a date", "2020-08-22T17:50:09.988921-01")] dts: &str) {
        assert!(Dater::new(Some(dts), None, None, None, None, None,).is_err());
    }

    #[rstest]
    fn unhappy_new_with_qb64(
        #[values(
            "1ABG2020-08-22T17c50c09d988921-01c00",
            "1AAG2020-08-22T17c50c09d988921-01c",
            "1AAG"
        )]
        qb64: &str,
    ) {
        assert!(Dater::new(None, None, None, None, Some(qb64), None,).is_err());
        assert!(Dater::new(None, None, None, Some(qb64.as_bytes()), None, None).is_err());
    }

    #[rstest]
    fn unhappy_new_with_qb2(
        #[values(
            b"\xd4\x01\x06\xdbM\xb4\xfbO>\xdbd\xf5\xed\xcetsO]\xf7\xcf=\xdb_\xb4\xd5\xcd4",
            b"\xd4\x00\x06\xdbM\xb4\xfbO>\xdbd\xf5\xed\xcetsO]\xf7\xcf=\xdb_\xb4\xd5",
            b"\xd4\x00\x06\xdbM\xb4\xfbO>\xdbd\xf5\xed\xcetsO]\xf7\xcf=\xdb_\xb4\xd5"
        )]
        qb2: &[u8],
    ) {
        assert!(Dater::new(None, None, None, None, None, Some(qb2),).is_err());
    }
}
