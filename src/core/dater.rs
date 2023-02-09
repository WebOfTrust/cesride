use lazy_static::lazy_static;

use crate::core::matter::{tables as matter, Matter};
use crate::error::{err, Error, Result};

type Blake2b256 = blake2::Blake2b<blake2::digest::consts::U32>;

pub trait Dater {
    fn new_with_code_and_raw(code: &str, raw: &[u8]) -> Result<Matter>;
    fn new_with_dts(dts: &str) -> Result<Matter>;
    fn new_with_dtsb(dts: &[u8]) -> Result<Matter>;
    fn new_with_qb64(qb64: &str) -> Result<Matter>;
    fn new_with_qb64b(qb64b: &[u8]) -> Result<Matter>;
    fn new_with_qb2(qb2: &[u8]) -> Result<Matter>;
    fn dts(&self) -> Result<String>;
    fn dtsb(&self) -> Result<Vec<u8>>;
}

fn validate_code(code: &str) -> Result<()> {
    lazy_static! {
        static ref CODES: Vec<&'static str> = vec![matter::Codex::DateTime.code(),];
    }

    if !CODES.contains(&code) {
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

impl Dater for Matter {
    fn new_with_code_and_raw(code: &str, raw: &[u8]) -> Result<Matter> {
        if !code.is_empty() {
            validate_code(code)?;
        }
        if raw.is_empty() {
            let qb64 = format!("{}{}", matter::Codex::DateTime.code(), now_as_b64());
            Matter::new_with_qb64(&qb64)
        } else {
            Matter::new_with_code_and_raw(code, raw)
        }
    }

    fn new_with_dts(dts: &str) -> Result<Matter> {
        let b64 = if dts.is_empty() { now_as_b64() } else { iso_8601_to_b64(dts) };
        let qb64 = format!("{}{}", matter::Codex::DateTime.code(), &b64);
        Matter::new_with_qb64(&qb64)
    }

    fn new_with_dtsb(dts: &[u8]) -> Result<Matter> {
        Matter::new_with_dts(&String::from_utf8(dts.to_vec())?)
    }

    fn new_with_qb64(qb64: &str) -> Result<Matter> {
        let dater = Matter::new_with_qb64(qb64)?;
        validate_code(&dater.code)?;
        Ok(dater)
    }

    fn new_with_qb64b(qb64b: &[u8]) -> Result<Matter> {
        let dater = Matter::new_with_qb64b(qb64b)?;
        validate_code(&dater.code)?;
        Ok(dater)
    }

    fn new_with_qb2(qb2: &[u8]) -> Result<Matter> {
        let dater = Matter::new_with_qb2(qb2)?;
        validate_code(&dater.code)?;
        Ok(dater)
    }

    fn dts(&self) -> Result<String> {
        let hs = matter::sizage(&self.code)?.hs as usize;
        let qb64 = self.clone().qb64()?;
        Ok(b64_to_iso_8601(&qb64[hs..]))
    }

    fn dtsb(&self) -> Result<Vec<u8>> {
        Ok(self.dts()?.as_bytes().to_vec())
    }
}

#[cfg(test)]
mod test_dater {
    use super::{matter, Dater, Matter};
    use rstest::rstest;

    #[rstest]
    fn test_new_default(
        #[values(
        &<Matter as Dater>::new_with_code_and_raw("", &[]).unwrap(),
        &<Matter as Dater>::new_with_dts("").unwrap(),
        &<Matter as Dater>::new_with_dtsb(b"").unwrap(),
    )]
        dater: &Matter,
    ) {
        assert_eq!(dater.code, matter::Codex::DateTime.code());
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
    fn test_new_with_data(
        #[case] dts: &str,
        #[case] dtqb64: &str,
        #[case] dtraw: &[u8],
        #[case] dtqb2: &[u8],
        #[values(
            &<Matter as Dater>::new_with_code_and_raw(matter::Codex::DateTime.code(), dtraw).unwrap(),
            &<Matter as Dater>::new_with_dts(dts).unwrap(),
            &<Matter as Dater>::new_with_dtsb(dts.as_bytes()).unwrap(),
            &<Matter as Dater>::new_with_qb64(dtqb64).unwrap(),
            &<Matter as Dater>::new_with_qb64b(dtqb64.as_bytes()).unwrap(),
            &<Matter as Dater>::new_with_qb2(dtqb2).unwrap(),
        )]
        dater: &Matter,
    ) {
        assert_eq!(dater.code, matter::Codex::DateTime.code());
        assert_eq!(dater.dts().unwrap(), dts);
        assert_eq!(dater.dtsb().unwrap(), dts.as_bytes());
        assert_eq!(dater.raw, dtraw);
        assert_eq!(dater.qb64().unwrap(), dtqb64);
        assert_eq!(dater.qb64b().unwrap(), dtqb64.as_bytes());
        assert_eq!(dater.qb2().unwrap(), dtqb2);
    }

    #[rstest]
    #[case(
            matter::Codex::Big.code(),
            b"\xdbM\xb4\xfbO>\xdbd\xf5\xed\xcetsO]\xf7\xcf=\xdb_\xb4\xd5\xcd4",
    )]
    #[case(
            matter::Codex::DateTime.code(),
            b"\xdbM\xb4\xfbO>\xdbd\xf5\xed\xcetsO]\xf7\xcf=\xdb_\xb4\xd5",
    )]
    #[case(
            matter::Codex::DateTime.code(),
            b"\xdbM\xb4\xfbO>\xdbd\xf5\xed\xcetsO]\xf7\xcf=\xdb_\xb4\xd5\xff",
    )]
    #[case("", b"\xdbM\xb4\xfbO>\xdbd\xf5\xed\xcetsO]\xf7\xcf=\xdb_\xb4\xd5\xcd4")]
    fn test_unhappy_new_with_code_and_raw(#[case] code: &str, #[case] dtraw: &[u8]) {
        assert!(<Matter as Dater>::new_with_code_and_raw(code, dtraw).is_err());
    }

    #[rstest]
    fn test_unhappy_new_with_dts(
        #[values("not a date", "2020-08-22T17:50:09.988921-01")] dts: &str,
    ) {
        assert!(<Matter as Dater>::new_with_dts(dts).is_err());
        assert!(<Matter as Dater>::new_with_dtsb(dts.as_bytes()).is_err());
    }

    #[rstest]
    fn test_unhappy_new_with_qb64(
        #[values(
            "1ABG2020-08-22T17c50c09d988921-01c00",
            "1AAG2020-08-22T17c50c09d988921-01c",
            "1AAG"
        )]
        qb64: &str,
    ) {
        assert!(<Matter as Dater>::new_with_qb64(qb64).is_err());
        assert!(<Matter as Dater>::new_with_qb64b(qb64.as_bytes()).is_err());
    }

    #[rstest]
    fn test_unhappy_new_with_qb2(
        #[values(
            b"\xd4\x01\x06\xdbM\xb4\xfbO>\xdbd\xf5\xed\xcetsO]\xf7\xcf=\xdb_\xb4\xd5\xcd4",
            b"\xd4\x00\x06\xdbM\xb4\xfbO>\xdbd\xf5\xed\xcetsO]\xf7\xcf=\xdb_\xb4\xd5",
            b"\xd4\x00\x06\xdbM\xb4\xfbO>\xdbd\xf5\xed\xcetsO]\xf7\xcf=\xdb_\xb4\xd5"
        )]
        qb2: &[u8],
    ) {
        assert!(<Matter as Dater>::new_with_qb2(qb2).is_err());
    }
}
