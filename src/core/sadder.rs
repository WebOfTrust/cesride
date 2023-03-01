use crate::core::{
    common::{loads, sizeify, sniff, Ids, Version, CURRENT_VERSION},
    matter::{tables as matter, Matter},
    saider::Saider,
};
use crate::data::{Data, Value};
use crate::error::{err, Error, Result};

#[derive(Debug, Clone, PartialEq)]
struct ExhaleResult {
    raw: Vec<u8>,
    ident: String,
    kind: String,
    ked: Value,
    version: Version,
}

#[derive(Debug, Clone, PartialEq)]
struct InhaleResult {
    ked: Value,
    ident: String,
    kind: String,
    version: Version,
    size: u32,
}

fn inhale(raw: &[u8]) -> Result<InhaleResult> {
    let result = sniff(raw)?;

    if result.version != *CURRENT_VERSION {
        return err!(Error::Value(format!(
            "unsupported version = {:?}, current version = {:?}",
            result.version, CURRENT_VERSION
        )));
    }

    let ked = loads(raw, Some(result.size), Some(&result.kind))?;

    Ok(InhaleResult {
        ked,
        ident: result.ident,
        kind: result.kind,
        version: result.version,
        size: result.size,
    })
}

fn exhale(ked: &Value, kind: Option<&str>) -> Result<ExhaleResult> {
    let result = sizeify(ked, kind)?;
    Ok(ExhaleResult {
        raw: result.raw,
        ident: result.ident,
        ked: result.ked,
        kind: result.kind,
        version: result.version,
    })
}

pub trait Sadder: Default + Clone {
    fn code(&self) -> String;
    fn raw(&self) -> Vec<u8>;
    fn ked(&self) -> Value;
    fn ident(&self) -> String;
    fn kind(&self) -> String;
    fn size(&self) -> u32;
    fn version(&self) -> Version;
    fn saider(&self) -> Saider;

    fn set_code(&mut self, code: &str);
    fn set_raw(&mut self, raw: &[u8]);
    fn set_ked(&mut self, ked: &Value);
    fn set_ident(&mut self, ident: &str);
    fn set_kind(&mut self, kind: &str);
    fn set_size(&mut self, size: u32);
    fn set_version(&mut self, version: &Version);
    fn set_saider(&mut self, saider: &Saider);

    fn new(
        code: Option<&str>,
        raw: Option<&[u8]>,
        kind: Option<&str>,
        ked: Option<&Value>,
        sad: Option<&Self>,
    ) -> Result<Self> {
        let mut sadder = Self::default();
        sadder.set_code(code.unwrap_or(matter::Codex::Blake3_256));
        if let Some(raw) = raw {
            sadder.populate_from_raw(raw)?;
        } else if let Some(ked) = ked {
            sadder.populate_from_ked(ked, kind)?;
        } else if let Some(sad) = sad {
            sadder = sad.clone();
        } else {
            return err!(Error::Value("improper initialzation. need sad, raw or ked.".to_string()));
        }

        Ok(sadder)
    }

    fn populate_from_raw(&mut self, raw: &[u8]) -> Result<()> {
        let result = inhale(raw)?;

        self.set_raw(&raw[..(result.size as usize)]);
        self.set_ked(&result.ked);
        self.set_ident(&result.ident);
        self.set_kind(&result.kind);
        self.set_size(result.size);
        self.set_version(&result.version);
        self.set_saider(&Saider::new(
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(&result.ked[Ids::d].to_string()?),
            None,
        )?);

        if self.code() != self.saider().code() {
            return err!(Error::Validation(
                "unmatched codes when constructing saider for sadder".to_string()
            ));
        }

        Ok(())
    }

    fn populate_from_ked(&mut self, ked: &Value, kind: Option<&str>) -> Result<()> {
        let result = exhale(ked, kind)?;

        self.set_raw(&result.raw);
        self.set_ked(&result.ked);
        self.set_ident(&result.ident);
        self.set_kind(&result.kind);
        self.set_size(result.raw.len() as u32);
        self.set_version(&result.version);
        self.set_saider(&Saider::new(
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(&result.ked[Ids::d].to_string()?),
            None,
        )?);

        if self.code() != self.saider().code() {
            return err!(Error::Validation(
                "unmatched codes when constructing saider for sadder".to_string()
            ));
        }

        Ok(())
    }

    fn populate_from_kind_and_self(&mut self, kind: &str) -> Result<()> {
        let result = exhale(&self.ked(), Some(kind))?;

        self.set_raw(&result.raw);
        self.set_ked(&result.ked);
        self.set_ident(&result.ident);
        self.set_kind(&result.kind);
        self.set_size(result.raw.len() as u32);
        self.set_version(&result.version);
        self.set_saider(&Saider::new(
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(&result.ked[Ids::d].to_string()?),
            None,
        )?);

        if self.code() != self.saider().code() {
            return err!(Error::Validation(
                "unmatched codes when constructing saider for sadder".to_string()
            ));
        }

        Ok(())
    }

    fn said(&self) -> Result<String> {
        self.saider().qb64()
    }

    fn saidb(&self) -> Result<Vec<u8>> {
        self.saider().qb64b()
    }

    fn pretty(&self, size: Option<usize>) -> Result<String> {
        let v: serde_json::Value = serde_json::from_str(&self.ked().to_json()?)?;
        match serde_json::to_string_pretty(&v) {
            Ok(s) => {
                let size = size.unwrap_or(1024);
                if s.len() > size {
                    Ok(s[..size].to_string())
                } else {
                    Ok(s)
                }
            }
            // pretty sure this is unreachable unless we borked .to_json()
            Err(_) => err!(Error::Value("cannot prettify ked".to_string())),
        }
    }
}

#[cfg(test)]
mod test {
    use crate::core::{
        common::{Identage, Serialage, Version, CURRENT_VERSION},
        matter::{tables as matter, Matter},
        sadder::Sadder,
        saider::Saider,
    };
    use crate::data::{data, Data, Value};

    #[derive(Debug, Clone, PartialEq)]
    struct TestSadder {
        code: String,
        raw: Vec<u8>,
        ked: Value,
        ident: String,
        kind: String,
        size: u32,
        version: Version,
        saider: Saider,
    }

    impl Default for TestSadder {
        fn default() -> Self {
            TestSadder {
                code: matter::Codex::Blake3_256.to_string(),
                raw: vec![],
                ked: data!({}),
                ident: Identage::KERI.to_string(),
                kind: Serialage::JSON.to_string(),
                size: 0,
                version: CURRENT_VERSION.clone(),
                saider: Saider::default(),
            }
        }
    }

    impl Sadder for TestSadder {
        fn code(&self) -> String {
            self.code.clone()
        }
        fn raw(&self) -> Vec<u8> {
            self.raw.clone()
        }
        fn ked(&self) -> Value {
            self.ked.clone()
        }
        fn ident(&self) -> String {
            self.ident.clone()
        }
        fn kind(&self) -> String {
            self.kind.clone()
        }
        fn size(&self) -> u32 {
            self.size
        }
        fn version(&self) -> Version {
            self.version.clone()
        }
        fn saider(&self) -> Saider {
            self.saider.clone()
        }

        fn set_code(&mut self, code: &str) {
            self.code = code.to_string()
        }
        fn set_raw(&mut self, raw: &[u8]) {
            self.raw = raw.to_vec()
        }
        fn set_ked(&mut self, ked: &Value) {
            self.ked = ked.clone()
        }
        fn set_ident(&mut self, ident: &str) {
            self.ident = ident.to_string()
        }
        fn set_kind(&mut self, kind: &str) {
            self.kind = kind.to_string()
        }
        fn set_size(&mut self, size: u32) {
            self.size = size
        }
        fn set_version(&mut self, version: &Version) {
            self.version = version.clone()
        }
        fn set_saider(&mut self, saider: &Saider) {
            self.saider = saider.clone()
        }
    }

    #[test]
    fn new() {
        let ked = data!({
            "v": "KERI10JSON000000_",
            "d": "",
        });

        let (saider, ked) = Saider::saidify(&ked, None, None, None, None).unwrap();
        let said = saider.qb64().unwrap();
        let saidb = saider.qb64b().unwrap();

        // with ked
        let sadder = TestSadder::new(None, None, None, Some(&ked), None).unwrap();
        assert_eq!(sadder.said().unwrap(), said);
        assert_eq!(sadder.saidb().unwrap(), saidb);
        assert_eq!(sadder.ked(), ked);
        assert_eq!(sadder.ked()["d"].to_string().unwrap(), said);

        // with raw
        let sadder = TestSadder::new(None, Some(&sadder.raw()), None, None, None).unwrap();
        assert_eq!(sadder.said().unwrap(), said);
        assert_eq!(sadder.saidb().unwrap(), saidb);
        assert_eq!(sadder.ked(), ked);
        assert_eq!(sadder.ked()["d"].to_string().unwrap(), said);

        // with sad
        let sadder = TestSadder::new(None, None, None, None, Some(&sadder)).unwrap();
        assert_eq!(sadder.said().unwrap(), said);
        assert_eq!(sadder.saidb().unwrap(), saidb);
        assert_eq!(sadder.ked(), ked);
        assert_eq!(sadder.ked()["d"].to_string().unwrap(), said);
    }

    #[test]
    fn new_unhappy_paths() {
        let ked = data!({
            "v": "KERI10JSON000000_",
            "d": "",
        });

        let (saider, ked) = Saider::saidify(&ked, None, None, None, None).unwrap();
        let mut ked2 = ked.clone();
        ked2["v"] = data!("KERI11JSON000000_");

        let raw = &ked.to_json().unwrap().as_bytes().to_vec();
        let raw2 = &ked2.to_json().unwrap().as_bytes().to_vec();

        assert!(TestSadder::new(None, Some(raw2), None, None, None).is_err());
        assert!(TestSadder::new(None, None, None, None, None).is_err());

        assert_eq!(saider.code(), matter::Codex::Blake3_256);
        assert!(
            TestSadder::new(Some(matter::Codex::Blake2b_256), Some(raw), None, None, None).is_err()
        );
        assert!(TestSadder::new(Some(matter::Codex::Blake2b_256), None, None, Some(&ked), None)
            .is_err());
    }

    #[test]
    fn populate_from_kind_and_self() {
        let ked = data!({
            "v": "KERI10JSON000000_",
            "d": "",
        });

        let (_, ked) = Saider::saidify(&ked, None, None, None, None).unwrap();

        let mut sadder = TestSadder::new(None, None, None, Some(&ked), None).unwrap();
        assert!(sadder.populate_from_kind_and_self(Serialage::JSON).is_ok());
    }

    #[test]
    fn populate_from_kind_and_self_unhappy_paths() {
        let ked = data!({
            "v": "KERI10JSON000000_",
            "d": "",
        });

        let (_, mut ked_blake3) =
            Saider::saidify(&ked, Some(matter::Codex::Blake3_256), None, None, None).unwrap();
        let (saider_blake2b, _) =
            Saider::saidify(&ked, Some(matter::Codex::Blake2b_256), None, None, None).unwrap();

        ked_blake3["d"] = data!(&saider_blake2b.qb64().unwrap());

        // saider code and sadder code must match
        let mut sadder = TestSadder::default();
        sadder.set_ked(&ked_blake3);
        sadder.set_code(matter::Codex::Blake3_256);
        assert!(sadder.populate_from_kind_and_self(Serialage::JSON).is_err());
    }

    #[test]
    fn pretty() {
        let ked = data!({
            "v": "KERI10JSON000000_",
            "d": "",
        });

        let (_, ked) = Saider::saidify(&ked, None, None, None, None).unwrap();

        let sadder = TestSadder::new(None, None, None, Some(&ked), None).unwrap();

        assert_eq!(sadder.pretty(None).unwrap(), "{\n  \"v\": \"KERI10JSON00004c_\",\n  \"d\": \"EN5gqodYDGPSYQvdixCjfD2leqb6zhPoDYcB21hfqu8d\"\n}");
        assert_eq!(sadder.pretty(Some(10)).unwrap(), "{\n  \"v\": \"");
    }
}
