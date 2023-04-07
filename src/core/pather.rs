use crate::{
    core::{
        bexter::{rawify, tables as bexter, Bext},
        matter::{tables as matter, Matter},
        sadder::Sadder,
        saider::Saider,
        serder::Serder,
        util::REB64_STRING,
    },
    data::Value,
    error::{err, Error, Result},
};

use lazy_static::lazy_static;
use regex::Regex;

#[derive(Debug, Clone, PartialEq)]
pub struct Pather {
    code: String,
    raw: Vec<u8>,
    size: u32,
}

impl Default for Pather {
    fn default() -> Self {
        Pather { code: matter::Codex::StrB64_L0.to_string(), raw: vec![], size: 0 }
    }
}

fn validate_code(code: &str) -> Result<()> {
    if !bexter::Codex::has_code(code) {
        return err!(Error::UnexpectedCode(code.to_string()));
    }

    Ok(())
}

fn pather_from_bext(bext: &str, code: &str) -> Result<Pather> {
    lazy_static! {
        static ref REB64: Regex = Regex::new(REB64_STRING).unwrap();
    }

    if !REB64.is_match(bext) {
        return err!(Error::Value("invalid base64".to_string()));
    }

    let raw = rawify(bext)?;

    Matter::new(Some(code), Some(&raw), None, None, None)
}

impl Pather {
    pub fn new(
        path: Option<&Value>,
        bext: Option<&str>,
        code: Option<&str>,
        raw: Option<&[u8]>,
        qb64b: Option<&[u8]>,
        qb64: Option<&str>,
        qb2: Option<&[u8]>,
    ) -> Result<Self> {
        let code = code.unwrap_or(matter::Codex::StrB64_L0);

        let pather: Pather = if bext.is_none()
            && raw.is_none()
            && qb64b.is_none()
            && qb64.is_none()
            && qb2.is_none()
        {
            if let Some(path) = path {
                pather_from_bext(&Self::bextify(path)?, code)?
            } else {
                return err!(Error::EmptyMaterial("missing bext string".to_string()));
            }
        } else if let Some(bext) = bext {
            pather_from_bext(bext, code)?
        } else {
            Matter::new(Some(code), raw, qb64b, qb64, qb2)?
        };

        validate_code(&pather.code())?;

        Ok(pather)
    }

    pub fn new_with_path(path: &Value) -> Result<Self> {
        Self::new(Some(path), None, None, None, None, None, None)
    }

    pub fn new_with_bext(bext: &str) -> Result<Self> {
        Self::new(None, Some(bext), None, None, None, None, None)
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

    pub fn path(&self) -> Result<Value> {
        let bext = self.bext()?;

        if !bext.starts_with('-') {
            return err!(Error::Value("invalid sad pointer".to_string()));
        }

        let result: Vec<Value> = bext[1..].split('-').map(|p| dat!(p)).collect();

        if result[0].to_string()?.is_empty() {
            Ok(dat!([]))
        } else {
            Ok(dat!(result.as_slice()))
        }
    }

    pub fn root(&self, root: &Self) -> Result<Self> {
        let mut path = root.path()?.to_vec()?;
        let mut to_append = self.path()?.to_vec()?;

        path.append(&mut to_append);
        let path = dat!(path.as_slice());

        Pather::new_with_path(&path)
    }

    pub fn strip(&self, root: &Self) -> Result<Self> {
        let mut root_path = root.path()?.to_vec()?;
        let mut path = self.path()?.to_vec()?;

        let hashmap: std::collections::HashMap<String, usize> =
            path.iter().enumerate().map(|(x, y)| (y.to_string().unwrap(), x)).collect();

        if root_path.len() > path.len() {
            return Ok(self.clone());
        }

        root_path.reverse();
        for p in root_path {
            path.remove(hashmap[&p.to_string()?]);
        }

        Pather::new_with_path(&dat!(path.as_slice()))
    }

    pub fn starts_with(&self, path: &Self) -> Result<bool> {
        Ok(self.bext()?.starts_with(&path.bext()?))
    }

    pub fn resolve(&self, sad: &Value) -> Result<Value> {
        Self::_resolve(sad, &self.path()?)
    }

    pub fn tail(&self, serder: &Serder) -> Result<String> {
        let val = self.resolve(&serder.ked())?;

        if val.to_string().is_ok() {
            let result = val.to_string()?;
            // validate said
            Saider::new(None, None, None, None, None, None, None, Some(&result), None)?;
            Ok(result)
        } else if val.to_map().is_ok() || val.to_vec().is_ok() {
            val.to_json()
        } else {
            return err!(Error::Value("bad tail value".to_string()));
        }
    }

    fn bextify(path: &Value) -> Result<String> {
        lazy_static! {
            static ref REB64: Regex = Regex::new(REB64_STRING).unwrap();
        }

        let mut vath = vec![];
        let path = path.to_vec()?;
        for e in &path {
            let p = e.to_string();
            let p = if let Ok(p) = p { p } else { e.to_i64()?.to_string() };

            if !REB64.is_match(&p) {
                return err!(Error::Value("invalid base64".to_string()));
            }

            vath.push(p);
        }

        Ok("-".to_string() + &vath.join("-"))
    }

    fn _resolve(val: &Value, ptr: &Value) -> Result<Value> {
        let mut ptr = ptr.to_vec()?;
        if ptr.is_empty() {
            return Ok(val.clone());
        }

        let idx = ptr.remove(0).to_string()?;

        let cur = if val.to_map().is_ok() {
            let val = val.to_map()?;
            let result = idx.parse::<usize>();
            if result.is_ok() {
                let i = result?;
                if i >= val.len() {
                    return err!(Error::Value(format!("invalid map index {i}, larger than size")));
                }
                val[i].clone()
            } else if idx.is_empty() {
                return Ok(dat!(&val));
            } else {
                if !val.contains_key(&idx) {
                    return err!(Error::Value(format!("invalid index {idx} for map")));
                }
                val[&idx].clone()
            }
        } else if val.to_vec().is_ok() {
            let val = val.to_vec()?;
            let i = idx.parse::<usize>()?;
            if i >= val.len() {
                return err!(Error::Value(format!("invalid array index {i}, larger than size")));
            }
            val[i].clone()
        } else {
            return err!(Error::Value("invalid traversal type".to_string()));
        };

        Self::_resolve(&cur, &dat!(ptr.as_slice()))
    }
}

impl Bext for Pather {}

impl Matter for Pather {
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
    use super::Pather;
    use crate::{
        core::{
            bexter::Bext,
            matter::{tables as matter, Matter},
            saider::Saider,
            serder::Serder,
        },
        data::dat,
    };

    #[test]
    fn convenience() {
        let pather = Pather::new_with_bext("-a").unwrap();

        assert!(Pather::new_with_bext(&pather.bext().unwrap()).is_ok());
        assert!(Pather::new_with_path(&pather.path().unwrap()).is_ok());
        assert!(Pather::new_with_qb2(&pather.qb2().unwrap()).is_ok());
        assert!(Pather::new_with_qb64(&pather.qb64().unwrap()).is_ok());
        assert!(Pather::new_with_qb64b(&pather.qb64b().unwrap()).is_ok());
        assert!(Pather::new_with_raw(&pather.raw(), None).is_ok());
    }

    #[test]
    fn unhappy() {
        assert!(Pather::new(
            None,
            None,
            Some(matter::Codex::Blake3_256),
            Some(b"00000000000000000000000000000000"),
            None,
            None,
            None
        )
        .is_err());
        assert!(Pather::new(None, Some("@!"), None, None, None, None, None).is_err());
        assert!(Pather::new(None, None, None, None, None, None, None).is_err());

        let pather =
            Pather::new(None, None, Some(matter::Codex::StrB64_L0), Some(b"00"), None, None, None)
                .unwrap();
        assert!(pather.path().is_err());

        let sad = dat!({
            "a": [1]
        });

        let pather = Pather::new(None, Some("-1"), None, None, None, None, None).unwrap();
        assert!(pather.resolve(&sad).is_err());

        let pather = Pather::new(None, Some("-b"), None, None, None, None, None).unwrap();
        assert!(pather.resolve(&sad).is_err());

        let pather = Pather::new(None, Some("-a-1"), None, None, None, None, None).unwrap();
        assert!(pather.resolve(&sad).is_err());

        // invalid traversal
        let sad = dat!(2);
        let pather = Pather::new(None, Some("-0"), None, None, None, None, None).unwrap();
        assert!(pather.resolve(&sad).is_err());
    }

    #[test]
    fn resolve() {
        let sad = dat!({
            "a": [2]
        });

        let pather = Pather::new(None, Some("-a-0"), None, None, None, None, None).unwrap();
        assert_eq!(pather.resolve(&sad).unwrap(), dat!(2));

        assert_eq!(Pather::_resolve(&sad, &dat!([""])).unwrap(), sad);
    }

    #[test]
    fn root() {
        let pather = Pather::new_with_bext("-a").unwrap();
        let root = Pather::new_with_bext("-r").unwrap();
        assert_eq!(pather.root(&root).unwrap().bext().unwrap(), "-r-a");
    }

    #[test]
    fn tail() {
        let _vs = "KERI10JSON000000_";
        let e1 = dat!({
            "v": _vs,
            "d": "",
            "i": "ABCDEFG",
            "s": {},
            "t": "rot",
            "x": 1
        });
        let (_, e1) = Saider::saidify(&e1, None, None, None, None).unwrap();
        let serder = Serder::new(None, None, None, Some(&e1), None).unwrap();

        let pather = Pather::new_with_bext("-d").unwrap();
        assert_eq!(pather.tail(&serder).unwrap(), e1["d"].to_string().unwrap());

        let pather = Pather::new_with_bext("-s").unwrap();
        assert_eq!(pather.tail(&serder).unwrap(), "{}");

        let pather = Pather::new_with_bext("-x").unwrap();
        assert!(pather.tail(&serder).is_err());
    }

    #[test]
    fn python_interop() {
        let sad = dat!({
            "a": {
                "z": "value",
                "b": {
                    "x": 1,
                    "y": 2,
                    "c": "test"
                }
            }
        });

        let path = dat!([]);
        let pather = Pather::new(Some(&path), None, None, None, None, None, None).unwrap();
        assert_eq!(pather.bext().unwrap(), "-");
        assert_eq!(pather.qb64().unwrap(), "6AABAAA-");
        assert_eq!(pather.raw(), b">");
        assert_eq!(pather.resolve(&sad).unwrap(), sad);
        assert_eq!(pather.path().unwrap(), path);

        let path = dat!(["a", "b", "c"]);
        let pather = Pather::new(Some(&path), None, None, None, None, None, None).unwrap();
        assert_eq!(pather.bext().unwrap(), "-a-b-c");
        assert_eq!(pather.qb64().unwrap(), "5AACAA-a-b-c");
        assert_eq!(pather.raw(), b"\x0f\x9a\xf9\xbf\x9c");
        assert_eq!(pather.resolve(&sad).unwrap().to_string().unwrap(), "test");
        assert_eq!(pather.path().unwrap(), path);

        let path = dat!(["0", "1", "2"]);
        let pather = Pather::new(Some(&path), None, None, None, None, None, None).unwrap();
        assert_eq!(pather.bext().unwrap(), "-0-1-2");
        assert_eq!(pather.qb64().unwrap(), "5AACAA-0-1-2");
        assert_eq!(pather.raw(), b"\x0f\xb4\xfb_\xb6");
        assert_eq!(pather.resolve(&sad).unwrap().to_string().unwrap(), "test");
        assert_eq!(pather.path().unwrap(), path);

        let sad = dat!({
            "field0": {
                "z": "value",
                "field1": {
                    "field2": 1,
                    "field3": 2,
                    "c": "test"
                }
            }
        });

        let path = dat!(["field0"]);
        let pather = Pather::new(Some(&path), None, None, None, None, None, None).unwrap();
        assert_eq!(pather.bext().unwrap(), "-field0");
        assert_eq!(pather.qb64().unwrap(), "4AACA-field0");
        assert_eq!(pather.raw(), b"\x03\xe7\xe2zWt");
        assert_eq!(
            pather.resolve(&sad).unwrap(),
            dat!({
                "z": "value",
                "field1": {
                    "field2": 1,
                    "field3": 2,
                    "c": "test"
                }
            })
        );
        assert_eq!(pather.path().unwrap(), path);

        let path = dat!(["field0", "field1", "field3"]);
        let pather = Pather::new(Some(&path), None, None, None, None, None, None).unwrap();
        assert_eq!(pather.bext().unwrap(), "-field0-field1-field3");
        assert_eq!(pather.qb64().unwrap(), "6AAGAAA-field0-field1-field3");
        assert_eq!(pather.raw(), b">~'\xa5wO\x9f\x89\xe9]\xd7\xe7\xe2zWw");
        assert_eq!(pather.resolve(&sad).unwrap().to_i64().unwrap(), 2);
        assert_eq!(pather.path().unwrap(), path);

        let path = dat!(["field0", "1", "0"]);
        let pather = Pather::new(Some(&path), None, None, None, None, None, None).unwrap();
        assert_eq!(pather.bext().unwrap(), "-field0-1-0");
        assert_eq!(pather.qb64().unwrap(), "4AADA-field0-1-0");
        assert_eq!(pather.raw(), b"\x03\xe7\xe2zWt\xfb_\xb4");
        assert_eq!(pather.resolve(&sad).unwrap().to_i64().unwrap(), 1);
        assert_eq!(pather.path().unwrap(), path);

        let sad = dat!({
            "field0": {
                "z": {
                    "field2": 1,
                    "field3": 2,
                    "c": "test"
                },
                "field1": "value"
            }
        });

        let text = "-0-z-2";
        let pather = Pather::new(None, Some(text), None, None, None, None, None).unwrap();
        assert_eq!(pather.bext().unwrap(), text);
        assert_eq!(pather.qb64().unwrap(), "5AACAA-0-z-2");
        assert_eq!(pather.raw(), b"\x0f\xb4\xfb?\xb6");
        assert_eq!(pather.resolve(&sad).unwrap().to_string().unwrap(), "test");
        assert_eq!(pather.path().unwrap(), dat!(["0", "z", "2"]));

        let text = "-0-a";
        let pather = Pather::new(None, Some(text), None, None, None, None, None).unwrap();
        assert_eq!(pather.bext().unwrap(), text);
        assert_eq!(pather.qb64().unwrap(), "4AAB-0-a");
        assert_eq!(pather.raw(), b"\xfbO\x9a");
        assert!(pather.resolve(&sad).is_err());
        assert_eq!(pather.path().unwrap(), dat!(["0", "a"]));

        let text = "-0-field1-0";
        let pather = Pather::new(None, Some(text), None, None, None, None, None).unwrap();
        assert_eq!(pather.bext().unwrap(), text);
        assert_eq!(pather.qb64().unwrap(), "4AADA-0-field1-0");
        assert_eq!(pather.raw(), b"\x03\xed>~'\xa5w_\xb4");
        assert!(pather.resolve(&sad).is_err());
        assert_eq!(pather.path().unwrap(), dat!(["0", "field1", "0"]));

        let path = dat!(["Not$Base64", "@moreso", "*again"]);
        assert!(Pather::new(Some(&path), None, None, None, None, None, None).is_err());

        let text = "-a";
        let a = Pather::new(None, Some(text), None, None, None, None, None).unwrap();
        let b = Pather::new(None, Some("-a-b"), None, None, None, None, None).unwrap();

        let pather = Pather::new(None, Some(text), None, None, None, None, None).unwrap();
        assert!(pather.starts_with(&a).unwrap());
        assert!(!pather.starts_with(&b).unwrap());

        let pnew = pather.strip(&a).unwrap();
        assert_eq!(pnew.path().unwrap(), dat!([]));

        let pnew = pather.strip(&b).unwrap();
        assert_eq!(pnew.path().unwrap(), pather.path().unwrap());

        let pather = Pather::new(None, Some("-a-b-c-d-e-f"), None, None, None, None, None).unwrap();
        assert!(pather.starts_with(&a).unwrap());
        assert!(pather.starts_with(&b).unwrap());

        let pnew = pather.strip(&a).unwrap();
        assert_eq!(pnew.path().unwrap(), dat!(["b", "c", "d", "e", "f"]));

        let pnew = pather.strip(&b).unwrap();
        assert_eq!(pnew.path().unwrap(), dat!(["c", "d", "e", "f"]));
    }
}
