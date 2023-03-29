use crate::{
    core::{
        common::{Identage, Ids, Ilkage, Serialage, Version, CURRENT_VERSION},
        diger::Diger,
        matter::tables as matter,
        number::Number,
        sadder::Sadder,
        saider::Saider,
        tholder::Tholder,
        verfer::Verfer,
    },
    data::{dat, Value},
    error::{err, Error, Result},
};

#[derive(Debug, Clone, PartialEq)]
pub struct Serder {
    code: String,
    raw: Vec<u8>,
    ked: Value,
    ident: String,
    kind: String,
    size: u32,
    version: Version,
    saider: Saider,
}

fn validate_ident(ident: &str) -> Result<()> {
    if ident != Identage::KERI {
        return err!(Error::Validation(format!("unexpected ident {ident}")));
    }

    Ok(())
}

impl Serder {
    pub fn new(
        code: Option<&str>,
        raw: Option<&[u8]>,
        kind: Option<&str>,
        ked: Option<&Value>,
        sad: Option<&Self>,
    ) -> Result<Self> {
        let code = code.unwrap_or(matter::Codex::Blake3_256);
        let serder = Sadder::new(Some(code), raw, kind, ked, sad)?;
        validate_ident(&serder.ident())?;

        Ok(serder)
    }

    pub fn new_with_ked(ked: &Value, code: Option<&str>, kind: Option<&str>) -> Result<Self> {
        Self::new(code, None, kind, Some(ked), None)
    }

    pub fn verfers(&self) -> Result<Vec<Verfer>> {
        let mut result: Vec<Verfer> = Vec::new();
        let map = self.ked.to_map()?;

        let label = Ids::k;
        if map.contains_key(label) {
            let r = self.ked[label].to_vec();
            if r.is_ok() {
                for key in r? {
                    result.push(Verfer::new(None, None, None, Some(&key.to_string()?), None)?);
                }
            }
        }

        Ok(result)
    }

    pub fn digers(&self) -> Result<Vec<Diger>> {
        let mut result: Vec<Diger> = Vec::new();
        let map = self.ked.to_map()?;

        let label = Ids::n;
        if map.contains_key(label) {
            let r = self.ked[label].to_vec();
            if r.is_ok() {
                for key in r? {
                    result.push(Diger::new(None, None, None, None, Some(&key.to_string()?), None)?);
                }
            }
        }

        Ok(result)
    }

    pub fn werfers(&self) -> Result<Vec<Verfer>> {
        let mut result: Vec<Verfer> = Vec::new();
        let map = self.ked.to_map()?;

        let label = Ids::b;
        if map.contains_key(label) {
            for witness in self.ked[label].to_vec()? {
                result.push(Verfer::new(None, None, None, Some(&witness.to_string()?), None)?)
            }
        }

        Ok(result)
    }

    pub fn tholder(&self) -> Result<Option<Tholder>> {
        let map = self.ked.to_map()?;

        let label = Ids::kt;
        let result = if map.contains_key(label) {
            Some(Tholder::new(None, None, Some(&(self.ked[label])))?)
        } else {
            None
        };

        Ok(result)
    }

    pub fn ntholder(&self) -> Result<Option<Tholder>> {
        let map = self.ked.to_map()?;

        let label = Ids::nt;
        let result = if map.contains_key(label) {
            Some(Tholder::new(None, None, Some(&(self.ked[label])))?)
        } else {
            None
        };

        Ok(result)
    }

    pub fn sner(&self) -> Result<Number> {
        let label = Ids::s;

        Number::new(None, Some(&self.ked[label].to_string()?), None, None, None, None, None)
    }

    pub fn sn(&self) -> Result<u128> {
        self.sner()?.num()
    }

    pub fn fner(&self) -> Result<Option<Number>> {
        let map = self.ked.to_map()?;

        let label = Ids::f;
        let result = if map.contains_key(label) {
            Some(Number::new(
                None,
                None,
                None,
                None,
                None,
                Some(&self.ked[label].to_string()?),
                None,
            )?)
        } else {
            None
        };

        Ok(result)
    }

    pub fn _fn(&self) -> Result<u128> {
        let _fner = self.fner()?;

        if let Some(_fner) = _fner {
            _fner.num()
        } else {
            err!(Error::Validation("first seen does not exist".to_string()))
        }
    }

    pub fn pre(&self) -> Result<String> {
        let label = Ids::i;
        self.ked[label].to_string()
    }

    pub fn preb(&self) -> Result<Vec<u8>> {
        Ok(self.pre()?.as_bytes().to_vec())
    }

    pub fn est(&self) -> Result<bool> {
        const ILKS: &[&str] = &[Ilkage::icp, Ilkage::rot, Ilkage::dip, Ilkage::drt];

        let label = Ids::t;
        let ilk = self.ked[label].to_string()?;

        Ok(ILKS.contains(&ilk.as_str()))
    }

    // pretty implemented in Sadder (this was overridden for some reason in KERIpy)
}

impl Default for Serder {
    fn default() -> Self {
        Serder {
            code: matter::Codex::Blake3_256.to_string(),
            raw: vec![],
            ked: dat!({}),
            ident: Identage::KERI.to_string(),
            kind: Serialage::JSON.to_string(),
            size: 0,
            version: CURRENT_VERSION.clone(),
            saider: Saider::default(),
        }
    }
}

impl Sadder for Serder {
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
        self.code = code.to_string();
    }

    fn set_raw(&mut self, raw: &[u8]) {
        self.raw = raw.to_vec();
    }

    fn set_ked(&mut self, ked: &Value) {
        self.ked = ked.clone();
    }

    fn set_ident(&mut self, ident: &str) {
        self.ident = ident.to_string();
    }

    fn set_kind(&mut self, kind: &str) {
        self.kind = kind.to_string();
    }

    fn set_size(&mut self, size: u32) {
        self.size = size;
    }

    fn set_version(&mut self, version: &Version) {
        self.version = version.clone();
    }

    fn set_saider(&mut self, saider: &Saider) {
        self.saider = saider.clone();
    }
}

#[cfg(test)]
pub(crate) mod test {
    use crate::{
        core::{
            common::{
                sniff, versify, Identage, Ids, Ilkage, Serialage, Version, CURRENT_VERSION,
                MINIMUM_SNIFF_SIZE, VERSION_FULL_SIZE,
            },
            matter::{tables as matter, Matter},
            number::Number,
            prefixer::Prefixer,
            sadder::Sadder,
            saider::Saider,
            serder::Serder,
            tholder::Tholder,
        },
        data::Value,
        error::{err, Error, Result},
    };

    #[test]
    fn python_interop() {
        assert!(Serder::new(None, None, None, None, None).is_err());

        let _vs = "KERI10JSON000000_";
        let e1 = dat!({
            "v": _vs,
            "d": "",
            "i": "ABCDEFG",
            "s": "0001",
            "t": "rot"
        });
        let (_, mut e1) = Saider::saidify(&e1, None, None, None, None).unwrap();

        let serder = Serder::new(None, None, None, Some(&e1), None).unwrap();
        assert_eq!(serder.ked(), e1);
        assert_eq!(serder.kind(), Serialage::JSON);
        assert_eq!(serder.version(), *CURRENT_VERSION);
        assert_eq!(serder.said().unwrap(), "EIM66TjBMfwPnbwK7oZqbZyGz9nOeVmQHeH3NZxrsk8F");
        assert_eq!(serder.saidb().unwrap(), b"EIM66TjBMfwPnbwK7oZqbZyGz9nOeVmQHeH3NZxrsk8F");
        assert_eq!(serder.size(), 111);
        assert_eq!(serder.verfers().unwrap(), []);
        assert_eq!(serder.raw(), b"{\"v\":\"KERI10JSON00006f_\",\"d\":\"EIM66TjBMfwPnbwK7oZqbZyGz9nOeVmQHeH3NZxrsk8F\",\"i\":\"ABCDEFG\",\"s\":\"0001\",\"t\":\"rot\"}");
        assert_eq!(serder.sn().unwrap(), 1);
        assert_eq!(serder.pre().unwrap(), "ABCDEFG");
        assert_eq!(serder.preb().unwrap(), b"ABCDEFG");

        let e1s = e1.to_json().unwrap();
        assert_eq!(e1s, "{\"v\":\"KERI10JSON00006f_\",\"d\":\"EIM66TjBMfwPnbwK7oZqbZyGz9nOeVmQHeH3NZxrsk8F\",\"i\":\"ABCDEFG\",\"s\":\"0001\",\"t\":\"rot\"}");

        let vs = versify(None, None, Some(Serialage::JSON), Some(e1s.len() as u32)).unwrap();
        assert_eq!(vs, "KERI10JSON00006f_");
        let label = Ids::v;
        e1[label] = dat!(&vs);
        let pretty = serder.pretty(None).unwrap();
        // this next one indents by 2, unlike KERIpy
        assert_eq!(
            pretty,
            "{\n".to_string()
                + "  \"v\": \"KERI10JSON00006f_\",\n"
                + "  \"d\": \"EIM66TjBMfwPnbwK7oZqbZyGz9nOeVmQHeH3NZxrsk8F\",\n"
                + "  \"i\": \"ABCDEFG\",\n"
                + "  \"s\": \"0001\",\n"
                + "  \"t\": \"rot\"\n"
                + "}"
        );

        let e1s = e1.to_json().unwrap();
        let e1sb = e1s.as_bytes();
        assert!(sniff(&e1sb[..VERSION_FULL_SIZE]).is_err());

        let result1 = sniff(&e1sb[..MINIMUM_SNIFF_SIZE]).unwrap();
        assert_eq!(result1.ident, Identage::KERI);
        assert_eq!(result1.kind, Serialage::JSON);
        assert_eq!(result1.size, 111);

        let result1 = sniff(e1sb).unwrap();
        assert_eq!(result1.ident, Identage::KERI);
        assert_eq!(result1.kind, Serialage::JSON);
        assert_eq!(result1.size, 111);

        let mut e1sb_extra = e1sb.to_vec();
        e1sb_extra.append(&mut b"extra attached at the end".to_vec());

        let ked = dat!({
            "v": "KERI10JSON00006a_",
            "d": "HAg9_-rPd8oga-oyPghCEIlJZHKbYXcP86LQl0Yg2AvA",
            "i": "ABCDEFG",
            "s": 1,
            "t": "rot"
        });
        let raw = b"{\"v\":\"KERI10JSON00006a_\",\"d\":\"HAg9_-rPd8oga-oyPghCEIlJZHKbYXcP86LQl0Yg2AvA\",\"i\":\"ABCDEFG\",\"s\":1,\"t\":\"rot\"}";

        let srdr = Serder::new(Some(matter::Codex::SHA3_256), Some(raw), None, None, None).unwrap();
        assert_eq!(srdr.kind(), "JSON");
        assert_eq!(srdr.raw(), raw);
        assert_eq!(srdr.ked(), ked);
        assert_eq!(srdr.saider().code(), matter::Codex::SHA3_256);

        let ked = dat!({
            "v": "KERI10JSON00006a_",
            "d": "EADZ055vgh5utgSY3OOL1lW0m1pJ1W0Ia6-SVuGa0OqE",
            "i": "ABCDEFG",
            "s": 1,
            "t": "rot"
        });
        let raw = b"{\"v\":\"KERI10JSON00006a_\",\"d\":\"EADZ055vgh5utgSY3OOL1lW0m1pJ1W0Ia6-SVuGa0OqE\",\"i\":\"ABCDEFG\",\"s\":1,\"t\":\"rot\"}";

        let srdr =
            Serder::new(Some(matter::Codex::Blake3_256), Some(raw), None, None, None).unwrap();
        assert_eq!(srdr.kind(), "JSON");
        assert_eq!(srdr.raw(), raw);
        assert_eq!(srdr.ked(), ked);
        assert_eq!(srdr.saider().code(), matter::Codex::Blake3_256);

        assert!(srdr.est().unwrap());
    }

    #[test]
    fn inception() {
        let aids = &[
            "BEy_EvE8OUMqj0AgCJ3wOCOrIVHVtwubYAysPyaAv9VI",
            "BC9Df6ssUZQFQZJYVUyfudw4WTQsugGcvVD_Z4ChFGE4",
            "BEejlxZytU7gjUwtgkmNKmBWiFPKSsXjk_uxzoun8dtK",
        ];

        let pre0 = aids[0];
        let wit0 = aids[1];
        let wit1 = aids[2];
        let srdr = incept(
            &[pre0],
            None,
            None,
            None,
            None,
            Some(&[wit0, wit1]),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();
        assert_eq!(srdr.raw(),
            b"{\"v\":\"KERI10JSON00015a_\",\"t\":\"icp\",\"d\":\"EBAjyPZ8Ed4XXl5cVZhqAy7SuaGivQp0WqQKVXvg7oqd\",\"i\":\"BEy_EvE8OUMqj0AgCJ3wOCOrIVHVtwubYAysPyaAv9VI\",\"s\":\"0\",\"kt\":\"1\",\"k\":[\"BEy_EvE8OUMqj0AgCJ3wOCOrIVHVtwubYAysPyaAv9VI\"],\"nt\":\"0\",\"n\":[],\"bt\":\"2\",\"b\":[\"BC9Df6ssUZQFQZJYVUyfudw4WTQsugGcvVD_Z4ChFGE4\",\"BEejlxZytU7gjUwtgkmNKmBWiFPKSsXjk_uxzoun8dtK\"],\"c\":[],\"a\":[]}"
        );
        assert_eq!(srdr.pre().unwrap(), pre0);
        assert_eq!(srdr.sn().unwrap(), 0);
        assert_eq!(
            srdr.verfers()
                .unwrap()
                .iter()
                .map(|verfer| verfer.qb64().unwrap())
                .collect::<Vec<String>>(),
            [pre0.to_string()]
        );
        assert_eq!(
            srdr.werfers()
                .unwrap()
                .iter()
                .map(|werfer| werfer.qb64().unwrap())
                .collect::<Vec<String>>(),
            [wit0.to_string(), wit1.to_string()]
        );

        println!("{p}", p = srdr.pretty(None).unwrap());
    }

    #[test]
    fn creation() {
        let ked = dat!({
            "v": "KERI10JSON00011c_",
            "t": "rep",
            "d": "EBAjyPZ8Ed4XXl5cVZhqAy7SuaGivQp0WqQKVXvg7oqd",
            "dt": "2020-08-22T17:50:12.988921+00:00",
            "r": "logs/processor",
            "a":
                {
                    "d": "EBAjyPZ8Ed4XXl5cVZhqAy7SuaGivQp0WqQKVXvg7oqd",
                    "i": "BEy_EvE8OUMqj0AgCJ3wOCOrIVHVtwubYAysPyaAv9VI",
                    "name": "John Jones",
                    "role": "Founder",
                }
        });

        let srdr = Serder::new(None, None, None, Some(&ked), None).unwrap();
        assert_eq!(srdr.said().unwrap(), "EBAjyPZ8Ed4XXl5cVZhqAy7SuaGivQp0WqQKVXvg7oqd");
        assert_eq!(srdr.saidb().unwrap(), b"EBAjyPZ8Ed4XXl5cVZhqAy7SuaGivQp0WqQKVXvg7oqd");

        let ked = dat!({
            "v": "KERI10JSON000000_",
            "t": "icp",
            "d": "",
            "i": "BEy_EvE8OUMqj0AgCJ3wOCOrIVHVtwubYAysPyaAv9VI",
            "s": "0",
            "kt": "1",
            "k": ["BC9Df6ssUZQFQZJYVUyfudw4WTQsugGcvVD_Z4ChFGE4"],
            "n": "",
            "bt": "0",
            "b": [],
            "c": [],
            "a": [],
        });

        let (_, mut ked) = Saider::saidify(&ked, None, None, None, None).unwrap();
        let srdr = Serder::new(None, None, None, Some(&ked), None).unwrap();
        assert_eq!(srdr.tholder().unwrap().unwrap().sith().unwrap(), dat!("1"));
        assert_eq!(srdr.tholder().unwrap().unwrap().thold(), dat!(1));
        assert_eq!(srdr.sn().unwrap(), 0);
        assert_eq!(srdr.sner().unwrap().num().unwrap(), 0);

        assert!(srdr.ntholder().unwrap().is_none());
        assert!(srdr.fner().unwrap().is_none());
        assert!(srdr._fn().is_err());
        assert_eq!(srdr.digers().unwrap().len(), 0);

        ked["s"] = dat!("-1");
        let srdr = Serder::new(None, None, None, Some(&ked), None).unwrap();
        assert!(srdr.sn().is_err());

        ked["s"] = dat!("15.34");
        let srdr = Serder::new(None, None, None, Some(&ked), None).unwrap();
        assert!(srdr.sn().is_err());

        let ked = dat!({
            "v": "KERI10JSON000000_",
            "t": "icp",
            "d": "",
            "i": "BEy_EvE8OUMqj0AgCJ3wOCOrIVHVtwubYAysPyaAv9VI",
            "s": "0",
            "kt": "1",
            "k": ["BC9Df6ssUZQFQZJYVUyfudw4WTQsugGcvVD_Z4ChFGE4"],
            "nt": "1",
            "n": ["ELC5L3iBVD77d_MYbYGGCUQgqQBju1o4x1Ud-z2sL-ux"],
            "bt": "0",
            "f": &Number::new(Some(0), None, None, None, None, None, None).unwrap().qb64().unwrap(),
            "b": [],
            "c": [],
            "a": [],
        });

        let (_, ked) = Saider::saidify(&ked, None, None, None, None).unwrap();
        let srdr = Serder::new(None, None, None, Some(&ked), None).unwrap();
        assert_eq!(srdr.tholder().unwrap().unwrap().sith().unwrap(), dat!("1"));
        assert_eq!(srdr.tholder().unwrap().unwrap().thold(), dat!(1));
        assert_eq!(srdr.sn().unwrap(), 0);
        assert_eq!(srdr.sner().unwrap().num().unwrap(), 0);

        assert_eq!(srdr.ntholder().unwrap().unwrap().sith().unwrap(), dat!("1"));
        assert_eq!(srdr.ntholder().unwrap().unwrap().thold(), dat!(1));
        assert!(srdr.fner().unwrap().is_some());
        assert_eq!(srdr._fn().unwrap(), 0);
        assert_eq!(srdr.digers().unwrap().len(), 1);

        let ked = dat!({
            "v": "ACDC10JSON000000_",
            "t": "icp",
            "d": "",
            "i": "BEy_EvE8OUMqj0AgCJ3wOCOrIVHVtwubYAysPyaAv9VI",
            "s": "0",
            "kt": "1",
            "k": ["BC9Df6ssUZQFQZJYVUyfudw4WTQsugGcvVD_Z4ChFGE4"],
            "nt": "1",
            "n": ["ELC5L3iBVD77d_MYbYGGCUQgqQBju1o4x1Ud-z2sL-ux"],
            "bt": "0",
            "f": &Number::new(Some(0), None, None, None, None, None, None).unwrap().qb64().unwrap(),
            "b": [],
            "c": [],
            "a": [],
        });

        let (_, ked) = Saider::saidify(&ked, None, None, None, None).unwrap();
        assert!(Serder::new(None, None, None, Some(&ked), None).is_err());
    }

    pub(crate) mod traiter {
        #[allow(non_upper_case_globals)]
        #[allow(non_snake_case)]
        mod Codex {
            const EstOnly: &str = "EO";
            const DoNotDelegate: &str = "DND";
            const NoBackeds: &str = "NB";
        }
    }

    // what follows is a simple inception function. it is used above to verify serder functionality.

    // this function uses convenience methods unlike most test code. it is likely that it will
    // be extracted and used elsewhere - and convenience methods make sense outside the tests.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn incept(
        keys: &[&str],          // current keys qb64
        sith: Option<&Value>,   // current signing threshold
        ndigs: Option<&[&str]>, // next keys qb64
        nsith: Option<&Value>,  // next signing threshold
        toad: Option<u128>,     // witness threshold number
        wits: Option<&[&str]>,  // witness identifier prefixes qb64
        cnfg: Option<&[&str]>,  // configuration traits from traiter::Codex
        data: Option<&[Value]>, // seal dicts
        version: Option<&Version>,
        kind: Option<&str>,
        code: Option<&str>,
        intive: Option<bool>, // sith, nsith and toad are ints, not hex when numeric
        delpre: Option<&str>, // delegator identifier prefix
    ) -> Result<Serder> {
        let version = version.unwrap_or(CURRENT_VERSION);
        let kind = kind.unwrap_or(Serialage::JSON);
        let intive = intive.unwrap_or(false);

        let vs = &versify(None, Some(version), Some(kind), Some(0))?;
        let ilk = if delpre.is_none() { Ilkage::icp } else { Ilkage::dip };
        let sner = Number::new_with_num(0)?;

        let sith = if let Some(sith) = sith {
            sith.clone()
        } else {
            let mut s: i64 = (keys.len() as i64 + 1) / 2;
            s = if s > 1 { s } else { 1 };
            dat!(s)
        };

        let tholder = Tholder::new_with_sith(&sith)?;
        if tholder.num()?.is_some() && tholder.num()?.unwrap() < 1 {
            return err!(Error::Value(format!(
                "invalid sith = {n} less than 1",
                n = tholder.num()?.unwrap()
            )));
        }
        if tholder.size() as usize > keys.len() {
            return err!(Error::Value(format!(
                "invalid sith size = {s} for keys = {keys:?}",
                s = tholder.size()
            )));
        }

        let ndigs = ndigs.unwrap_or(&[]);
        let nsith = if let Some(nsith) = nsith {
            nsith.clone()
        } else {
            let mut s: i64 = (ndigs.len() as i64 + 1) / 2;
            s = if s > 0 { s } else { 0 };
            dat!(s)
        };

        let ntholder = Tholder::new_with_sith(&nsith)?;
        if ntholder.size() as usize > ndigs.len() {
            return err!(Error::Value(format!(
                "invalid nsith size = {s} for keys = {keys:?}",
                s = ntholder.size()
            )));
        }

        let wits = wits.unwrap_or(&[]);
        let mut unique = wits.to_vec();
        unique.dedup();
        if wits.len() != unique.len() {
            return err!(Error::Value(format!("invalid wits = {wits:?}, has duplicates")));
        }

        let toader = if let Some(toad) = toad {
            Number::new_with_num(toad)?
        } else if wits.is_empty() {
            Number::new_with_num(0)?
        } else {
            let toad = ample(wits.len() as u128, None, None)?;
            Number::new_with_num(toad)?
        };

        if !wits.is_empty() {
            if toader.num()? < 1 || toader.num()? > wits.len() as u128 {
                return err!(Error::Value(format!(
                    "invalid toad = {n} for wits = {wits:?}",
                    n = toader.num()?
                )));
            }
        } else if toader.num()? != 0 {
            return err!(Error::Value(format!(
                "invalid toad = {n} for wits = {wits:?}",
                n = toader.num()?
            )));
        }

        let cnfg = cnfg.unwrap_or(&[]);
        let data = data.unwrap_or(&[]);

        let kt = if let Some(n) = tholder.num()? {
            if intive && n < u32::MAX {
                dat!(n)
            } else {
                tholder.sith()?
            }
        } else {
            tholder.sith()?
        };

        let nt = if let Some(n) = ntholder.num()? {
            if intive && n < u32::MAX {
                dat!(n)
            } else {
                ntholder.sith()?
            }
        } else {
            ntholder.sith()?
        };

        let toad = if intive && toader.num()? < u32::MAX as u128 {
            dat!(toader.num()? as i64)
        } else {
            dat!(&toader.numh()?)
        };

        let keys: Vec<Value> = keys.iter().map(|key| dat!(*key)).collect();
        let ndigs: Vec<Value> = ndigs.iter().map(|dig| dat!(*dig)).collect();
        let wits: Vec<Value> = wits.iter().map(|wit| dat!(*wit)).collect();
        let cnfg: Vec<Value> = cnfg.iter().map(|cfg| dat!(*cfg)).collect();

        let mut ked = dat!({
            "v": vs,
            "t": ilk,
            "d": "",
            "i": "",
            "s": &sner.numh()?,
            "kt": kt,
            "k": keys.as_slice(),
            "nt": nt,
            "n": ndigs.as_slice(),
            "bt": toad,
            "b": wits.as_slice(),
            "c": cnfg.as_slice(),
            "a": data
        });

        let code = if let Some(delpre) = delpre {
            let label = Ids::di;
            ked[label] = dat!(delpre);
            Some(code.unwrap_or(matter::Codex::Blake3_256))
        } else {
            code
        };

        let prefixer = if delpre.is_none() && code.is_none() && keys.len() == 1 {
            let prefixer = Prefixer::new_with_qb64(&keys[0].to_string()?)?;
            if prefixer.digestive() {
                return err!(Error::Value(format!(
                    "invalid code, digestive = {c}, must be derived from ked",
                    c = prefixer.code()
                )));
            }
            prefixer
        } else {
            let prefixer = Prefixer::new_with_ked(&ked, None, code)?;
            if delpre.is_some() && !prefixer.digestive() {
                return err!(Error::Value(format!(
                    "invalid derivation code = {c} for delegation, must be digestive",
                    c = prefixer.code()
                )));
            }
            prefixer
        };

        let label = Ids::i;
        ked[label] = dat!(&prefixer.qb64()?);
        let ked = if prefixer.digestive() {
            let label = Ids::d;
            ked[label] = dat!(&prefixer.qb64()?);
            ked
        } else {
            let (_, ked) = Saider::saidify(&ked, None, None, None, None)?;
            ked
        };

        Serder::new(None, None, None, Some(&ked), None)
    }

    fn ample(n: u128, f: Option<u128>, weak: Option<bool>) -> Result<u128> {
        let weak = weak.unwrap_or(true);
        let n = if n > 0 { n } else { 0 };
        if let Some(f) = f {
            let f = if f > 0 { f } else { 0 };
            let m1 = (n + f + 2) / 2;
            let m2 = if n - f > 0 { n - f } else { 0 };

            if m2 < m1 && n > 0 {
                return err!(Error::Value(format!("invalid f={f}, too big for n={n}")));
            }

            if weak {
                match [n, m1, m2].iter().min() {
                    Some(x) => Ok(*x),
                    None => err!(Error::Value("unreachable".to_string())),
                }
            } else {
                Ok(std::cmp::min(n, std::cmp::max(m1, m2)))
            }
        } else {
            let f1 = std::cmp::max(1, std::cmp::max(0, n - 1) / 3);
            let f2 = std::cmp::max(1, (std::cmp::max(0, n - 1) + 2) / 3);

            if weak {
                match [n, (n + f1 + 3) / 2, (n + f2 + 3) / 2].iter().min() {
                    Some(x) => Ok(*x),
                    None => err!(Error::Value("unreachable".to_string())),
                }
            } else {
                match [0, n - f1, (n + f1 + 3) / 2].iter().max() {
                    Some(x) => Ok(std::cmp::min(n, *x)),
                    None => err!(Error::Value("unreachable".to_string())),
                }
            }
        }
    }
}
