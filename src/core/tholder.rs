use crate::{
    core::{
        bexter::{tables as bexter, Bexter},
        matter::{tables as matter, Matter},
        number::{tables as number, Number},
    },
    data::{data, Array, Data, Value},
    error::{err, Error, Result},
};

use lazy_static::lazy_static;
use num_rational::Rational32;

#[derive(Debug, Clone, PartialEq)]
pub struct Tholder {
    thold: Value,
    weighted: bool,
    size: u32,
    number: Option<Number>,
    bexter: Option<Bexter>,
}

impl Default for Tholder {
    fn default() -> Self {
        Tholder { thold: data!(1), weighted: false, size: 1, number: None, bexter: None }
    }
}

fn values_to_rationals(value: &Value) -> Result<Vec<Vec<Rational32>>> {
    let threshold = value.to_vec()?;
    let separator = "/";
    let mut clauses: Vec<Vec<Rational32>> = Vec::new();

    for _clause in threshold {
        let mut clause: Vec<Rational32> = Vec::new();
        let _clause = _clause.to_vec()?;
        for weight in _clause {
            let weight = weight.to_string()?;
            let parts: Vec<&str> = weight.split(separator).collect();
            if parts.len() != 2 {
                // must be 0 or 1
                if parts[0] == "0" {
                    clause.push(Rational32::new(0, 1));
                } else if parts[0] == "1" {
                    clause.push(Rational32::new(1, 1));
                } else {
                    return err!(Error::Value("integral weight must be 0 or 1".to_string()));
                }
            } else {
                let numer = parts[0].parse::<i32>()?;
                let denom = parts[1].parse::<i32>()?;
                if numer < 0 || denom < 0 {
                    return err!(Error::Value("negative weights do not make sense".to_string()));
                }
                if numer > denom {
                    return err!(Error::Value(format!("weight {numer}/{denom} > 1")));
                }
                clause.push(Rational32::new(numer, denom));
            }
        }
        clauses.push(clause);
    }

    for clause in &*clauses {
        let mut sum = Rational32::new(0, 1);

        for weight in clause {
            sum += weight;
        }

        if sum < Rational32::new(1, 1) {
            return err!(Error::Value(format!(
                "invalid sith clause = {}, clause weight sums must be >= 1",
                value.to_json()?
            )));
        }
    }

    Ok(clauses)
}

fn rationals_to_bext(clauses: &Vec<Vec<Rational32>>) -> String {
    let mut envelope: Vec<String> = Vec::new();
    for clause in clauses {
        let mut text_clause: Vec<String> = Vec::new();
        for weight in clause {
            if *weight.denom() == 1 {
                text_clause.push(format!("{n}", n = weight.numer()));
            } else {
                text_clause.push(format!("{n}s{d}", n = weight.numer(), d = weight.denom()));
            }
        }
        envelope.push(text_clause.join("c"));
    }
    envelope.join("a")
}

impl Tholder {
    pub fn new(thold: Option<&Value>, limen: Option<&[u8]>, sith: Option<&Value>) -> Result<Self> {
        let mut tholder = Self::default();

        if let Some(thold) = thold {
            tholder.process_thold(thold)?;
        }

        if let Some(limen) = limen {
            tholder.process_limen(limen)?;
        }

        if let Some(sith) = sith {
            tholder.process_sith(sith)?;
        }

        if tholder == Self::default() {
            return err!(Error::EmptyMaterial("missing threshold expression".to_string()));
        }

        Ok(tholder)
    }

    pub fn new_with_thold(thold: &Value) -> Result<Self> {
        Self::new(Some(thold), None, None)
    }

    pub fn new_with_limen(limen: &[u8]) -> Result<Self> {
        Self::new(None, Some(limen), None)
    }

    pub fn new_with_sith(sith: &Value) -> Result<Self> {
        Self::new(None, None, Some(sith))
    }

    pub fn thold(&self) -> Value {
        self.thold.clone()
    }

    pub fn weighted(&self) -> bool {
        self.weighted
    }

    pub fn size(&self) -> u32 {
        self.size
    }

    pub fn num(&self) -> Result<Option<u32>> {
        if !self.weighted() {
            Ok(Some(u32::try_from(self.thold().to_i64()?)?))
        } else {
            Ok(None)
        }
    }

    pub fn number(&self) -> Option<Number> {
        self.number.as_ref().cloned()
    }

    pub fn bexter(&self) -> Option<Bexter> {
        self.bexter.as_ref().cloned()
    }

    pub fn limen(&self) -> Result<Vec<u8>> {
        if self.weighted() {
            if let Some(bexter) = self.bexter() {
                bexter.qb64b()
            } else {
                // unreachable
                err!(Error::Value("malformed tholder".to_string()))
            }
        } else if let Some(number) = self.number() {
            number.qb64b()
        } else {
            // unreachable
            err!(Error::Value("malformed tholder".to_string()))
        }
    }

    pub fn sith(&self) -> Result<Value> {
        if self.weighted() {
            let thold = self.thold();
            if thold.to_vec()?.len() == 1 {
                Ok(thold[0].clone())
            } else {
                Ok(thold)
            }
        } else {
            let thold = self.thold().to_i64()?;
            let sith = format!("{thold:x}");
            Ok(data!(&sith))
        }
    }

    pub fn to_json(&self) -> Result<String> {
        self.sith()?.to_json()
    }

    pub fn satisfy(&self, indices: &[u32]) -> Result<bool> {
        return if self.number().is_some() {
            self.satisfy_numeric(indices)
        } else if self.bexter().is_some() {
            self.satisfy_weighted(indices)
        } else {
            Ok(false)
        };
    }

    fn satisfy_numeric(&self, indices: &[u32]) -> Result<bool> {
        let thold = self.thold().to_i64()?;

        if thold > 0 && indices.len() >= thold as usize {
            return Ok(true);
        }

        Ok(false)
    }

    fn satisfy_weighted(&self, indices: &[u32]) -> Result<bool> {
        lazy_static! {
            static ref RATIONAL_ONE: Rational32 = Rational32::new(1, 1);
        }

        let mut indices = indices.to_vec();
        indices.sort();
        indices.dedup();

        let mut sats = vec![false; self.size() as usize];
        for index in indices {
            sats[index as usize] = true
        }

        let clauses = values_to_rationals(&self.thold())?;

        let mut wio: usize = 0;
        for clause in clauses {
            let mut cw = Rational32::new(0, 1);
            for weight in clause {
                if sats[wio] {
                    cw += weight;
                }
                wio += 1;
            }
            if cw < *RATIONAL_ONE {
                return Ok(false);
            }
        }

        Ok(true)
    }

    fn process_thold(&mut self, thold: &Value) -> Result<()> {
        let result = thold.to_i64();
        if result.is_ok() {
            self.process_unweighted(result.unwrap())?;
            return Ok(());
        }

        self.process_weighted(thold)?;

        Ok(())
    }

    fn process_limen(&mut self, limen: &[u8]) -> Result<()> {
        if limen.is_empty() {
            return Ok(());
        }

        let limen = String::from_utf8(limen.to_vec())?;

        let hs = matter::hardage(limen.chars().next().unwrap())? as usize;
        let code = &limen[..hs];

        if number::Codex::has_code(code) {
            let number = Number::new(None, None, None, None, None, Some(&limen), None)?;
            let thold = i64::try_from(number.num()?)?;
            self.process_unweighted(thold)?;
        } else if bexter::Codex::has_code(code) {
            let bexter = Bexter::new(None, None, None, None, Some(&limen), None)?;
            let t = bexter.bext()?.replace('s', "/");
            let clauses: Vec<&str> = t.split('a').collect();
            let mut oclauses: Array = Vec::new();
            for clause in clauses {
                let weights: Vec<&str> = clause.split('c').collect();
                let mut oweights: Array = Vec::new();
                for weight in weights {
                    oweights.push(data!(weight));
                }
                oclauses.push(data!(oweights.as_slice()));
            }
            let thold = data!(oclauses.as_slice());
            self.process_weighted(&thold)?;
        } else {
            return err!(Error::UnexpectedCode(code.to_string()));
        }

        Ok(())
    }

    fn process_sith(&mut self, sith: &Value) -> Result<()> {
        let result = sith.to_i64();
        if result.is_ok() {
            self.process_unweighted(result?)?;
            return Ok(());
        }

        let mut sith = sith.clone();
        let result = sith.to_string();
        if result.is_ok() {
            let s = result?;

            if s.starts_with('[') {
                let v: serde_json::Value = serde_json::from_str(&s)?;
                sith = Value::from(&v);
            } else {
                let thold = i64::from_str_radix(&s, 16)?;
                self.process_unweighted(thold)?;
                return Ok(());
            }
        }

        let array = sith.to_vec()?;

        if array.is_empty() {
            return err!(Error::Value(format!("empty weight list = {s}", s = sith.to_json()?)));
        }

        if !array.iter().all(|clause| clause.to_vec().is_ok()) {
            sith = data!([sith]);
        }

        for clause in sith.to_vec()? {
            let _clause = clause.to_vec()?;
            for weight in _clause {
                if weight.to_string().is_err() {
                    return err!(Error::Value(format!(
                        "invalid sith = {s}, some weights in clause {c} are not strings",
                        s = sith.to_json()?,
                        c = clause.to_json()?
                    )));
                }
            }
        }

        // KERIpy converts to rationals here but it's more convenient for us to persist as a Value
        // in the struct, and convert in process_weighted()
        self.process_weighted(&sith)?;

        Ok(())
    }

    fn process_unweighted(&mut self, thold: i64) -> Result<()> {
        if thold < 0 {
            return err!(Error::Value(format!("negative int threshold {thold}")));
        }

        self.size = u32::try_from(thold)?;
        self.weighted = false;
        self.thold = data!(self.size);
        self.number = Some(Number::new(Some(thold as u128), None, None, None, None, None, None)?);
        self.bexter = None;

        Ok(())
    }

    fn process_weighted(&mut self, thold: &Value) -> Result<()> {
        let threshold = &values_to_rationals(thold)?;
        let mut size = 0;
        for clause in threshold {
            size += clause.len() as u32;
        }
        let mut outer: Vec<Value> = Vec::new();
        for clause in threshold {
            let mut inner: Vec<Value> = Vec::new();
            for weight in clause {
                if *weight.denom() == 1 {
                    inner.push(data!(&format!("{n}", n = weight.numer())));
                } else {
                    inner.push(data!(&weight.to_string()));
                }
            }
            outer.push(data!(inner.as_slice()));
        }

        self.thold = data!(outer.as_slice());
        self.weighted = true;
        self.size = size;
        self.number = None;
        let bext = rationals_to_bext(threshold);
        self.bexter = Some(Bexter::new(Some(&bext), None, None, None, None, None)?);

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::core::tholder::Tholder;
    use rstest::rstest;

    #[test]
    fn convenience() {
        assert!(Tholder::new_with_thold(&data!(11)).is_ok());
        assert!(Tholder::new_with_limen(b"MAAL").is_ok());
        assert!(Tholder::new_with_sith(&data!("b")).is_ok());
    }

    #[rstest]
    fn creation(
        #[values(b"MAAL")] limen: &[u8],
        #[values(
            Tholder::new(None, None, Some(&data!("b"))).unwrap(),
            Tholder::new(None, None, Some(&data!(11))).unwrap(),
            Tholder::new(None, Some(limen), None).unwrap(),
            Tholder::new(Some(&data!(11)), None, None).unwrap(),
        )]
        tholder: Tholder,
    ) {
        assert!(!tholder.weighted());
        assert_eq!(tholder.size(), 11);
        assert_eq!(tholder.thold().to_i64().unwrap(), 11);
        assert_eq!(tholder.limen().unwrap(), limen);
        assert_eq!(tholder.sith().unwrap(), data!("b"));
        assert_eq!(tholder.to_json().unwrap(), "\"b\"");
        assert_eq!(tholder.num().unwrap().unwrap(), 11);
        assert!(!tholder.satisfy(&[0, 1, 2]).unwrap());
        assert!(tholder.satisfy(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10]).unwrap());
    }

    #[test]
    fn python_interop() {
        assert!(Tholder::new(None, None, None).is_err());

        assert!(Tholder::new(None, None, Some(&data!("[[\"1/2\",\"4/4\"]]"))).is_ok());
        assert!(Tholder::new(None, None, Some(&data!("[[\"1/2\",\"-3/4\"]]"))).is_err());
        assert!(!Tholder::default().satisfy(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9]).unwrap());
        assert!(Tholder::new(None, None, Some(&data!("[[\"1/2\",\"3/4\"]]"))).is_ok());
        assert!(Tholder::new(None, Some(&[]), Some(&data!("[[\"1/2\",\"3/4\"]]"))).is_ok());
        assert!(Tholder::new(None, Some(b"DKxy2sgzfplyr-tgwIxS19f2OchFHtLwPWD3v4oYimBx"), None)
            .is_err());

        let tholder = Tholder::new(None, None, Some(&data!("f"))).unwrap();
        assert!(!tholder.weighted());
        assert_eq!(tholder.size(), 15);
        assert_eq!(tholder.thold().to_i64().unwrap(), 15);
        assert_eq!(tholder.limen().unwrap(), b"MAAP");
        assert_eq!(tholder.sith().unwrap(), data!("f"));
        assert_eq!(tholder.to_json().unwrap(), "\"f\"");
        assert_eq!(tholder.num().unwrap().unwrap(), 15);
        assert!(!tholder.satisfy(&[0, 1, 2]).unwrap());
        assert!(tholder.satisfy(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]).unwrap());

        let tholder = Tholder::new(None, None, Some(&data!(2))).unwrap();
        assert!(!tholder.weighted());
        assert_eq!(tholder.size(), 2);
        assert_eq!(tholder.thold().to_i64().unwrap(), 2);
        assert_eq!(tholder.limen().unwrap(), b"MAAC");
        assert_eq!(tholder.sith().unwrap(), data!("2"));
        assert_eq!(tholder.to_json().unwrap(), "\"2\"");
        assert_eq!(tholder.num().unwrap().unwrap(), 2);
        assert!(tholder.satisfy(&[0, 1, 2]).unwrap());
        assert!(tholder.satisfy(&[0, 1]).unwrap());

        let tholder = Tholder::new(None, None, Some(&data!(1))).unwrap();
        assert!(!tholder.weighted());
        assert_eq!(tholder.size(), 1);
        assert_eq!(tholder.thold().to_i64().unwrap(), 1);
        assert_eq!(tholder.limen().unwrap(), b"MAAB");
        assert_eq!(tholder.sith().unwrap(), data!("1"));
        assert_eq!(tholder.to_json().unwrap(), "\"1\"");
        assert_eq!(tholder.num().unwrap().unwrap(), 1);
        assert!(tholder.satisfy(&[0]).unwrap());

        assert!(Tholder::new(None, None, Some(&data!(-1))).is_err());

        assert!(Tholder::new(None, None, Some(&data!([1]))).is_err());
        assert!(Tholder::new(None, None, Some(&data!([2]))).is_err());
        assert!(Tholder::new(None, None, Some(&data!(["2"]))).is_err());
        assert!(Tholder::new(None, None, Some(&data!([0.5, 0.5]))).is_err());
        assert!(Tholder::new(None, None, Some(&data!(["0.5", "0.5"]))).is_err());
        assert!(Tholder::new(None, None, Some(&data!(1.0))).is_err());
        assert!(Tholder::new(None, None, Some(&data!("1.0"))).is_err());
        assert!(Tholder::new(None, None, Some(&data!(0.5))).is_err());
        assert!(Tholder::new(None, None, Some(&data!("0.5"))).is_err());
        assert!(Tholder::new(None, None, Some(&data!("1.0/2.0"))).is_err());
        assert!(Tholder::new(None, None, Some(&data!([]))).is_err());
        assert!(Tholder::new(None, None, Some(&data!(["1/3", "1/2", []]))).is_err());
        assert!(Tholder::new(None, None, Some(&data!(["1/3", "1/2"]))).is_err());
        assert!(Tholder::new(None, None, Some(&data!([[], []]))).is_err());
        assert!(Tholder::new(None, None, Some(&data!([["1/3", "1/2",], ["1"]]))).is_err());
        assert!(Tholder::new(None, None, Some(&data!([["1/3", "1/2"], []]))).is_err());
        assert!(Tholder::new(None, None, Some(&data!([["1/2", "1/2"], [[], "1"]]))).is_err());
        assert!(Tholder::new(None, None, Some(&data!([["1/2", "1/2", "3/2"]]))).is_err());
        assert!(Tholder::new(None, None, Some(&data!(["1/2", "1/2", "3/2"]))).is_err());
        assert!(Tholder::new(None, None, Some(&data!(["1/2", "1/2", "2/1"]))).is_err());
        assert!(Tholder::new(None, None, Some(&data!(["1/2", "1/2", "2"]))).is_err());
        assert!(Tholder::new(None, None, Some(&data!([["1/2", "1/2", "2"]]))).is_err());
        assert!(Tholder::new(None, None, Some(&data!([["1/2", "1/2"], "1"]))).is_err());
        assert!(Tholder::new(None, None, Some(&data!([["1/2", "1/2"], 1]))).is_err());
        assert!(Tholder::new(None, None, Some(&data!([["1/2", "1/2"], "1.0"]))).is_err());
        assert!(Tholder::new(None, None, Some(&data!(["1/2", "1/2", []]))).is_err());
        assert!(Tholder::new(None, None, Some(&data!(["1/2", 0.5]))).is_err());

        let tholder =
            Tholder::new(None, None, Some(&data!(["1/2", "1/2", "1/4", "1/4", "1/4"]))).unwrap();
        assert!(tholder.weighted());
        assert_eq!(tholder.size(), 5);
        assert_eq!(tholder.thold(), data!([["1/2", "1/2", "1/4", "1/4", "1/4"]]));
        assert_eq!(tholder.limen().unwrap(), b"4AAFA1s2c1s2c1s4c1s4c1s4");
        assert_eq!(tholder.sith().unwrap(), data!(["1/2", "1/2", "1/4", "1/4", "1/4"]));
        assert_eq!(tholder.to_json().unwrap(), "[\"1/2\",\"1/2\",\"1/4\",\"1/4\",\"1/4\"]"); // this isn't identical to KERIpy but still conforms to JSON
        assert_eq!(tholder.num().unwrap(), None);
        assert!(tholder.satisfy(&[0, 2, 4]).unwrap());
        assert!(tholder.satisfy(&[0, 1]).unwrap());
        assert!(tholder.satisfy(&[1, 3, 4]).unwrap());
        assert!(tholder.satisfy(&[0, 1, 2, 3, 4]).unwrap());
        assert!(tholder.satisfy(&[3, 2, 0]).unwrap());
        assert!(tholder.satisfy(&[0, 0, 1, 2, 1]).unwrap());
        assert!(!tholder.satisfy(&[0, 2]).unwrap());
        assert!(!tholder.satisfy(&[2, 3, 4]).unwrap());
        assert!(!tholder.satisfy(&[0, 0, 2]).unwrap());

        let tholder =
            Tholder::new(None, None, Some(&data!(["1/2", "1/2", "1/4", "1/4", "1/4", "0"])))
                .unwrap();
        assert!(tholder.weighted());
        assert_eq!(tholder.size(), 6);
        assert_eq!(tholder.thold(), data!([["1/2", "1/2", "1/4", "1/4", "1/4", "0"]]));
        assert_eq!(tholder.limen().unwrap(), b"6AAGAAA1s2c1s2c1s4c1s4c1s4c0");
        assert_eq!(tholder.sith().unwrap(), data!(["1/2", "1/2", "1/4", "1/4", "1/4", "0"]));
        assert_eq!(tholder.to_json().unwrap(), "[\"1/2\",\"1/2\",\"1/4\",\"1/4\",\"1/4\",\"0\"]");
        assert_eq!(tholder.num().unwrap(), None);
        assert!(tholder.satisfy(&[0, 2, 4]).unwrap());
        assert!(tholder.satisfy(&[0, 1]).unwrap());
        assert!(tholder.satisfy(&[1, 3, 4]).unwrap());
        assert!(tholder.satisfy(&[0, 1, 2, 3, 4]).unwrap());
        assert!(tholder.satisfy(&[3, 2, 0]).unwrap());
        assert!(tholder.satisfy(&[0, 0, 1, 2, 1]).unwrap());
        assert!(!tholder.satisfy(&[0, 2, 5]).unwrap());
        assert!(!tholder.satisfy(&[2, 3, 4, 5]).unwrap());

        let tholder =
            Tholder::new(None, None, Some(&data!([["1/2", "1/2", "1/4", "1/4", "1/4"]]))).unwrap();
        assert!(tholder.weighted());
        assert_eq!(tholder.size(), 5);
        assert_eq!(tholder.thold(), data!([["1/2", "1/2", "1/4", "1/4", "1/4"]]));
        assert_eq!(tholder.limen().unwrap(), b"4AAFA1s2c1s2c1s4c1s4c1s4");
        assert_eq!(tholder.sith().unwrap(), data!(["1/2", "1/2", "1/4", "1/4", "1/4"]));
        assert_eq!(tholder.to_json().unwrap(), "[\"1/2\",\"1/2\",\"1/4\",\"1/4\",\"1/4\"]"); // this isn't identical to KERIpy but still conforms to JSON
        assert_eq!(tholder.num().unwrap(), None);
        assert!(tholder.satisfy(&[0, 2, 4]).unwrap());
        assert!(tholder.satisfy(&[0, 1]).unwrap());
        assert!(tholder.satisfy(&[1, 3, 4]).unwrap());
        assert!(tholder.satisfy(&[0, 1, 2, 3, 4]).unwrap());
        assert!(tholder.satisfy(&[3, 2, 0]).unwrap());
        assert!(tholder.satisfy(&[0, 0, 1, 2, 1]).unwrap());
        assert!(!tholder.satisfy(&[0, 2]).unwrap());
        assert!(!tholder.satisfy(&[2, 3, 4]).unwrap());
        assert!(!tholder.satisfy(&[0, 0, 2]).unwrap());

        let tholder = Tholder::new(
            None,
            None,
            Some(&data!([["1/2", "1/2", "1/4", "1/4", "1/4"], ["1/1", "1"]])),
        )
        .unwrap();
        assert!(tholder.weighted());
        assert_eq!(tholder.size(), 7);
        assert_eq!(tholder.thold(), data!([["1/2", "1/2", "1/4", "1/4", "1/4"], ["1", "1"]]));
        assert_eq!(tholder.limen().unwrap(), b"4AAGA1s2c1s2c1s4c1s4c1s4a1c1");
        assert_eq!(
            tholder.sith().unwrap(),
            data!([["1/2", "1/2", "1/4", "1/4", "1/4"], ["1", "1"]])
        );
        assert_eq!(
            tholder.to_json().unwrap(),
            "[[\"1/2\",\"1/2\",\"1/4\",\"1/4\",\"1/4\"],[\"1\",\"1\"]]"
        );
        assert_eq!(tholder.num().unwrap(), None);
        assert!(tholder.satisfy(&[1, 2, 3, 5]).unwrap());
        assert!(tholder.satisfy(&[0, 1, 6]).unwrap());
        assert!(!tholder.satisfy(&[0, 1]).unwrap());
        assert!(!tholder.satisfy(&[5, 6]).unwrap());
        assert!(!tholder.satisfy(&[2, 3, 4]).unwrap());
        assert!(!tholder.satisfy(&[]).unwrap());

        let tholder = Tholder::new(None, Some(b"4AAGA1s2c1s2c1s4c1s4c1s4a1c1"), None).unwrap();
        assert!(tholder.weighted());
        assert_eq!(tholder.size(), 7);
        assert_eq!(tholder.thold(), data!([["1/2", "1/2", "1/4", "1/4", "1/4"], ["1", "1"]]));
        assert_eq!(tholder.limen().unwrap(), b"4AAGA1s2c1s2c1s4c1s4c1s4a1c1");
        assert_eq!(
            tholder.sith().unwrap(),
            data!([["1/2", "1/2", "1/4", "1/4", "1/4"], ["1", "1"]])
        );
        assert_eq!(
            tholder.to_json().unwrap(),
            "[[\"1/2\",\"1/2\",\"1/4\",\"1/4\",\"1/4\"],[\"1\",\"1\"]]"
        );
        assert_eq!(tholder.num().unwrap(), None);
        assert!(tholder.satisfy(&[1, 2, 3, 5]).unwrap());
        assert!(tholder.satisfy(&[0, 1, 6]).unwrap());
        assert!(!tholder.satisfy(&[0, 1]).unwrap());
        assert!(!tholder.satisfy(&[5, 6]).unwrap());
        assert!(!tholder.satisfy(&[2, 3, 4]).unwrap());
        assert!(!tholder.satisfy(&[]).unwrap());

        let tholder = Tholder::new(
            Some(&data!([["1/2", "1/2", "1/4", "1/4", "1/4"], ["1/1", "1/1"]])),
            None,
            None,
        )
        .unwrap();
        assert!(tholder.weighted());
        assert_eq!(tholder.size(), 7);
        assert_eq!(tholder.thold(), data!([["1/2", "1/2", "1/4", "1/4", "1/4"], ["1", "1"]]));
        assert_eq!(tholder.limen().unwrap(), b"4AAGA1s2c1s2c1s4c1s4c1s4a1c1");
        assert_eq!(
            tholder.sith().unwrap(),
            data!([["1/2", "1/2", "1/4", "1/4", "1/4"], ["1", "1"]])
        );
        assert_eq!(
            tholder.to_json().unwrap(),
            "[[\"1/2\",\"1/2\",\"1/4\",\"1/4\",\"1/4\"],[\"1\",\"1\"]]"
        );
        assert_eq!(tholder.num().unwrap(), None);
        assert!(tholder.satisfy(&[1, 2, 3, 5]).unwrap());
        assert!(tholder.satisfy(&[0, 1, 6]).unwrap());
        assert!(!tholder.satisfy(&[0, 1]).unwrap());
        assert!(!tholder.satisfy(&[5, 6]).unwrap());
        assert!(!tholder.satisfy(&[2, 3, 4]).unwrap());
        assert!(!tholder.satisfy(&[]).unwrap());
    }
}
