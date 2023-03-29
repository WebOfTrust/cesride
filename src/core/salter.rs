use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    core::{
        common::Tierage,
        matter::{tables as matter, Matter},
        signer::Signer,
    },
    crypto::{csprng, salt},
    error::{err, Error, Result},
};

#[derive(Debug, Clone, PartialEq, ZeroizeOnDrop)]
pub struct Salter {
    #[zeroize(skip)]
    code: String,
    raw: Vec<u8>,
    #[zeroize(skip)]
    size: u32,
    #[zeroize(skip)]
    tier: String,
}

fn validate_code(code: &str) -> Result<()> {
    if code != matter::Codex::Salt_128 {
        return err!(Error::UnexpectedCode(code.to_string()));
    }

    Ok(())
}

const SALTER_SEED_BYTES: usize = 16;

impl Salter {
    pub fn new(
        tier: Option<&str>,
        code: Option<&str>,
        raw: Option<&[u8]>,
        qb64b: Option<&[u8]>,
        qb64: Option<&str>,
        qb2: Option<&[u8]>,
    ) -> Result<Self> {
        let code = code.unwrap_or(matter::Codex::Salt_128);
        validate_code(code)?;

        let mut salter: Self =
            if raw.is_none() && qb64b.is_none() && qb64.is_none() && qb2.is_none() {
                let mut raw = [0_u8; SALTER_SEED_BYTES];
                csprng::fill_bytes(&mut raw);
                let matter = Matter::new(Some(code), Some(&raw), None, None, None)?;
                raw.zeroize();
                matter
            } else {
                Matter::new(Some(code), raw, qb64b, qb64, qb2)?
            };

        salter.tier = tier.unwrap_or(Tierage::low).to_string();
        Ok(salter)
    }

    pub fn new_with_defaults(tier: Option<&str>) -> Result<Self> {
        Self::new(tier, None, None, None, None, None)
    }

    pub fn new_with_raw(raw: &[u8], code: Option<&str>, tier: Option<&str>) -> Result<Self> {
        Self::new(tier, code, Some(raw), None, None, None)
    }

    pub fn new_with_qb64b(qb64b: &[u8], tier: Option<&str>) -> Result<Self> {
        Self::new(tier, None, None, Some(qb64b), None, None)
    }

    pub fn new_with_qb64(qb64: &str, tier: Option<&str>) -> Result<Self> {
        Self::new(tier, None, None, None, Some(qb64), None)
    }

    pub fn new_with_qb2(qb2: &[u8], tier: Option<&str>) -> Result<Self> {
        Self::new(tier, None, None, None, None, Some(qb2))
    }

    pub fn stretch(
        &self,
        size: Option<usize>,
        path: Option<&str>,
        tier: Option<&str>,
        temp: Option<bool>,
    ) -> Result<Vec<u8>> {
        let temp = temp.unwrap_or(false);
        let st = self.tier();
        let tier = if temp { Tierage::min } else { tier.unwrap_or(st.as_str()) };
        let path = path.unwrap_or("");
        let size = size.unwrap_or(32);

        let seed = salt::stretch(path.as_bytes(), &self.raw(), size, tier)?;

        Ok(seed)
    }

    pub fn tier(&self) -> String {
        self.tier.clone()
    }

    pub fn signer(
        &self,
        code: Option<&str>,
        transferable: Option<bool>,
        path: Option<&str>,
        tier: Option<&str>,
        temp: Option<bool>,
    ) -> Result<Signer> {
        let code = code.unwrap_or(matter::Codex::Ed25519_Seed);
        let transferable = transferable.unwrap_or(true);
        let path = path.unwrap_or("");
        let temp = temp.unwrap_or(false);

        let size = matter::raw_size(code)?;
        let mut seed = self.stretch(Some(size as usize), Some(path), tier, Some(temp))?;

        let signer = Signer::new(Some(transferable), Some(code), Some(&seed), None, None, None)?;
        seed.zeroize();

        Ok(signer)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn signers(
        &self,
        count: Option<usize>,
        start: Option<usize>,
        path: Option<&str>,
        code: Option<&str>,
        transferable: Option<bool>,
        tier: Option<&str>,
        temp: Option<bool>,
    ) -> Result<Vec<Signer>> {
        let count = count.unwrap_or(1);
        let start = start.unwrap_or(0);
        let path = path.unwrap_or("");
        let mut signers: Vec<Signer> = vec![];

        for i in 0..count {
            let path = format!("{path}{n:x}", n = (i + start));
            signers.push(self.signer(code, transferable, Some(&path), tier, temp)?);
        }

        Ok(signers)
    }
}

impl Default for Salter {
    fn default() -> Self {
        Salter {
            code: matter::Codex::Salt_128.to_string(),
            raw: vec![],
            size: 0,
            tier: Tierage::low.to_string(),
        }
    }
}

impl Matter for Salter {
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
    use crate::core::{
        common::{versify, Ilkage, Serialage, Tierage, CURRENT_VERSION},
        matter::{tables as matter, Matter},
        salter::Salter,
        signer::Signer,
    };

    #[test]
    fn convenience() {
        let salter = Salter::new_with_defaults(None).unwrap();

        assert!(Salter::new_with_defaults(None).is_ok());
        assert!(Salter::new_with_raw(&salter.raw(), Some(&salter.code()), None).is_ok());
        assert!(Salter::new_with_qb64b(&salter.qb64b().unwrap(), None).is_ok());
        assert!(Salter::new_with_qb64(&salter.qb64().unwrap(), None).is_ok());
        assert!(Salter::new_with_qb2(&salter.qb2().unwrap(), None).is_ok());
    }

    #[test]
    fn python_interop() {
        let salter = Salter::new(None, None, None, None, None, None).unwrap();
        assert_eq!(salter.code(), matter::Codex::Salt_128);
        assert_eq!(salter.raw().len(), 16);

        let raw = b"0123456789abcdef";
        let qb64 = "0AAwMTIzNDU2Nzg5YWJjZGVm";
        let salter = Salter::new(None, None, Some(raw), None, None, None).unwrap();
        assert_eq!(salter.raw(), raw);
        assert_eq!(salter.qb64().unwrap(), qb64);

        let signer = salter.signer(None, None, Some("01"), None, Some(true)).unwrap();
        assert_eq!(signer.code(), matter::Codex::Ed25519_Seed);
        assert_eq!(signer.raw().len() as u32, matter::raw_size(&signer.code()).unwrap());
        assert_eq!(signer.verfer().code(), matter::Codex::Ed25519);
        assert_eq!(
            signer.verfer().raw().len() as u32,
            matter::raw_size(&signer.verfer().code()).unwrap()
        );
        assert_eq!(signer.qb64().unwrap(), "AMPsqBZxWdtYpBhrWnKYitwFa77s902Q-nX3sPTzqs0R");
        assert_eq!(signer.verfer().qb64().unwrap(), "DFYFwZJOMNy3FknECL8tUaQZRBUyQ9xCv6F8ckG-UCrC");

        let signer = salter.signer(None, None, Some("01"), None, None).unwrap();
        assert_eq!(signer.code(), matter::Codex::Ed25519_Seed);
        assert_eq!(signer.raw().len() as u32, matter::raw_size(&signer.code()).unwrap());
        assert_eq!(signer.verfer().code(), matter::Codex::Ed25519);
        assert_eq!(
            signer.verfer().raw().len() as u32,
            matter::raw_size(&signer.verfer().code()).unwrap()
        );
        assert_eq!(signer.qb64().unwrap(), "AEkqQiNTexWB9fTLpgJp_lXW63tFlT-Y0_mgQww4o-dC");
        assert_eq!(signer.verfer().qb64().unwrap(), "DPJGyH9H1M_SUSf18RzX8OqdyhxEyZJpKm5Em0PnpsWd");

        let salter = Salter::new(None, None, None, None, Some(qb64), None).unwrap();
        assert_eq!(salter.raw(), raw);
        assert_eq!(salter.qb64().unwrap(), qb64);

        assert!(Salter::new(None, None, None, None, Some(""), None).is_err());
    }

    #[test]
    fn vault() {
        let _vault = Vault::default().unwrap();
    }

    use crate::{
        core::{
            cigar::Cigar,
            common::Version,
            counter::{tables as counter, Counter},
            diger::Diger,
            indexer::Indexer,
            number::Number,
            sadder::Sadder,
            seqner::Seqner,
            serder::{test::incept, Serder},
            siger::Siger,
        },
        error::{err, Error, Result},
    };

    #[derive(Debug, Clone, PartialEq)]
    struct Vault {
        current: Vec<Signer>,
        next: Vec<Signer>,
    }

    #[derive(Debug, Clone, PartialEq)]
    pub struct Seal {
        i: String,
        s: String,
        d: String,
        last: bool,
    }

    impl Seal {
        pub fn new(i: &str, s: &str, d: &str, last: Option<bool>) -> Self {
            let last = last.unwrap_or(false);

            Self { i: i.to_string(), s: s.to_string(), d: d.to_string(), last }
        }

        pub fn i(&self) -> String {
            self.i.clone()
        }

        pub fn s(&self) -> Result<String> {
            Seqner::new_with_snh(&self.s)?.qb64()
        }

        pub fn d(&self) -> String {
            self.d.clone()
        }
    }

    impl Vault {
        fn default() -> Result<Self> {
            // Tierage::min is not exposed externally, this is for testing. One needs to use 'temp'
            // during stretching to accomplish this in a production scenario
            let csalter = Salter::new_with_defaults(Some(Tierage::min))?;
            let nsalter = Salter::new_with_defaults(Some(Tierage::min))?;
            let wsalter = Salter::new_with_defaults(Some(Tierage::min))?;

            let current = csalter.signers(Some(3), None, Some("icp"), None, None, None, None)?;
            let next = nsalter.signers(Some(5), None, Some("rot-0"), None, None, None, None)?;
            let witness =
                wsalter.signers(Some(4), None, Some("wit-0"), None, Some(false), None, None)?;

            let ckeys: Vec<String> =
                current.iter().map(|signer| signer.verfer().qb64().unwrap()).collect();
            let ndigs: Vec<String> = next
                .iter()
                .map(|signer| {
                    Diger::new_with_ser(&signer.verfer().qb64b().unwrap(), None)
                        .unwrap()
                        .qb64()
                        .unwrap()
                })
                .collect();
            let wkeys: Vec<String> =
                witness.iter().map(|signer| signer.verfer().qb64().unwrap()).collect();

            let ckeys: Vec<&str> = ckeys.iter().map(|key| key.as_ref()).collect();
            let ndigs: Vec<&str> = ndigs.iter().map(|dig| dig.as_ref()).collect();
            let wkeys: Vec<&str> = wkeys.iter().map(|key| key.as_ref()).collect();

            let serder = incept(
                &ckeys,
                Some(&dat!(2)),
                Some(&ndigs),
                Some(&dat!(3)),
                Some(4),
                Some(&wkeys),
                None,
                None,
                None,
                None,
                Some(matter::Codex::Blake3_256),
                None,
                None,
            )?;

            let mut sigers: Vec<Siger> = vec![];
            for (i, val) in current.iter().take(current.len() - 1).enumerate() {
                let siger: Siger = val.sign_indexed(&serder.raw(), false, i as u32, None)?;
                sigers.push(siger);
            }

            let inception_message = messagize(&serder, Some(&sigers), None, None, None)?;

            let ked = serder.ked();

            let receipt_serder = receipt(&ked["i"].to_string()?, 0, &serder.said()?, None, None)?;
            let mut wigers: Vec<Siger> = vec![];
            for (i, val) in witness.iter().enumerate() {
                let siger: Siger = val.sign_indexed(&serder.raw(), false, i as u32, None)?;
                wigers.push(siger);
            }

            let receipt_message = messagize(&receipt_serder, None, None, Some(&wigers), None)?;

            println!("{im}{rm}", im = inception_message, rm = receipt_message);

            Ok(Vault { current, next })
        }

        pub fn current(&self) -> Vec<Signer> {
            self.current.clone()
        }

        pub fn next(&self) -> Vec<Signer> {
            self.next.clone()
        }
    }

    fn messagize(
        serder: &Serder,
        sigers: Option<&[Siger]>,
        seal: Option<&Seal>,
        wigers: Option<&[Siger]>,
        cigars: Option<&[Cigar]>,
    ) -> Result<String> {
        let message = String::from_utf8(serder.raw())?;
        let mut atc = "".to_string();

        if sigers.is_none() && wigers.is_none() && cigars.is_none() {
            return err!(Error::Value("missing attached signatures".to_string()));
        }

        if let Some(sigers) = sigers {
            if let Some(seal) = seal {
                if seal.last {
                    atc += &Counter::new_with_code_and_count(
                        counter::Codex::TransLastIdxSigGroups,
                        1,
                    )?
                    .qb64()?;
                    atc += &seal.i();
                } else {
                    atc += &Counter::new_with_code_and_count(counter::Codex::TransIdxSigGroups, 1)?
                        .qb64()?;
                    atc += &seal.i();
                    atc += &seal.s()?;
                    atc += &seal.d();
                }
            }

            atc += &Counter::new_with_code_and_count(
                counter::Codex::ControllerIdxSigs,
                sigers.len() as u32,
            )?
            .qb64()?;
            for siger in sigers {
                atc += &(*siger).qb64()?;
            }
        }

        if let Some(wigers) = wigers {
            atc += &Counter::new_with_code_and_count(
                counter::Codex::WitnessIdxSigs,
                wigers.len() as u32,
            )?
            .qb64()?;
            for wiger in wigers {
                // todo: deny non-transferable
                atc += &(*wiger).qb64()?;
            }
        }

        // todo: complete this

        Ok(message + &atc)
    }

    fn receipt(
        pre: &str,
        sn: u128,
        said: &str,
        version: Option<&Version>,
        kind: Option<&str>,
    ) -> Result<Serder> {
        let version = version.unwrap_or(CURRENT_VERSION);
        let kind = kind.unwrap_or(Serialage::JSON);

        let vs = versify(None, Some(version), Some(kind), Some(0))?;
        let ilk = Ilkage::rct;

        let sner = Number::new_with_num(sn)?;

        let ked = dat!({
            "v": &vs,
            "t": ilk,
            "d": said,
            "i": pre,
            "s": &sner.numh()?
        });

        Serder::new_with_ked(&ked, None, None)
    }
}
