pub(crate) mod tables;

use base64::{engine::general_purpose as b64_engine, Engine};

use crate::{
    core::indexer::tables::{BothSigCodex, CurrentSigCodex},
    error::{err, Error, Result},
};

use crate::core::util;

/// Indexer is fully qualified cryptographic material primitive base class for
/// indexed primitives. Indexed codes are a mix of indexed and variable length
/// because code table has two char codes for compact variable length.
pub trait Indexer: Default {
    /// stable (hard) part of derivation code
    fn code(&self) -> String;
    fn set_code(&mut self, code: &str);
    /// unqualified crypto material usable for crypto operations
    fn raw(&self) -> Vec<u8>;
    fn set_raw(&mut self, raw: &[u8]);
    ///  main index offset into list or length of material
    fn index(&self) -> u32;
    fn set_index(&mut self, index: u32);
    ///  other index offset into list or length of material
    fn ondex(&self) -> u32;
    fn set_ondex(&mut self, ondex: u32);

    fn new_with_code_and_raw(
        code: &str,
        raw: &[u8],
        index: u32,
        mut ondex: Option<u32>,
    ) -> Result<Self>
    where
        Self: Sized,
    {
        if code.is_empty() {
            return err!(Error::EmptyMaterial("empty code".to_string()));
        }

        let szg = tables::sizage(code)?;

        // both hard + soft code size
        let cs = szg.hs + szg.ss;
        let ms = szg.ss - szg.os;

        if index > (64_u32.pow(ms - 1)) {
            return err!(Error::InvalidVarIndex(format!(
                "Invalid index '{index}' for code '{code}'"
            )));
        }

        if let Some(o) = ondex {
            if szg.os > 0 && o > 64_u32.pow(szg.os - 1) {
                return err!(Error::InvalidVarIndex(format!(
                    "Invalid ondex '{o}' for code '{code}'"
                )));
            }
        }

        if CurrentSigCodex::has_code(code) && ondex.is_some() {
            return err!(Error::InvalidVarIndex(format!(
                "Non None ondex '{o}' for code '{code}'",
                o = ondex.unwrap()
            )));
        }

        if BothSigCodex::has_code(code) {
            if ondex.is_none() {
                // when not provided make ondex match index
                ondex = Some(index);
            }
        } else if let Some(o) = ondex {
            if o != index && szg.os == 0 {
                return err!(Error::InvalidVarIndex(format!(
                    "Non matching ondex '{o}' and index '{index}' for code = '{code}'."
                )));
            }
        }

        // compute fs from index
        let mut fs = szg.fs;
        if fs == 0 {
            if cs % 4 != 0 {
                return err!(Error::InvalidCodeSize(format!(
                    "Whole code size not multiple of 4 for variable length material. cs = '{cs}'."
                )));
            }

            if szg.os != 0 {
                return err!(Error::InvalidCodeSize(format!(
                    "Non-zero other index size for variable length material. os = '{o}'.",
                    o = szg.os
                )));
            }

            fs = (index * 4) + cs
        }

        let rize = (fs - cs) * 3 / 4;
        if raw.len() < rize as usize {
            return err!(Error::Shortage(format!(
                "insufficient raw material: raw size = '{}', rize = '{rize}'",
                raw.len()
            )));
        }

        let mut indexer = Self::default();
        indexer.set_code(code);
        indexer.set_raw(&raw[..rize as usize]);
        indexer.set_index(index);
        indexer.set_ondex(ondex.unwrap_or_default());

        Ok(indexer)
    }

    fn new_with_qb64(qb64: &str) -> Result<Self>
    where
        Self: Sized,
    {
        let mut i: Self = Self::default();
        i.exfil(qb64)?;
        Ok(i)
    }

    fn new_with_qb64b(qb64b: &[u8]) -> Result<Self>
    where
        Self: Sized,
    {
        let qb64 = String::from_utf8(qb64b.to_vec())?;

        let mut i: Self = Self::default();
        i.exfil(&qb64)?;
        Ok(i)
    }

    fn new_with_qb2(qb2: &[u8]) -> Result<Self>
    where
        Self: Sized,
    {
        let i: Self = Self::default();
        i.bexfil(qb2)?;
        Ok(i)
    }

    /// Fully Qualified Base64 Version
    /// Assumes self.raw and self.code are correctly populated
    fn qb64(&self) -> Result<String> {
        self.infil()
    }

    /// Fully Qualified Base64 Version encoded as bytes
    /// Assumes self.raw and self.code are correctly populated
    fn qb64b(&self) -> Result<Vec<u8>> {
        Ok(self.qb64()?.as_bytes().to_vec())
    }

    /// Fully Qualified Binary Version Bytes
    fn qb2(&self) -> Result<Vec<u8>> {
        self.binfil()
    }

    /// Returns fully qualified attached sig base64 bytes computed from
    /// self.raw, self.code and self.index.
    /// cs = hs + ss
    /// os = ss - ms (main index size)
    /// when fs None then size computed & fs = size * 4 + cs
    fn infil(&self) -> Result<String> {
        let code = &self.code();
        let index = self.index();
        let ondex = self.ondex();
        let mut raw = self.raw();

        let ps = (3 - (raw.len() % 3)) % 3;
        let szg = tables::sizage(code)?;
        let cs = szg.hs + szg.ss;
        let ms = szg.ss + szg.os;

        let mut fs = szg.fs;
        if szg.fs == 0 {
            if (cs % 4) != 0 {
                return err!(Error::InvalidCodeSize(format!(
                    "Whole code size not multiple of 4 for variable length material. cs = '{cs}'."
                )));
            }
            if szg.os != 0 {
                return err!(Error::InvalidCodeSize(format!(
                    "Non-zero other index size for variable length material. os = '{}'.",
                    szg.os
                )));
            }

            fs = (index * 4) + cs
        }

        if index > 64_u32.pow(ms - 1) {
            return err!(Error::InvalidVarIndex(format!(
                "Invalid index = '{index}' for code = '{code}'."
            )));
        }

        if szg.os == 1 && ondex > 64_u32.pow(szg.os - 1) {
            return err!(Error::InvalidVarIndex(format!(
                "Invalid ondex = '{ondex}' for os = '{os}' and code = '{code}'.",
                os = szg.os
            )));
        }

        // both is hard code + converted index + converted ondex
        let both = format!(
            "{code}{}{}",
            util::u32_to_b64(index, ms as usize)?,
            util::u32_to_b64(ondex, szg.os as usize)?
        );
        if both.len() != cs as usize {
            return err!(Error::InvalidCodeSize(format!(
                "Mismatch code size = {} with table = {}.",
                cs,
                both.len()
            )));
        }

        if (cs % 4) != (ps as u32 - szg.ls) {
            return err!(Error::InvalidCodeSize(format!(
                "Invalid code={both} for converted raw pad size={ps}."
            )));
        }

        for _ in 0..ps {
            raw.insert(0, 0);
        }

        let b64 = b64_engine::URL_SAFE.encode(raw);
        let full = format!("{both}{}", &b64[(ps - szg.ls as usize)..]);

        if full.len() != fs as usize {
            return err!(Error::InvalidCodeSize(format!(
                "Invalid code={both} for raw size={} {}.",
                full.len(),
                fs
            )));
        }

        Ok(full)
    }

    /// Returns bytes of fully qualified base2 bytes, that is .qb2
    /// self.code and self.index  converted to Base2 + self.raw left shifted
    /// with pad bits equivalent of Base64 decode of .qb64 into .qb2
    fn binfil(&self) -> Result<Vec<u8>> {
        let code = &self.code();
        let index = self.index();
        let ondex = self.ondex();
        let mut raw = self.raw();

        let ps = (3 - (raw.len() % 3)) % 3;
        let szg = tables::sizage(code)?;
        let cs = szg.hs + szg.ss;
        let ms = szg.ss - szg.os;

        if index > 64_u32.pow(szg.ss - 1) {
            return err!(Error::InvalidVarIndex(format!(
                "Invalid index = '{index}' for code = '{code}'."
            )));
        }

        if szg.os == 1 && ondex > 64_u32.pow(szg.os - 1) {
            return err!(Error::InvalidVarIndex(format!(
                "Invalid ondex = '{ondex}' for os = '{}' and code = '{code}'.",
                szg.os
            )));
        }

        let mut fs = szg.fs;
        if fs == 0 {
            if (cs % 4) == 1 {
                return err!(Error::InvalidCodeSize(format!(
                    "Whole code size not multiple of 4 for variable length material. cs = '{cs}'."
                )));
            }

            if szg.os != 0 {
                return err!(Error::InvalidCodeSize(format!(
                    "Non-zero other index size for variable length material. os = '{}'.",
                    szg.os
                )));
            }

            fs = (index * 4) + cs;
        }

        // both is hard code + converted index
        let both = format!(
            "{code}{}{}",
            util::u32_to_b64(index, ms as usize)?,
            util::u32_to_b64(ondex, szg.os as usize)?
        );

        if both.len() != cs as usize {
            return err!(Error::InvalidCodeSize(format!(
                "Mismatch code size = '{cs}' with table = '{}'.",
                both.len()
            )));
        }

        if (cs % 4) != (ps as u32 - szg.ls) {
            return err!(Error::InvalidCodeSize(format!(
                "Invalid code = '{both}' for converted raw pad size = '{ps}'.",
            )));
        }

        // 3870
        let n = ((cs + 1) * 3) / 4;
        let mut full: Vec<u8>;
        if n <= tables::SMALL_VRZ_BYTES {
            full = (util::b64_to_u32(&both)? << (2 * (cs % 4))).to_be_bytes().to_vec();
        } else if n <= tables::LARGE_VRZ_BYTES {
            full = (util::b64_to_u64(&both)? << (2 * (cs % 4))).to_be_bytes().to_vec();
        } else {
            // unreachable
            // programmer error - sizages will not permit cs > 8, thus:
            // (8 + 1) * 3 / 4 == 6, which is <= 6, always.
            return err!(Error::InvalidCodeSize(format!("Unsupported code size: cs = '{cs}'",)));
        }
        // unpad code
        full.drain(0..full.len() - n as usize);
        // pad lead
        full.resize(full.len() + szg.ls as usize, 0);
        full.append(&mut raw);

        let bfs = full.len();
        if bfs % 3 != 0 || (bfs * 4 / 3) != fs as usize {
            return err!(Error::InvalidCodeSize(format!(
                "Invalid code for raw size: code = '{both}', raw size = '{}'",
                raw.len()
            )));
        }

        Ok(full)
    }

    /// Extracts self.code, self.index, and self.raw from qualified base64 bytes qb64b
    /// cs = hs + ss
    /// ms = ss - os (main index size)
    /// when fs None then size computed & fs = size * 4 + cs
    fn exfil(&mut self, qb64: &str) -> Result<()> {
        if qb64.is_empty() {
            return err!(Error::EmptyMaterial("empty qb64".to_string()));
        }

        let first = qb64.chars().next().unwrap();
        let hs = tables::hardage(first)? as usize;
        if qb64.len() < hs {
            return err!(Error::Shortage(format!(
                "Need '{s}' more characters.",
                s = (hs - qb64.len())
            )));
        }

        let hard = &qb64[..hs];
        let szg = tables::sizage(hard)?;

        // both hard + soft code size
        let cs = szg.hs + szg.ss;
        let ms = szg.ss - szg.os;

        if qb64.len() < cs as usize {
            return err!(Error::Shortage(format!(
                "Need '{l}' more characters",
                l = ((cs as usize) - qb64.len()),
            )));
        }

        let index = util::b64_to_u32(&qb64[hs..(hs + ms as usize)])?;
        let odx = &qb64[(hs + ms as usize)..(hs + (ms + szg.os) as usize)];

        let mut ondex: Option<u32> = None;
        if CurrentSigCodex::has_code(hard) {
            if szg.os != 0 {
                ondex = Some(util::b64_to_u32(odx)?);
            }
            // not zero or None
            if ondex.is_some() && ondex.unwrap() != 0 {
                return err!(Error::Value(format!(
                    "Invalid ondex = '{o}' for code = '{hard}'.",
                    o = ondex.unwrap()
                )));
            }
        } else if szg.os != 0 {
            ondex = Some(util::b64_to_u32(odx)?);
        } else {
            ondex = Some(index);
        }

        // index is index for some codes and variable length for others
        let mut fs = szg.fs;
        if fs == 0 {
            if (cs % 4) != 0 {
                return err!(Error::Validation(format!(
                    "Whole code size not multiple of 4 for variable length material. cs = '{cs}'"
                )));
            }

            if szg.os != 0 {
                return err!(Error::Validation(format!(
                    "Non-zero other index size for variable length material. os = '{o}'",
                    o = szg.os
                )));
            }

            fs = (index * 4) + cs;
        }

        if qb64.len() < (fs as usize) {
            return err!(Error::Shortage(format!(
                "Need '{m}' more chars.",
                m = { fs as usize - qb64.len() }
            )));
        }

        let qb64_ = &qb64[..fs as usize];
        let ps = cs % 4;
        let pbs = 2 * if ps != 0 { ps } else { szg.ls };

        let raw: Vec<u8>;
        if ps != 0 {
            let mut buf = "A".repeat(ps as usize);
            buf.push_str(&qb64_[(cs as usize)..]);

            let mut paw = Vec::<u8>::new();
            base64::engine::general_purpose::URL_SAFE.decode_vec(buf, &mut paw)?;

            let mut pi: i32 = 0;
            for b in &paw[..ps as usize] {
                pi = (pi * 256) + (*b as i32)
            }

            if (pi & (2_i32.pow(pbs) - 1)) != 0 {
                return err!(Error::Prepad());
            }

            raw = paw[ps as usize..].to_owned();
            paw.clear();
        } else {
            let buf = &qb64_[cs as usize..];
            let mut paw = Vec::<u8>::new();
            base64::engine::general_purpose::URL_SAFE.decode_vec(buf, &mut paw)?;

            let mut li: u32 = 0;
            for b in &paw[..szg.ls as usize] {
                li = (li * 256) + (*b as u32);
            }

            if li != 0 {
                return if szg.ls == 1 {
                    err!(Error::NonZeroedLeadByte())
                } else {
                    err!(Error::NonZeroedLeadBytes())
                };
            }

            raw = paw[ps as usize..].to_owned();
            paw.clear();
        }

        self.set_code(hard);
        self.set_raw(&raw);
        self.set_index(index);
        self.set_ondex(ondex.unwrap_or_default());

        Ok(())
    }

    /// Extracts self.code, self.index, and self.raw from qualified base2 bytes qb2
    /// cs = hs + ss
    /// ms = ss - os (main index size)
    /// when fs None then size computed & fs = size * 4 + cs
    fn bexfil(&self, _qb2: &[u8]) -> Result<()> {
        // if qb2.is_empty() {
        //     return err!(Error::EmptyMaterial(format!("empty qualified base2")));
        // }

        // let first_byte = util::nab_sextets(qb2, 1)?[0];
        // if first_byte > 0x3d {
        //     if first_byte == 0x3e {
        //         return err!(Error::UnexpectedCountCode(
        //             "unexpected start during extraction".to_string(),
        //         ));
        //     } else if first_byte == 0x3f {
        //         return err!(Error::UnexpectedOpCode(
        //             "unexpected start during extraction".to_string(),
        //         ));
        //     } else {
        //         // unreachable
        //         // we just shifted a u8 right by 2, making it max 0x3f.
        //         // we then validated it was > 0x3d and not 0x3f or 0x3e
        //         return err!(Error::UnexpectedCode(format!(
        //             "unexpected code start: sextet = {first_byte}",
        //         )));
        //     }
        // }
        todo!()
    }
}

#[cfg(test)]
mod indexer_tests {
    use base64::{engine::general_purpose as b64_engine, Engine};

    use crate::core::{
        indexer::{tables::Codex, Indexer},
        util,
    };

    use super::tables;

    struct TestIndexer {
        raw: Vec<u8>,
        code: String,
        index: u32,
        ondex: u32,
    }

    impl Default for TestIndexer {
        fn default() -> Self {
            TestIndexer {
                raw: vec![],
                code: tables::Codex::Ed25519.code().to_string(),
                index: 0,
                ondex: 0,
            }
        }
    }
    impl Indexer for TestIndexer {
        fn code(&self) -> String {
            self.code.clone()
        }

        fn set_code(&mut self, code: &str) {
            self.code = code.to_string();
        }

        fn raw(&self) -> Vec<u8> {
            self.raw.clone()
        }

        fn set_raw(&mut self, raw: &[u8]) {
            self.raw = raw.to_vec();
        }

        fn index(&self) -> u32 {
            self.index
        }

        fn set_index(&mut self, index: u32) {
            self.index = index;
        }

        fn ondex(&self) -> u32 {
            self.ondex
        }

        fn set_ondex(&mut self, ondex: u32) {
            self.ondex = ondex;
        }
    }

    #[test]
    fn test_indexer() {
        let sig =  b"\x99\xd2<9$$0\x9fk\xfb\x18\xa0\x8c@r\x122.k\xb2\xc7\x1fp\x0e'm\x8f@\xaa\xa5\x8c\xc8n\x85\xc8!\xf6q\x91p\xa9\xec\xcf\x92\xaf)\xde\xca\xfc\x7f~\xd7o|\x17\x82\x1d\xd4<o\"\x81&\t";
        assert_eq!(sig.len(), 64);

        let ps = (3 - (sig.len() % 3)) % 3;

        let mut raw = sig.to_vec();
        for _ in 0..ps {
            raw.insert(0, 0);
        }

        let sig64 = b64_engine::URL_SAFE.encode(raw);
        assert_eq!(sig64, "AACZ0jw5JCQwn2v7GKCMQHISMi5rsscfcA4nbY9AqqWMyG6FyCH2cZFwqezPkq8p3sr8f37Xb3wXgh3UPG8igSYJ");
        assert_eq!(sig64.len(), 88);

        let code = Codex::Ed25519.code();
        let qsc = format!("{code}{}", util::u32_to_b64(0, 1).unwrap());
        assert_eq!(qsc, "AA");

        let qsig64 = qsc + &sig64[(ps as usize)..];
        assert_eq!(qsig64, "AACZ0jw5JCQwn2v7GKCMQHISMi5rsscfcA4nbY9AqqWMyG6FyCH2cZFwqezPkq8p3sr8f37Xb3wXgh3UPG8igSYJ");
        assert_eq!(qsig64.len(), 88);

        let qsig2b = b64_engine::URL_SAFE.decode(qsig64).unwrap();
        assert_eq!(qsig2b, b"\x00\x00\x99\xd2<9$$0\x9fk\xfb\x18\xa0\x8c@r\x122.k\xb2\xc7\x1fp\x0e'm\x8f@\xaa\xa5\x8c\xc8n\x85\xc8!\xf6q\x91p\xa9\xec\xcf\x92\xaf)\xde\xca\xfc\x7f~\xd7o|\x17\x82\x1d\xd4<o\"\x81&\t");
        assert_eq!(qsig2b.len(), 66);

        let mut idx =
            TestIndexer::new_with_code_and_raw(Codex::Ed25519.code(), sig, 0, None).unwrap();
        assert_eq!(idx.code, Codex::Ed25519.code());
        assert_eq!(idx.code(), Codex::Ed25519.code());
        assert_eq!(idx.raw, sig);
        assert_eq!(idx.raw(), sig);
        assert_eq!(idx.index, 0);
        assert_eq!(idx.ondex, 0);
        assert_eq!(idx.qb64().unwrap(), sig64);
        assert_eq!(idx.qb64b().unwrap(), sig64.as_bytes());
        assert_eq!(idx.qb2().unwrap(), qsig2b);

        idx = TestIndexer::new_with_qb64("AACZ0jw5JCQwn2v7GKCMQHISMi5rsscfcA4nbY9AqqWMyG6FyCH2cZFwqezPkq8p3sr8f37Xb3wXgh3UPG8igSYJ").unwrap();
        assert_eq!(idx.raw, sig);
        assert_eq!(idx.raw(), sig);
        assert_eq!(idx.code, Codex::Ed25519.code());
        assert_eq!(idx.code(), Codex::Ed25519.code());
        assert_eq!(idx.index, 0);
        assert_eq!(idx.ondex, 0);
        assert_eq!(idx.qb64().unwrap(), sig64);
        assert_eq!(idx.qb64b().unwrap(), sig64.as_bytes());
        assert_eq!(idx.qb2().unwrap(), qsig2b);

        idx = TestIndexer::new_with_qb64b("AACZ0jw5JCQwn2v7GKCMQHISMi5rsscfcA4nbY9AqqWMyG6FyCH2cZFwqezPkq8p3sr8f37Xb3wXgh3UPG8igSYJ".as_bytes()).unwrap();
        assert_eq!(idx.raw, sig);
        assert_eq!(idx.raw(), sig);
        assert_eq!(idx.code, Codex::Ed25519.code());
        assert_eq!(idx.code(), Codex::Ed25519.code());
        assert_eq!(idx.index, 0);
        assert_eq!(idx.ondex, 0);
        assert_eq!(idx.qb64().unwrap(), sig64);
        assert_eq!(idx.qb64b().unwrap(), sig64.as_bytes());
        assert_eq!(idx.qb2().unwrap(), qsig2b);

        // idx = Indexer::new_with_qb2(&qsig2b).unwrap();
        // assert_eq!(idx.raw, sig);
        // assert_eq!(idx.code, Codex::Ed25519.code());
        // assert_eq!(idx.index, 0);
        // assert_eq!(idx.ondex, Some(0));
        // assert_eq!(idx.qb64().unwrap(), sig64);
        // assert_eq!(idx.qb64b().unwrap(), sig64.as_bytes());
        // assert_eq!(idx.qb2().unwrap(), qsig2b);
    }

    #[test]
    fn test_unhappy_paths() {
        assert!(TestIndexer::new_with_code_and_raw("", &[], 0, None).is_err());
        assert!(TestIndexer::new_with_code_and_raw(Codex::Ed25519.code(), &[], 0, None).is_err());
        assert!(TestIndexer::new_with_qb64("").is_err());
        assert!(TestIndexer::new_with_qb64b(&[]).is_err());
        // assert!(Indexer::new_with_qb2(&[]).is_err());

        // unknown sizage
        assert!(TestIndexer::new_with_code_and_raw("CESR", &[], 0, None).is_err());

        // shortage
        assert!(TestIndexer::new_with_qb64("0").is_err());
    }
}
