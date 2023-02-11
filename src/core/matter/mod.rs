use base64::{engine::general_purpose as b64_engine, Engine};

use crate::core::util;
use crate::error::{err, Error, Result};

pub mod tables;

pub trait Matter: Default {
    fn code(&self) -> String;
    fn size(&self) -> u32;
    fn raw(&self) -> Vec<u8>;
    fn set_code(&mut self, code: &str);
    fn set_size(&mut self, size: u32);
    fn set_raw(&mut self, raw: &[u8]);

    fn new_with_code_and_raw(code: &str, raw: &[u8]) -> Result<Self>
    where
        Self: Sized,
    {
        if code.is_empty() {
            return err!(Error::EmptyMaterial("empty code".to_string()));
        }

        let mut size: u32 = 0;
        // this unwrap can stay since we have validated that code is not empty, above
        let first = code.chars().next().unwrap();

        let mut code = code.to_string();
        let rize =
            if tables::SMALL_VRZ_DEX.contains(&first) || tables::LARGE_VRZ_DEX.contains(&first) {
                let rize = raw.len() as u32;

                let ls = (3 - (rize % 3)) % 3;
                size = (rize + ls) / 3;

                if tables::SMALL_VRZ_DEX.contains(&first) {
                    if size < 64_u32.pow(2) {
                        let hs = 2;
                        let s = tables::SMALL_VRZ_DEX[ls as usize];
                        code = format!("{s}{}", &code[1..hs as usize]);
                    } else if size < 64_u32.pow(4) {
                        let hs = 4;
                        let s = tables::LARGE_VRZ_DEX[ls as usize];

                        code = format!("{s}{}{}", &"AAAA"[0..hs as usize - 2], &code[1..2]);
                    } else {
                        return err!(Error::InvalidVarRawSize(format!(
                            "unsupported raw size: code = '{code}'",
                        )));
                    }
                } else if tables::LARGE_VRZ_DEX.contains(&first) {
                    if size < 64_u32.pow(4) {
                        let hs = 4;
                        let s = tables::LARGE_VRZ_DEX[ls as usize];
                        code = format!("{s}{}", &code[1..hs as usize]);
                    } else {
                        return err!(Error::InvalidVarRawSize(format!(
                            "unsupported raw size: code = '{code}'",
                        )));
                    }
                } else {
                    // unreachable
                    // since this if else is inside another if that protects us against this
                    return err!(Error::InvalidVarRawSize(format!(
                        "unsupported variable raw size: code = '{code}'",
                    )));
                }

                rize
            } else {
                let szg = tables::sizage(&code)?;
                if szg.fs == 0 {
                    // unreachable
                    // programmer error, variable length sizages should be the only ones with fs == 0
                    return err!(Error::InvalidVarSize(format!(
                        "unsupported variable size: code = '{code}'",
                    )));
                }
                let cs = szg.hs + szg.ss;
                ((szg.fs - cs) * 3 / 4) - szg.ls
            };

        if raw.len() < rize as usize {
            return err!(Error::Shortage(format!(
                "insufficient raw material: raw size = {}, rize = {rize}",
                raw.len()
            )));
        }

        let mut matter = Self::default();
        matter.set_code(&code);
        matter.set_size(size);
        matter.set_raw(&raw[..rize as usize]);

        Ok(matter)
    }

    fn new_with_qb64(qb64: &str) -> Result<Self>
    where
        Self: Sized,
    {
        let mut matter = Self::default();
        matter.exfil(qb64)?;
        Ok(matter)
    }

    fn new_with_qb64b(qb64b: &[u8]) -> Result<Self>
    where
        Self: Sized,
    {
        let qb64 = String::from_utf8(qb64b.to_vec())?;

        let mut matter = Self::default();
        matter.exfil(&qb64)?;
        Ok(matter)
    }

    fn new_with_qb2(qb2: &[u8]) -> Result<Self>
    where
        Self: Sized,
    {
        let mut matter = Self::default();
        matter.bexfil(qb2)?;
        Ok(matter)
    }

    fn qb64(&self) -> Result<String> {
        self.infil()
    }

    fn qb64b(&self) -> Result<Vec<u8>> {
        Ok(self.qb64()?.as_bytes().to_vec())
    }

    fn qb2(&self) -> Result<Vec<u8>> {
        self.binfil()
    }

    fn infil(&self) -> Result<String> {
        let code = &self.code();
        let size = self.size();
        let mut raw = self.raw();

        let ps = (3 - raw.len() % 3) % 3;
        let szg = tables::sizage(code)?;

        if szg.fs == 0 {
            let cs = szg.hs + szg.ss;
            if cs % 4 != 0 {
                // unreachable
                // programmer error, this can't happen if sizages are correct
                return err!(Error::InvalidCodeSize(format!(
                    "whole code size not multiple of 4 for variable length material: cs = {cs}",
                )));
            };

            if 64_u32.pow(szg.ss) - 1 < size {
                return err!(Error::InvalidVarSize(format!(
                    "invalid size for code: size = {size}, code = '{code}'",
                )));
            }

            let both = format!("{}{}", code, util::u32_to_b64(size, szg.ss as usize)?);

            // TODO: should abstract into unsigned-friendly abs
            if (ps >= szg.ls as usize && both.len() % 4 != ps - szg.ls as usize)
                || (ps < szg.ls as usize && both.len() % 4 != szg.ls as usize - ps)
            {
                return err!(Error::InvalidCodeSize(format!(
                    "invalid code for converted raw pad size: code = '{both}', pad size = {ps}",
                )));
            }

            for _ in 0..szg.ls {
                raw.insert(0, 0);
            }

            let b64 = b64_engine::URL_SAFE.encode(raw);

            Ok(format!("{both}{b64}"))
        } else {
            let both = code;
            let cs = both.len();

            if (cs % 4) as u32 != ps as u32 - szg.ls {
                return err!(Error::InvalidCodeSize(format!(
                    "invalid code for converted raw pad size: code = '{both}', pad size = {ps}",
                )));
            }

            for _ in 0..ps {
                raw.insert(0, 0);
            }

            let b64 = b64_engine::URL_SAFE.encode(raw);

            Ok(format!("{both}{}", &b64[cs % 4..]))
        }
    }

    fn binfil(&self) -> Result<Vec<u8>> {
        let code = &self.code();
        let size = self.size();
        let mut raw = self.raw();

        let mut szg = tables::sizage(code)?;
        let cs = szg.hs + szg.ss;

        let both: &str;
        let temp: String;
        if szg.fs == 0 {
            if cs % 4 != 0 {
                // unreachable
                // programmer error - sizages should not permit this
                return err!(Error::InvalidCodeSize(format!(
                    "whole code size not multiple of 4 for variable length material: cs = {cs}",
                )));
            }

            // ? check python code for a < 0 comparison
            if 64_u32.pow(szg.ss) - 1 < size {
                return err!(Error::InvalidVarSize(format!(
                    "invalid size for code: size = {size}, code = '{code}'",
                )));
            }

            temp = format!("{code}{}", util::u32_to_b64(size, szg.ss as usize)?);
            both = &temp;
            szg.fs = cs + (size * 4)
        } else {
            both = code;
        }

        if both.len() != cs as usize {
            // unreachable
            // programmer error - we compute cs from sizages and use those to create `both`
            return err!(Error::InvalidCodeSize(format!(
                "mismatched code size with table: code size = {cs}, table size = {}",
                both.len()
            )));
        }

        let n = ((cs + 1) * 3) / 4;

        // bcode
        let mut full: Vec<u8>;
        if n <= tables::SMALL_VRZ_BYTES {
            full = (util::b64_to_u32(both)? << (2 * (cs % 4))).to_be_bytes().to_vec();
        } else if n <= tables::LARGE_VRZ_BYTES {
            full = (util::b64_to_u64(both)? << (2 * (cs % 4))).to_be_bytes().to_vec();
        } else {
            // unreachable
            // programmer error - sizages will not permit cs > 8, thus:
            // (8 + 1) * 3 / 4 == 6, which is <= 6, always.
            return err!(Error::InvalidCodeSize(format!("unsupported code size: cs = {cs}",)));
        }
        // unpad code
        full.drain(0..full.len() - n as usize);
        // pad lead
        full.resize(full.len() + szg.ls as usize, 0);
        full.append(&mut raw);

        let bfs = full.len();
        if bfs % 3 != 0 || (bfs * 4 / 3) != szg.fs as usize {
            return err!(Error::InvalidCodeSize(format!(
                "invalid code for raw size: code = '{both}', raw size = {}",
                raw.len()
            )));
        }

        Ok(full)
    }

    fn exfil(&mut self, qb64: &str) -> Result<()> {
        if qb64.is_empty() {
            return err!(Error::EmptyMaterial("empty qb64".to_string()));
        }

        // we validated there will be a char here, above.
        let first = qb64.chars().next().unwrap();

        let hs = tables::hardage(first)? as usize;
        if qb64.len() < hs {
            return err!(Error::Shortage(format!(
                "insufficient material for hard part of code: qb64 size = {}, hs = {hs}",
                qb64.len(),
            )));
        }

        // bounds already checked
        let hard = &qb64[..hs];
        let mut szg = tables::sizage(hard)?;
        let cs = szg.hs + szg.ss;

        let mut size: u32 = 0;
        if szg.fs == 0 {
            if cs % 4 != 0 {
                // unreachable
                // programmer error - cs is computed from sizages, code has been validated
                return err!(Error::InvalidCodeSize(format!(
                    "code size not multiple of 4 for variable length material: cs = {cs}",
                )));
            }

            if qb64.len() < cs as usize {
                return err!(Error::Shortage(format!(
                    "insufficient material for code: qb64 size = {}, cs = {cs}",
                    qb64.len(),
                )));
            }
            let soft = &qb64[szg.hs as usize..cs as usize];
            size = util::b64_to_u32(soft)?;
            szg.fs = (size * 4) + cs;
        }

        if qb64.len() < szg.fs as usize {
            return err!(Error::Shortage(format!(
                "insufficient material: qb64 size = {}, fs = {}",
                qb64.len(),
                szg.fs
            )));
        }

        let trim = &qb64[..szg.fs as usize];
        let ps = cs % 4;
        let pbs = 2 * if ps != 0 { ps } else { szg.ls };

        let raw: Vec<u8>;
        if ps != 0 {
            let mut buf = "A".repeat(ps as usize);
            buf.push_str(&trim[(cs as usize)..]);

            // decode base to leave pre-padded raw
            let mut paw = Vec::<u8>::new();
            b64_engine::URL_SAFE.decode_vec(buf, &mut paw)?;

            let mut pi: i32 = 0;
            // readInt
            for b in &paw[..ps as usize] {
                pi = (pi * 256) + (*b as i32)
            }

            if (pi & (2_i32.pow(pbs) - 1)) != 0 {
                return err!(Error::Prepad());
            }

            raw = paw[ps as usize..].to_vec();
            paw.clear();
        } else {
            let buf = &trim[cs as usize..];
            let mut paw = Vec::<u8>::new();
            b64_engine::URL_SAFE.decode_vec(buf, &mut paw)?;

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
            raw = paw[szg.ls as usize..].to_vec();
            paw.clear();
        }

        self.set_code(hard);
        self.set_size(size);
        self.set_raw(&raw);

        Ok(())
    }

    fn bexfil(&mut self, qb2: &[u8]) -> Result<()> {
        if qb2.is_empty() {
            return err!(Error::EmptyMaterial("empty qualified base2".to_string()));
        }

        let first_byte = util::nab_sextets(qb2, 1)?[0];
        if first_byte > 0x3d {
            if first_byte == 0x3e {
                return err!(Error::UnexpectedCountCode(
                    "unexpected start during extraction".to_string(),
                ));
            } else if first_byte == 0x3f {
                return err!(Error::UnexpectedOpCode(
                    "unexpected start during extraction".to_string(),
                ));
            } else {
                // unreachable
                // we just shifted a u8 right by 2, making it max 0x3f.
                // we then validated it was > 0x3d and not 0x3f or 0x3e
                return err!(Error::UnexpectedCode(format!(
                    "unexpected code start: sextet = {first_byte}",
                )));
            }
        }

        let first = util::b64_index_to_char(first_byte)?;
        let hs = tables::hardage(first)? as usize;
        let bhs = (hs * 3 + 3) / 4;
        if qb2.len() < bhs {
            return err!(Error::Shortage(format!(
                "insufficient material for hard part of code: qb2 size = {}, bhs = {bhs}",
                qb2.len(),
            )));
        }

        let qb2_vec = qb2.to_vec();
        let hard = util::code_b2_to_b64(&qb2_vec, hs)?;
        let mut szg = tables::sizage(&hard)?;
        let cs = szg.hs + szg.ss;
        let bcs = ((cs + 1) * 3) / 4;
        let mut size: u32 = 0;
        if szg.fs == 0 {
            if cs % 4 != 0 {
                // unreachable
                // programmer error - computed from sizages
                return err!(Error::ParseQb2(format!(
                    "code size not multiple of 4 for variable length material: cs = {cs}",
                )));
            }

            if qb2.len() < bcs as usize {
                return err!(Error::Shortage(format!(
                    "insufficient material for code: qb2 size = {}, bcs = {bcs}",
                    qb2.len(),
                )));
            }

            let both = util::code_b2_to_b64(&qb2_vec, cs as usize)?;
            size = util::b64_to_u32(&both[szg.hs as usize..cs as usize])?;
            szg.fs = (size * 4) + cs
        }

        let bfs = ((szg.fs + 1) * 3) / 4;
        if qb2.len() < bfs as usize {
            return err!(Error::Shortage(format!(
                "insufficient material: qb2 size = {}, bfs = {bfs}",
                qb2.len(),
            )));
        }

        let trim = qb2[..bfs as usize].to_vec();
        let ps = cs % 4;
        let pbs = 2 * if ps != 0 { ps } else { szg.ls };
        if ps != 0 {
            let mut bytes: [u8; 1] = [0];
            bytes[0] = trim[bcs as usize - 1];
            let pi = u8::from_be_bytes(bytes);
            if pi & (2_u8.pow(pbs) - 1) != 0 {
                return err!(Error::NonZeroedPadBits());
            }
        } else {
            for value in trim.iter().take((bcs + szg.ls) as usize).skip(bcs as usize) {
                if *value != 0 {
                    match szg.ls {
                        1 => {
                            return err!(Error::NonZeroedLeadByte());
                        }
                        _ => {
                            return err!(Error::NonZeroedLeadBytes());
                        }
                    }
                }
            }
        }

        let raw = trim[(bcs + szg.ls) as usize..].to_vec();
        if raw.len() != (trim.len() - bcs as usize) - szg.ls as usize {
            // unreachable
            // rust prevents this by the definition of `raw` above. i did some algebra to clarify
            return err!(Error::Conversion(format!(
                "improperly qualified material: qb2 = {qb2:?}",
            )));
        }

        self.set_code(&hard);
        self.set_size(size);
        self.set_raw(&raw);

        Ok(())
    }
}

#[cfg(test)]
mod matter_tests {
    use crate::core::matter::{tables as matter, Matter};
    use rstest::rstest;

    struct TestMatter {
        raw: Vec<u8>,
        code: String,
        size: u32,
    }
    impl Default for TestMatter {
        fn default() -> Self {
            TestMatter { raw: vec![], code: matter::Codex::Blake3_256.code().to_string(), size: 0 }
        }
    }
    impl Matter for TestMatter {
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

    #[rstest]
    #[case(&vec![0, 1, 2, 3, 4, 5, 6, 7, 8], matter::Codex::StrB64_L0.code())]
    #[case(&vec![0, 1, 2, 3, 4, 5, 6, 7], matter::Codex::StrB64_L1.code())]
    #[case(&vec![0, 1, 2, 3, 4, 5, 6], matter::Codex::StrB64_L2.code())]
    #[case(&vec![0, 1, 2, 3, 4, 5, 6, 7, 8], matter::Codex::Bytes_L0.code())]
    #[case(&vec![0, 1, 2, 3, 4, 5, 6, 7], matter::Codex::Bytes_L1.code())]
    #[case(&vec![0, 1, 2, 3, 4, 5, 6], matter::Codex::Bytes_L2.code())]
    #[case(&vec![0, 1, 2, 3, 4, 5, 6, 7, 8], matter::Codex::StrB64_Big_L0.code())]
    #[case(&vec![0, 1, 2, 3, 4, 5, 6, 7], matter::Codex::StrB64_Big_L1.code())]
    #[case(&vec![0, 1, 2, 3, 4, 5, 6], matter::Codex::StrB64_Big_L2.code())]
    #[case(&vec![0, 1, 2, 3, 4, 5, 6, 7, 8], matter::Codex::Bytes_Big_L0.code())]
    #[case(&vec![0, 1, 2, 3, 4, 5, 6, 7], matter::Codex::Bytes_Big_L1.code())]
    #[case(&vec![0, 1, 2, 3, 4, 5, 6], matter::Codex::Bytes_Big_L2.code())]
    fn test_matter_new(#[case] raw: &Vec<u8>, #[case] code: &str) {
        let m = TestMatter::new_with_code_and_raw(code, raw).unwrap();
        let m2 = TestMatter::new_with_qb64(&m.qb64().unwrap()).unwrap();
        assert_eq!(m.code, m2.code);
        assert_eq!(m.raw, m2.raw);
        assert_eq!(m.size, m2.size);
        let m2 = TestMatter::new_with_qb2(&m.qb2().unwrap()).unwrap();
        assert_eq!(m.code, m2.code);
        assert_eq!(m.raw, m2.raw);
        assert_eq!(m.size, m2.size);
    }

    #[test]
    fn test_defaults_and_overrides() {
        // default
        let m = TestMatter::default();
        assert_eq!(m.code, matter::Codex::Blake3_256.code());

        // partial override
        let m = TestMatter { size: 3, ..Default::default() };
        assert_eq!(m.size, 3);

        // full override
        let m = TestMatter {
            raw: b"a".to_vec(),
            code: matter::Codex::X25519_Cipher_Seed.code().to_string(),
            size: 1,
        };

        assert_eq!(m.raw, b"a".to_vec());
        assert_eq!(m.code, matter::Codex::X25519_Cipher_Seed.code());
        assert_eq!(m.size, 1);
    }

    #[test]
    fn test_exfil_infil_bexfil_binfil() {
        let qb64 = "BGlOiUdp5sMmfotHfCWQKEzWR91C72AH0lT84c0um-Qj";

        // basic
        let m = TestMatter::new_with_qb64(qb64).unwrap();
        assert_eq!(m.code, matter::Codex::Ed25519N.code());

        // qb64
        let m2 = TestMatter::new_with_code_and_raw(&m.code, &m.raw).unwrap();
        assert_eq!(m.code, m2.code);
        assert_eq!(m.raw, m2.raw);
        assert_eq!(m.size, m2.size);
        assert_eq!(qb64, m2.qb64().unwrap());

        // qb64b
        let m2 = TestMatter::new_with_qb64b(&m.qb64b().unwrap()).unwrap();
        assert_eq!(m.code, m2.code);
        assert_eq!(m.raw, m2.raw);
        assert_eq!(m.size, m2.size);
        assert_eq!(qb64, m2.qb64().unwrap());

        // qb2
        let m2 = TestMatter::new_with_qb2(&m.qb2().unwrap()).unwrap();
        assert_eq!(m.code, m2.code);
        assert_eq!(m.raw, m2.raw);
        assert_eq!(m.size, m2.size);
        assert_eq!(qb64, m2.qb64().unwrap());
    }

    #[test]
    fn test_big_boundary() {
        let m =
            TestMatter::new_with_code_and_raw(matter::Codex::Bytes_L2.code(), &[0; 4095 * 3 + 1])
                .unwrap();
        assert_eq!(m.raw().len(), 4095 * 3 + 1);
        assert_eq!(m.code(), matter::Codex::Bytes_Big_L2.code());
    }

    #[test]
    fn test_unhappy_paths() {
        // empty material
        assert!(TestMatter::new_with_code_and_raw("", &[]).is_err());
        assert!(TestMatter::new_with_code_and_raw(matter::Codex::Blake3_256.code(), &[]).is_err());
        assert!(TestMatter::new_with_qb64("").is_err());
        assert!(TestMatter::new_with_qb64b(&[]).is_err());
        assert!(TestMatter::new_with_qb2(&[]).is_err());

        // invalid code
        assert!(TestMatter::new_with_code_and_raw("CESR", &[]).is_err());

        // invalid code/raw size combination
        assert!(TestMatter {
            code: matter::Codex::Blake3_256.code().to_string(),
            size: 32,
            raw: [0; 31].to_vec(),
        }
        .qb64()
        .is_err());

        // insufficient hard material
        assert!(TestMatter::new_with_qb64("0").is_err());
        assert!(TestMatter::new_with_qb2(&[52 << 2]).is_err());

        // insufficient code material
        assert!(TestMatter::new_with_qb64("4A").is_err());
        assert!(TestMatter::new_with_qb2(&[224, 0]).is_err());

        // insufficient material
        assert!(TestMatter::new_with_qb64("E").is_err());
        assert!(TestMatter::new_with_qb2(&[4 << 2]).is_err());

        // raw size too large
        assert!(TestMatter::new_with_code_and_raw(
            matter::Codex::Bytes_Big_L2.code(),
            &[0; (16777215 * 3 + 1)],
        )
        .is_err());
        assert!(TestMatter::new_with_code_and_raw(
            matter::Codex::Bytes_L2.code(),
            &[0; (16777215 * 3 + 1)],
        )
        .is_err());

        assert!(TestMatter {
            code: matter::Codex::Bytes_L2.code().to_string(),
            size: 4096,
            raw: [0; 4096].to_vec()
        }
        .qb64()
        .is_err());
        assert!(TestMatter {
            code: matter::Codex::Bytes_L2.code().to_string(),
            size: 4096,
            raw: [0; 4096].to_vec(),
        }
        .qb2()
        .is_err());
        assert!(TestMatter {
            code: matter::Codex::Bytes_L1.code().to_string(),
            size: 4095,
            raw: [0; 3].to_vec(),
        }
        .qb64()
        .is_err());
        assert!(TestMatter {
            code: matter::Codex::Bytes_L1.code().to_string(),
            size: 4095,
            raw: [0; 3].to_vec(),
        }
        .qb2()
        .is_err());

        // pre-pad error
        assert!(TestMatter::new_with_qb64("E___________________________________________").is_err());
        assert!(TestMatter::new_with_qb2(&[
            19, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        ])
        .is_err());

        // non-zeroed lead byte(s)
        assert!(TestMatter::new_with_qb64("5AAB____").is_err());
        assert!(TestMatter::new_with_qb64("6AAB____").is_err());
        assert!(TestMatter::new_with_qb2(&[228, 0, 1, 255, 255, 255]).is_err());
        assert!(TestMatter::new_with_qb2(&[232, 0, 1, 255, 255, 255]).is_err());

        // unexpected qb2 codes
        assert!(TestMatter::new_with_qb2(&[0xf8]).is_err()); // count code
        assert!(TestMatter::new_with_qb2(&[0xfc]).is_err()); // op code
    }
}
