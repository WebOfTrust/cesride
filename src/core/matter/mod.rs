pub(crate) mod tables;

use base64::Engine;

use crate::core::util;
use crate::error::{Error, Result};

#[derive(Debug)]
pub struct Matter {
    pub(crate) raw: Vec<u8>,
    pub(crate) code: String,
    pub(crate) size: u32,
}

impl Matter {
    pub fn new_with_code_and_raw(code: &str, raw: &[u8], raw_size: usize) -> Result<Matter> {
        if code.is_empty() {
            return Err(Box::new(Error::EmptyMaterial("empty code".to_string())));
        }

        let mut size: u32 = 0;
        // this unwrap can stay since we have validated that code is not empty, above
        let first = code.chars().next().unwrap();

        const SMALL_VRZ_DEX: [char; 3] = ['4', '5', '6'];
        const LARGE_VRZ_DEX: [char; 3] = ['7', '8', '9'];

        let mut code = code.to_string();
        let rize = if SMALL_VRZ_DEX.contains(&first) || LARGE_VRZ_DEX.contains(&first) {
            let rize = if raw_size == 0 {
                raw.len() as u32
            } else {
                raw_size as u32
            };

            let ls = (3 - (rize % 3)) % 3;
            size = (rize + ls) / 3;

            const SIXTY_FOUR: u32 = 64;
            if SMALL_VRZ_DEX.contains(&first) {
                if size < SIXTY_FOUR.pow(2) {
                    let hs = 2;
                    let s = SMALL_VRZ_DEX[ls as usize];
                    code = format!("{}{}", s, &code[1..hs as usize]);
                } else if size < SIXTY_FOUR.pow(4) {
                    let hs = 4;
                    let s = LARGE_VRZ_DEX[ls as usize];

                    code = format!("{}{}{}", s, &"AAAA"[0..hs as usize - 2], &code[1..2]);
                } else {
                    return Err(Box::new(Error::InvalidVarRawSize(format!(
                        "unsupported raw size: code = [{}]",
                        code
                    ))));
                }
            } else if LARGE_VRZ_DEX.contains(&first) {
                if size < SIXTY_FOUR.pow(4) {
                    let hs = 4;
                    let s = LARGE_VRZ_DEX[ls as usize];
                    code = format!("{}{}", s, &code[1..hs as usize]);
                } else {
                    return Err(Box::new(Error::InvalidVarRawSize(format!(
                        "unsupported raw size: code = [{}]",
                        code
                    ))));
                }
            } else {
                return Err(Box::new(Error::InvalidVarRawSize(format!(
                    "unsupported variable raw size: code = [{}]",
                    code
                ))));
            }

            rize
        } else {
            let sizage_ = tables::sizage(&code)?;
            if sizage_.fs == 0 {
                return Err(Box::new(Error::InvalidVarRawSize(format!(
                    "unsupported variable size: code = [{}]",
                    code
                ))));
            }
            let cs = sizage_.hs + sizage_.ss;
            ((sizage_.fs - cs) * 3 / 4) - sizage_.ls
        };

        Ok(Matter {
            code,
            size,
            raw: raw[..rize as usize].to_owned(),
        })
    }

    pub fn new_with_qb64(qb64: &str) -> Result<Matter> {
        let mut m: Matter = Default::default();
        m.exfil(qb64)?;
        Ok(m)
    }

    pub fn new_with_qb64b(qb64b: &[u8]) -> Result<Matter> {
        let qb64 = String::from_utf8(qb64b.to_vec())?;

        let mut m: Matter = Default::default();
        m.exfil(&qb64)?;
        Ok(m)
    }

    pub fn new_with_qb2(qb2: &[u8]) -> Result<Matter> {
        let mut m: Matter = Default::default();
        m.bexfil(qb2)?;
        Ok(m)
    }

    pub fn code(&self) -> String {
        self.code.to_string()
    }

    pub fn size(&self) -> u32 {
        self.size
    }

    pub fn raw(&self) -> Vec<u8> {
        self.raw.to_vec()
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

    pub fn transferable() {}

    fn infil(&self) -> Result<String> {
        let code = &self.code;
        let size = self.size;
        let mut raw = self.raw.to_vec();

        let ps = (3 - raw.len() % 3) % 3;
        let sizage_ = tables::sizage(code)?;

        if sizage_.fs == 0 {
            let cs = sizage_.hs + sizage_.ss;
            if cs % 4 != 0 {
                return Err(Box::new(Error::InvalidCodeSize(format!(
                    "whole code size not multiple of 4 for variable length material: cs = [{}]",
                    cs
                ))));
            };

            const SIXTY_FOUR: u32 = 64;
            if SIXTY_FOUR.pow(sizage_.ss) - 1 < size {
                return Err(Box::new(Error::InvalidVarSize(format!(
                    "invalid size for code: size = [{}], code = [{}]",
                    size, code
                ))));
            }

            let both = format!("{}{}", code, util::u32_to_b64(size, sizage_.ss as usize));

            if both.len() % 4 != ps - sizage_.ls as usize {
                return Err(Box::new(Error::InvalidCodeSize(format!(
                    "invalid code for converted raw pad size: code = [{}], pad size = [{}]",
                    both, ps
                ))));
            }

            for _ in 0..sizage_.ls {
                raw.insert(0, 0);
            }

            let b64 = base64::engine::general_purpose::URL_SAFE.encode(raw);

            Ok(format!("{}{}", both, b64))
        } else {
            let both = code;
            let cs = both.len();

            if (cs % 4) as u32 != ps as u32 - sizage_.ls {
                return Err(Box::new(Error::InvalidCodeSize(format!(
                    "invalid code for converted raw pad size: code = [{}], pad size = [{}]",
                    both, ps
                ))));
            }

            for _ in 0..ps {
                raw.insert(0, 0);
            }

            let b64 = base64::engine::general_purpose::URL_SAFE.encode(raw);

            Ok(format!("{}{}", both, &b64[cs % 4..]))
        }
    }

    fn binfil(&self) -> Result<Vec<u8>> {
        let code = &self.code;
        let size = self.size;
        let mut raw = self.raw.to_vec();

        let mut sizage_ = tables::sizage(code)?;
        let cs = sizage_.hs + sizage_.ss;

        let both: &str;
        let temp: String;
        if sizage_.fs == 0 {
            if cs % 4 != 0 {
                return Err(Box::new(Error::InvalidCodeSize(format!(
                    "whole code size not multiple of 4 for variable length material: cs = [{}]",
                    cs
                ))));
            }

            // ? check python code for a < 0 comparison
            const SIXTY_FOUR: u32 = 64;
            if SIXTY_FOUR.pow(sizage_.ss) - 1 < size {
                return Err(Box::new(Error::InvalidVarSize(format!(
                    "invalid size for code: size = [{}], code = [{}]",
                    size, code
                ))));
            }

            temp = format!("{}{}", code, util::u32_to_b64(size, sizage_.ss as usize));
            both = &temp;
            sizage_.fs = cs + (size * 4)
        } else {
            both = code;
        }

        if both.len() != cs as usize {
            return Err(Box::new(Error::InvalidCodeSize(format!(
                "mismatched code size with table: code size = [{}], table size = [{}]",
                cs,
                both.len()
            ))));
        }

        let n = ((cs + 1) * 3) / 4;

        const SMALL_VRZ_BYTES: u32 = 3;
        const LARGE_VRZ_BYTES: u32 = 6;

        // bcode
        let mut full: Vec<u8>;
        if n <= SMALL_VRZ_BYTES {
            full = (util::b64_to_u32(both) << (2 * (cs % 4)))
                .to_be_bytes()
                .to_vec();
        } else if n <= LARGE_VRZ_BYTES {
            full = (util::b64_to_u64(both) << (2 * (cs % 4)))
                .to_be_bytes()
                .to_vec();
        } else {
            return Err(Box::new(Error::InvalidCodeSize(format!(
                "unsupported code size: cs = [{}]",
                cs
            ))));
        }
        // unpad code
        full.drain(0..full.len() - n as usize);
        // pad lead
        full.resize(full.len() + sizage_.ls as usize, 0);
        full.append(&mut raw);

        let bfs = full.len();
        if bfs % 3 != 0 || (bfs * 4 / 3) != sizage_.fs as usize {
            return Err(Box::new(Error::InvalidCodeSize(format!(
                "invalid code for raw size: code = [{}], raw size = [{}]",
                both,
                raw.len()
            ))));
        }

        Ok(full)
    }

    fn exfil(&mut self, qb64: &str) -> Result<()> {
        if qb64.is_empty() {
            return Err(Box::new(Error::EmptyMaterial("empty qb64".to_string())));
        }

        // we validated there will be a char here, above.
        let first = qb64.chars().next().unwrap();

        let hs = tables::hardage(first)? as usize;
        if qb64.len() < hs {
            return Err(Box::new(Error::Shortage(format!(
                "insufficient material for hard part of code: qb64 size = [{}], hs = [{}]",
                qb64.len(),
                hs
            ))));
        }

        // bounds already checked
        let hard = &qb64[..hs];
        let mut sizage_ = tables::sizage(hard)?;
        let cs = sizage_.hs + sizage_.ss;

        let mut size: u32 = 0;
        if sizage_.fs == 0 {
            if cs % 4 != 0 {
                return Err(Box::new(Error::InvalidCodeSize(format!(
                    "code size not multiple of 4 for variable length material: cs = [{}]",
                    cs
                ))));
            }

            if qb64.len() < cs as usize {
                return Err(Box::new(Error::Shortage(format!(
                    "insufficient material for code: qb64 size = [{}], cs = [{}]",
                    qb64.len(),
                    cs
                ))));
            }
            let soft = &qb64[sizage_.hs as usize..cs as usize];
            size = util::b64_to_u32(soft);
            sizage_.fs = (size * 4) + cs;
        }

        if qb64.len() < sizage_.fs as usize {
            return Err(Box::new(Error::Shortage(format!(
                "insufficient material: qb64 size = [{}], fs = [{}]",
                qb64.len(),
                sizage_.fs
            ))));
        }

        let trim = &qb64[..sizage_.fs as usize];
        let ps = cs % 4;
        let pbs = 2 * if ps != 0 { ps } else { sizage_.ls };

        let raw: Vec<u8>;
        if ps != 0 {
            let mut buf = "A".repeat(ps as usize);
            buf.push_str(&trim[(cs as usize)..]);

            // decode base to leave pre-padded raw
            let mut paw = Vec::<u8>::new();
            base64::engine::general_purpose::URL_SAFE.decode_vec(buf, &mut paw)?;

            let mut pi: i32 = 0;
            // readInt
            for b in &paw[..ps as usize] {
                pi = (pi * 256) + (*b as i32)
            }

            const TWO: i32 = 2;
            if (pi & (TWO.pow(pbs) - 1)) != 0 {
                return Err(Box::new(Error::Prepad()));
            }

            raw = paw[ps as usize..].to_owned();
            paw.clear();
        } else {
            let buf = &trim[cs as usize..];
            let mut paw = Vec::<u8>::new();
            base64::engine::general_purpose::URL_SAFE.decode_vec(buf, &mut paw)?;

            let mut li: u32 = 0;
            for b in &paw[..sizage_.ls as usize] {
                li = (li * 256) + (*b as u32);
            }

            if li != 0 {
                return if sizage_.ls == 1 {
                    Err(Box::new(Error::NonZeroedLeadByte()))
                } else {
                    Err(Box::new(Error::NonZeroedLeadBytes()))
                };
            }
            raw = paw[sizage_.ls as usize..].to_owned();
            paw.clear();
        }

        self.code = hard.to_string();
        self.size = size;
        self.raw = raw;

        Ok(())
    }

    fn bexfil(&mut self, qb2: &[u8]) -> Result<()> {
        if qb2.is_empty() {
            return Err(Box::new(Error::EmptyMaterial(
                "empty qualified base2".to_string(),
            )));
        }

        let first_byte = (qb2[0] & 0xfc) >> 2;
        if first_byte > 0x3d {
            if first_byte == 0x3e {
                return Err(Box::new(Error::UnexpectedCountCode(
                    "unexpected start during extraction".to_string(),
                )));
            } else if first_byte == 0x3f {
                return Err(Box::new(Error::UnexpectedOpCode(
                    "unexpected start during extraction".to_string(),
                )));
            } else {
                return Err(Box::new(Error::UnexpectedCode(format!(
                    "unexpected code start: sextet = [{}]",
                    first_byte
                ))));
            }
        }

        let first = util::b64_index_to_char(first_byte);
        let hs = tables::hardage(first)? as usize;
        let bhs = (hs * 3 + 3) / 4;
        if qb2.len() < bhs {
            return Err(Box::new(Error::Shortage(format!(
                "insufficient material for hard part of code: qb2 size = [{}], bhs = [{}]",
                qb2.len(),
                bhs
            ))));
        }

        let qb2_vec = qb2.to_vec();
        let hard = util::code_b2_to_b64(&qb2_vec, hs)?;
        let mut sizage_ = tables::sizage(&hard)?;
        let cs = sizage_.hs + sizage_.ss;
        let bcs = ((cs + 1) * 3) / 4;
        let mut size: u32 = 0;
        if sizage_.fs == 0 {
            if cs % 4 != 0 {
                return Err(Box::new(Error::ParseQb2(format!(
                    "code size not multiple of 4 for variable length material: cs = [{}]",
                    cs
                ))));
            }

            if qb2.len() < bcs as usize {
                return Err(Box::new(Error::Shortage(format!(
                    "insufficient material for code: qb2 size = [{}], bcs = [{}]",
                    qb2.len(),
                    bcs
                ))));
            }

            let both = util::code_b2_to_b64(&qb2_vec, cs as usize)?;
            size = util::b64_to_u32(&both[sizage_.hs as usize..cs as usize]);
            sizage_.fs = (size * 4) + cs
        }

        let bfs = ((sizage_.fs + 1) * 3) / 4;
        if qb2.len() < bfs as usize {
            return Err(Box::new(Error::Shortage(format!(
                "insufficient material: qb2 size = [{}], bfs = [{}]",
                qb2.len(),
                bfs
            ))));
        }

        let trim = qb2[..bfs as usize].to_vec();
        let ps = cs % 4;
        let pbs = 2 * if ps != 0 { ps } else { sizage_.ls };
        if ps != 0 {
            let mut bytes: [u8; 1] = [0];
            bytes[0] = trim[bcs as usize - 1];
            let pi = u8::from_be_bytes(bytes);
            const TWO: u8 = 2;
            if pi & (TWO.pow(pbs) - 1) != 0 {
                return Err(Box::new(Error::NonZeroedPadBits()));
            }
        } else {
            for value in trim
                .iter()
                .take((bcs + sizage_.ls) as usize)
                .skip(bcs as usize)
            {
                if *value != 0 {
                    match sizage_.ls {
                        1 => {
                            return Err(Box::new(Error::NonZeroedLeadByte()));
                        }
                        _ => {
                            return Err(Box::new(Error::NonZeroedLeadBytes()));
                        }
                    }
                }
            }
        }

        let raw = trim[(bcs + sizage_.ls) as usize..].to_vec();
        if raw.len() != (trim.len() - bcs as usize) - sizage_.ls as usize {
            return Err(Box::new(Error::Conversion(format!(
                "improperly qualified material: qb2 = {:?}",
                qb2
            ))));
        }

        self.code = hard;
        self.size = size;
        self.raw = raw;

        Ok(())
    }
}

impl Default for Matter {
    fn default() -> Self {
        Matter {
            raw: vec![],
            code: tables::Codex::Blake3_256.code().to_string(),
            size: 0,
        }
    }
}

#[cfg(test)]
mod matter_tests {
    use crate::core::matter::{tables as matter, Matter};

    #[test]
    fn test_matter_new() {
        let qb64 = "BGlOiUdp5sMmfotHfCWQKEzWR91C72AH0lT84c0um-Qj";

        // basic
        let mut m = Matter::new_with_qb64(qb64).unwrap();
        assert_eq!(m.code, matter::Codex::Ed25519N.code());

        // qb64
        let mut m2 = Matter::new_with_code_and_raw(&m.code, &m.raw, m.raw.len()).unwrap();
        assert_eq!(m.code, m2.code);
        assert_eq!(m.raw, m2.raw);
        assert_eq!(m.size, m2.size);
        assert_eq!(qb64, m2.qb64().unwrap());

        // qb64b
        m2 = Matter::new_with_qb64b(&m.qb64b().unwrap()).unwrap();
        assert_eq!(m.code, m2.code);
        assert_eq!(m.raw, m2.raw);
        assert_eq!(m.size, m2.size);
        assert_eq!(qb64, m2.qb64().unwrap());

        // qb2
        m2 = Matter::new_with_qb2(&m.qb2().unwrap()).unwrap();
        assert_eq!(m.code, m2.code);
        assert_eq!(m.raw, m2.raw);
        assert_eq!(m.size, m2.size);
        assert_eq!(qb64, m2.qb64().unwrap());

        // small variable b64(), ls = 0
        let raw: Vec<u8> = vec![0, 1, 2, 3, 4, 5, 6, 7, 8];
        m = Matter::new_with_code_and_raw(matter::Codex::StrB64_L0.code(), &raw, 9).unwrap();
        m2 = Matter::new_with_qb64(&m.qb64().unwrap()).unwrap();
        assert_eq!(m.code, m2.code);
        assert_eq!(m.raw, m2.raw);
        assert_eq!(m.size, m2.size);
        m2 = Matter::new_with_qb2(&m.qb2().unwrap()).unwrap();
        assert_eq!(m.code, m2.code);
        assert_eq!(m.raw, m2.raw);
        assert_eq!(m.size, m2.size);

        // small variable b64(), ls = 1
        let raw: Vec<u8> = vec![0, 1, 2, 3, 4, 5, 6, 7];
        m = Matter::new_with_code_and_raw(matter::Codex::StrB64_L1.code(), &raw, 8).unwrap();
        m2 = Matter::new_with_qb64(&m.qb64().unwrap()).unwrap();
        assert_eq!(m.code, m2.code);
        assert_eq!(m.raw, m2.raw);
        assert_eq!(m.size, m2.size);
        m2 = Matter::new_with_qb2(&m.qb2().unwrap()).unwrap();
        assert_eq!(m.code, m2.code);
        assert_eq!(m.raw, m2.raw);
        assert_eq!(m.size, m2.size);

        // small variable b64(), ls = 2
        let raw: Vec<u8> = vec![0, 1, 2, 3, 4, 5, 6];
        m = Matter::new_with_code_and_raw(matter::Codex::StrB64_L2.code(), &raw, 7).unwrap();
        m2 = Matter::new_with_qb64(&m.qb64().unwrap()).unwrap();
        assert_eq!(m.code, m2.code);
        assert_eq!(m.raw, m2.raw);
        assert_eq!(m.size, m2.size);
        m2 = Matter::new_with_qb2(&m.qb2().unwrap()).unwrap();
        assert_eq!(m.code, m2.code);
        assert_eq!(m.raw, m2.raw);
        assert_eq!(m.size, m2.size);

        // small variable bytes is essentially the same as the above

        // large variable b64 is essentially the same as below

        // large variable bytes, ls = 0
        let raw: Vec<u8> = vec![0, 1, 2, 3, 4, 5, 6, 7, 8];
        m = Matter::new_with_code_and_raw(matter::Codex::Bytes_Big_L0.code(), &raw, 9).unwrap();
        m2 = Matter::new_with_qb64(&m.qb64().unwrap()).unwrap();
        assert_eq!(m.code, m2.code);
        assert_eq!(m.raw, m2.raw);
        assert_eq!(m.size, m2.size);
        m2 = Matter::new_with_qb2(&m.qb2().unwrap()).unwrap();
        assert_eq!(m.code, m2.code);
        assert_eq!(m.raw, m2.raw);
        assert_eq!(m.size, m2.size);

        // large variable bytes, ls = 1
        let raw: Vec<u8> = vec![0, 1, 2, 3, 4, 5, 6, 7];
        m = Matter::new_with_code_and_raw(matter::Codex::Bytes_Big_L1.code(), &raw, 8).unwrap();
        m2 = Matter::new_with_qb64(&m.qb64().unwrap()).unwrap();
        assert_eq!(m.code, m2.code);
        assert_eq!(m.raw, m2.raw);
        assert_eq!(m.size, m2.size);
        m2 = Matter::new_with_qb2(&m.qb2().unwrap()).unwrap();
        assert_eq!(m.code, m2.code);
        assert_eq!(m.raw, m2.raw);
        assert_eq!(m.size, m2.size);

        // large variable bytes, ls = 0
        let raw: Vec<u8> = vec![0, 1, 2, 3, 4, 5, 6];
        m = Matter::new_with_code_and_raw(matter::Codex::Bytes_Big_L2.code(), &raw, 7).unwrap();
        m2 = Matter::new_with_qb64(&m.qb64().unwrap()).unwrap();
        assert_eq!(m.code, m2.code);
        assert_eq!(m.raw, m2.raw);
        assert_eq!(m.size, m2.size);
        m2 = Matter::new_with_qb2(&m.qb2().unwrap()).unwrap();
        assert_eq!(m.code, m2.code);
        assert_eq!(m.raw, m2.raw);
        assert_eq!(m.size, m2.size);

        // default
        m = Default::default();
        assert_eq!(m.code, matter::Codex::Blake3_256.code());

        // partial override
        m = Matter {
            size: 3,
            ..Default::default()
        };
        assert_eq!(m.size, 3);

        // full override
        m = Matter {
            raw: b"a".to_vec(),
            code: matter::Codex::X25519_Cipher_Seed.code().to_string(),
            size: 1,
        };

        assert_eq!(m.raw, b"a".to_vec());
        assert_eq!(m.code, matter::Codex::X25519_Cipher_Seed.code());
        assert_eq!(m.size, 1);
    }
}
