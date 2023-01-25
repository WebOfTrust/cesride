use base64::Engine;

use crate::core::sizage::{sizage, Sizage};
use crate::core::util;
use crate::error;

use super::hardage::hardage;

#[allow(non_camel_case_types)]
#[derive(Debug, Eq, PartialEq, Clone)]
pub enum MatterCodex {
    Ed25519_Seed,
    Ed25519N,
    X25519,
    Ed25519,
    Blake3_256,
    Blake2b_256,
    Blake2s_256,
    SHA3_256,
    SHA2_256,
    ECDSA_256k1_Seed,
    Ed448_Seed,
    X448,
    Short,
    Big,
    X25519_Private,
    X25519_Cipher_Seed,
    Salt_128,
    Ed25519_Sig,
    ECDSA_256k1_Sig,
    Blake3_512,
    Blake2b_512,
    SHA3_512,
    SHA2_512,
    Long,
    ECDSA_256k1N,
    ECDSA_256k1,
    Ed448N,
    Ed448,
    Ed448_Sig,
    Tern,
    DateTime,
    X25519_Cipher_Salt,
    TBD1,
    TBD2,
    StrB64_L0,
    StrB64_L1,
    StrB64_L2,
    StrB64_Big_L0,
    StrB64_Big_L1,
    StrB64_Big_L2,
    Bytes_L0,
    Bytes_L1,
    Bytes_L2,
    Bytes_Big_L0,
    Bytes_Big_L1,
    Bytes_Big_L2,
}

impl MatterCodex {
    pub(crate) fn code(&self) -> &'static str {
        match self {
            MatterCodex::Ed25519_Seed => "A", // Ed25519 256 bit random seed for private key
            MatterCodex::Ed25519N => "B", // Ed25519 verification key non-transferable, basic derivation.
            MatterCodex::X25519 => "C", // X25519 public encryption key, converted from Ed25519 or Ed25519N.
            MatterCodex::Ed25519 => "D", // Ed25519 verification key basic derivation
            MatterCodex::Blake3_256 => "E", // Blake3 256 bit digest self-addressing derivation.
            MatterCodex::Blake2b_256 => "F", // Blake2b 256 bit digest self-addressing derivation.
            MatterCodex::Blake2s_256 => "G", // Blake2s 256 bit digest self-addressing derivation.
            MatterCodex::SHA3_256 => "H", // SHA3 256 bit digest self-addressing derivation.
            MatterCodex::SHA2_256 => "I", // SHA2 256 bit digest self-addressing derivation.
            MatterCodex::ECDSA_256k1_Seed => "J", // ECDSA secp256k1 256 bit random Seed for private key
            MatterCodex::Ed448_Seed => "K",       // Ed448 448 bit random Seed for private key
            MatterCodex::X448 => "L", // X448 public encryption key, converted from Ed448
            MatterCodex::Short => "M", // Short 2 byte b2 number
            MatterCodex::Big => "N",  // Big 8 byte b2 number
            MatterCodex::X25519_Private => "O", // X25519 private decryption key converted from Ed25519
            MatterCodex::X25519_Cipher_Seed => "P", // X25519 124 char b64 Cipher of 44 char qb64 Seed
            MatterCodex::Salt_128 => "0A", // 128 bit random salt or 128 bit number (see Huge)
            MatterCodex::Ed25519_Sig => "0B", // Ed25519 signature.
            MatterCodex::ECDSA_256k1_Sig => "0C", // ECDSA secp256k1 signature.
            MatterCodex::Blake3_512 => "0D", // Blake3 512 bit digest self-addressing derivation.
            MatterCodex::Blake2b_512 => "0E", // Blake2b 512 bit digest self-addressing derivation.
            MatterCodex::SHA3_512 => "0F", // SHA3 512 bit digest self-addressing derivation.
            MatterCodex::SHA2_512 => "0G", // SHA2 512 bit digest self-addressing derivation.
            MatterCodex::Long => "0H",     // Long 4 byte b2 number
            MatterCodex::ECDSA_256k1N => "1AAA", // ECDSA secp256k1 verification key non-transferable, basic derivation.
            MatterCodex::ECDSA_256k1 => "1AAB", // Ed25519 public verification or encryption key, basic derivation
            MatterCodex::Ed448N => "1AAC", // Ed448 non-transferable prefix public signing verification key. Basic derivation.
            MatterCodex::Ed448 => "1AAD", // Ed448 public signing verification key. Basic derivation.
            MatterCodex::Ed448_Sig => "1AAE", // Ed448 signature. Self-signing derivation.
            MatterCodex::Tern => "1AAF",  // 3 byte b2 number or 4 char B64 str.
            MatterCodex::DateTime => "1AAG", // Base64 custom encoded 32 char ISO-8601 DateTime
            MatterCodex::X25519_Cipher_Salt => "1AAH", // X25519 100 char b64 Cipher of 24 char qb64 Salt
            MatterCodex::TBD1 => "2AAA", // Testing purposes only fixed with lead size 1
            MatterCodex::TBD2 => "3AAA", // Testing purposes only of fixed with lead size 2
            MatterCodex::StrB64_L0 => "4A", // String Base64 Only Lead Size 0 (4095 * 3 | 4)
            MatterCodex::StrB64_L1 => "5A", // String Base64 Only Lead Size 1
            MatterCodex::StrB64_L2 => "6A", // String Base64 Only Lead Size 2
            MatterCodex::StrB64_Big_L0 => "7AAA", // String Base64 Only Big Lead Size 0 (16777215 * 3 | 4)
            MatterCodex::StrB64_Big_L1 => "8AAA", // String Base64 Only Big Lead Size 1
            MatterCodex::StrB64_Big_L2 => "9AAA", // String Base64 Only Big Lead Size 2
            MatterCodex::Bytes_L0 => "4B",        // Byte String Leader Size 0
            MatterCodex::Bytes_L1 => "5B",        // Byte String Leader Size 1
            MatterCodex::Bytes_L2 => "6B",        // Byte String Leader Size 2
            MatterCodex::Bytes_Big_L0 => "7AAB",  // Byte String Big Leader Size 0
            MatterCodex::Bytes_Big_L1 => "8AAB",  // Byte String Big Leader Size 1
            MatterCodex::Bytes_Big_L2 => "9AAB",  // Byte String Big Leader Size 2
        }
    }
}

#[derive(Debug)]
pub struct Matter {
    raw: Vec<u8>,
    code: String,
    size: u32,
}

impl Matter {
    pub fn new_with_code_and_raw(
        code: String,
        raw: Vec<u8>,
        raw_length: usize,
    ) -> error::Result<Matter> {
        let mut m = Matter::default();

        if code.is_empty() {
            return Err(Box::new(error::Error::EmptyMaterial(
                "empty code".to_owned(),
            )));
        }

        let mut size: u32 = 0;
        let mut rize = raw_length as u32;
        // this unwrap can stay since we have validated that code is not empty, above
        let first = code.chars().next().unwrap();

        const SMALL_VRZ_DEX: [char; 3] = ['4', '5', '6'];
        const LARGE_VRZ_DEX: [char; 3] = ['7', '8', '9'];

        if SMALL_VRZ_DEX.contains(&first) || LARGE_VRZ_DEX.contains(&first) {
            if rize == 0 {
                rize = raw.len() as u32;
            }

            let ls = (3 - (rize % 3)) % 3;
            size = (rize + ls) / 3;
            let mut code = code.clone();

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
                    return Err(Box::new(error::Error::InvalidVarRawSize(format!(
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
                    return Err(Box::new(error::Error::InvalidVarRawSize(format!(
                        "unsupported raw size: code = [{}]",
                        code
                    ))));
                }
            } else {
                return Err(Box::new(error::Error::InvalidVarRawSize(format!(
                    "unsupported variable raw size: code = [{}]",
                    code
                ))));
            }
        } else {
            let sizage_ = sizage(&code)?;
            if sizage_.fs == 0 {
                return Err(Box::new(error::Error::InvalidVarRawSize(format!(
                    "unsupported variable size: code = [{}]",
                    code
                ))));
            }
            rize = raw_size(sizage_);
        }

        m.code = code;
        m.size = size;
        m.raw = raw[..rize as usize].to_owned();

        Ok(m)
    }

    pub fn new_with_qb64(qb64: String) -> error::Result<Matter> {
        let mut m: Matter = Default::default();
        m.exfil(qb64)?;
        Ok(m)
    }

    pub fn new_with_qb64b(qb64b: Vec<u8>) -> error::Result<Matter> {
        let qb64 = String::from_utf8(qb64b)?;

        let mut m: Matter = Default::default();
        m.exfil(qb64)?;
        Ok(m)
    }

    pub fn new_with_qb2(qb2: Vec<u8>) -> error::Result<Matter> {
        let mut m: Matter = Default::default();
        m.bexfil(qb2)?;
        Ok(m)
    }

    pub fn code(&self) -> &str {
        self.code.as_str()
    }

    pub fn size(&self) -> u32 {
        self.size
    }

    pub fn raw(&self) -> Vec<u8> {
        self.raw.clone()
    }

    pub fn qb64(&self) -> error::Result<String> {
        self.infil()
    }

    pub fn qb64b(&self) -> error::Result<Vec<u8>> {
        Ok(Vec::from(self.qb64()?.as_bytes()))
    }

    pub fn qb2(&self) -> error::Result<Vec<u8>> {
        self.binfil()
    }

    pub fn transferable() {}

    fn infil(&self) -> error::Result<String> {
        let code = &self.code;
        let size = self.size;
        let mut raw = self.raw.clone();

        let ps = (3 - raw.len() % 3) % 3;
        let sizage_ = sizage(code)?;

        if sizage_.fs == 0 {
            let cs = sizage_.hs + sizage_.ss;
            if cs % 4 != 0 {
                return Err(Box::new(error::Error::InvalidCodeSize(format!(
                    "whole code size not multiple of 4 for variable length material: cs = [{}]",
                    cs
                ))));
            };

            const SIXTY_FOUR: u32 = 64;
            if SIXTY_FOUR.pow(sizage_.ss) - 1 < size {
                return Err(Box::new(error::Error::InvalidVarSize(format!(
                    "invalid size for code: size = [{}], code = [{}]",
                    size, code
                ))));
            }

            let both = format!("{}{}", code, util::u32_to_b64(size, sizage_.ss as usize));

            if both.len() % 4 != ps - sizage_.ls as usize {
                return Err(Box::new(error::Error::InvalidCodeSize(format!(
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
                return Err(Box::new(error::Error::InvalidCodeSize(format!(
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

    fn binfil(&self) -> error::Result<Vec<u8>> {
        let code = &self.code;
        let size = self.size;
        let mut raw = self.raw.clone();

        let mut sizage_ = sizage(code)?;
        let cs = sizage_.hs + sizage_.ss;

        let both: &String;
        let temp: String;
        if sizage_.fs == 0 {
            if cs % 4 != 0 {
                return Err(Box::new(error::Error::InvalidCodeSize(format!(
                    "whole code size not multiple of 4 for variable length material: cs = [{}]",
                    cs
                ))));
            }

            // ? check python code for a < 0 comparison
            const SIXTY_FOUR: u32 = 64;
            if SIXTY_FOUR.pow(sizage_.ss) - 1 < size {
                return Err(Box::new(error::Error::InvalidVarSize(format!(
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
            return Err(Box::new(error::Error::InvalidCodeSize(format!(
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
            return Err(Box::new(error::Error::InvalidCodeSize(format!(
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
            return Err(Box::new(error::Error::InvalidCodeSize(format!(
                "invalid code for raw size: code = [{}], raw size = [{}]",
                both,
                raw.len()
            ))));
        }

        Ok(full)
    }

    fn exfil(&mut self, qb64: String) -> error::Result<()> {
        if qb64.is_empty() {
            return Err(Box::new(error::Error::EmptyMaterial(
                "empty qb64".to_owned(),
            )));
        }

        // we validated there will be a char here, above.
        let first = qb64.chars().next().unwrap();

        let hs = hardage(first)? as usize;
        if qb64.len() < hs {
            return Err(Box::new(error::Error::Shortage(format!(
                "insufficient material for hard part of code: qb64 size = [{}], hs = [{}]",
                qb64.len(),
                hs
            ))));
        }

        // bounds already checked
        let hard = qb64[..hs].to_owned();
        let mut sizage_ = sizage(&hard)?;
        let cs = sizage_.hs + sizage_.ss;

        let mut size: u32 = 0;
        if sizage_.fs == 0 {
            if cs % 4 != 0 {
                return Err(Box::new(error::Error::InvalidCodeSize(format!(
                    "code size not multiple of 4 for variable length material: cs = [{}]",
                    cs
                ))));
            }

            if qb64.len() < cs as usize {
                return Err(Box::new(error::Error::Shortage(format!(
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
            return Err(Box::new(error::Error::Shortage(format!(
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
            base64::engine::general_purpose::URL_SAFE
                .decode_vec(buf, &mut paw)
                .unwrap();

            let mut pi: i32 = 0;
            // readInt
            for b in &paw[..ps as usize] {
                pi = (pi * 256) + (*b as i32)
            }

            const TWO: i32 = 2;
            if (pi & (TWO.pow(pbs) - 1)) != 0 {
                return Err(Box::new(error::Error::Prepad()));
            }

            raw = paw[ps as usize..].to_owned();
            paw.clear();
        } else {
            let buf = &trim[cs as usize..];
            let mut paw = Vec::<u8>::new();
            base64::engine::general_purpose::URL_SAFE
                .decode_vec(buf, &mut paw)
                .unwrap();

            let mut li: u32 = 0;
            for b in &paw[..sizage_.ls as usize] {
                li = (li * 256) + (*b as u32);
            }

            if li != 0 {
                return if sizage_.ls == 1 {
                    Err(Box::new(error::Error::NonZeroedLeadByte()))
                } else {
                    Err(Box::new(error::Error::NonZeroedLeadBytes()))
                };
            }
            raw = paw[sizage_.ls as usize..].to_owned();
            paw.clear();
        }

        self.code = hard;
        self.size = size;
        self.raw.clone_from(&raw);

        Ok(())
    }

    fn bexfil(&mut self, qb2: Vec<u8>) -> error::Result<()> {
        if qb2.is_empty() {
            return Err(Box::new(error::Error::EmptyMaterial(
                "empty qualified base2".to_owned(),
            )));
        }

        let first_byte = (qb2[0] & 0xfc) >> 2;
        if first_byte > 0x3d {
            if first_byte == 0x3e {
                return Err(Box::new(error::Error::UnexpectedCountCode(
                    "unexpected start during extraction".to_owned(),
                )));
            } else if first_byte == 0x3f {
                return Err(Box::new(error::Error::UnexpectedOpCode(
                    "unexpected start during extraction".to_owned(),
                )));
            } else {
                return Err(Box::new(error::Error::UnexpectedCode(format!(
                    "unexpected code start: sextet = [{}]",
                    first_byte
                ))));
            }
        }

        let first = util::b64_index_to_char(first_byte);
        let hs = hardage(first)? as usize;
        let bhs = (hs * 3 + 3) / 4;
        if qb2.len() < bhs {
            return Err(Box::new(error::Error::Shortage(format!(
                "insufficient material for hard part of code: qb2 size = [{}], bhs = [{}]",
                qb2.len(),
                bhs
            ))));
        }

        let hard = util::code_b2_to_b64(&qb2, hs)?;
        let mut sizage_ = sizage(&hard)?;
        let cs = sizage_.hs + sizage_.ss;
        let bcs = ((cs + 1) * 3) / 4;
        let mut size: u32 = 0;
        if sizage_.fs == 0 {
            if cs % 4 != 0 {
                return Err(Box::new(error::Error::ParseQb2(format!(
                    "code size not multiple of 4 for variable length material: cs = [{}]",
                    cs
                ))));
            }

            if qb2.len() < bcs as usize {
                return Err(Box::new(error::Error::Shortage(format!(
                    "insufficient material for code: qb2 size = [{}], bcs = [{}]",
                    qb2.len(),
                    bcs
                ))));
            }

            let both = util::code_b2_to_b64(&qb2, cs as usize)?;
            size = util::b64_to_u32(&both[sizage_.hs as usize..cs as usize]);
            sizage_.fs = (size * 4) + cs
        }

        let bfs = ((sizage_.fs + 1) * 3) / 4;
        if qb2.len() < bfs as usize {
            return Err(Box::new(error::Error::Shortage(format!(
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
                return Err(Box::new(error::Error::NonZeroedPadBits()));
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
                            return Err(Box::new(error::Error::NonZeroedLeadByte()));
                        }
                        _ => {
                            return Err(Box::new(error::Error::NonZeroedLeadBytes()));
                        }
                    }
                }
            }
        }

        let raw = trim[(bcs + sizage_.ls) as usize..].to_vec();
        if raw.len() != (trim.len() - bcs as usize) - sizage_.ls as usize {
            return Err(Box::new(error::Error::Conversion(format!(
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
            code: "".to_owned(),
            size: 0,
        }
    }
}

fn raw_size(sizage: Sizage) -> u32 {
    let cs = sizage.hs + sizage.ss;
    ((sizage.fs - cs) * 3 / 4) - sizage.ls
}

#[cfg(test)]
mod matter_codex_tests {
    use super::Sizage;
    use crate::core::matter::{sizage, Matter, MatterCodex};

    #[test]
    fn test_codes() {
        assert_eq!(MatterCodex::Ed25519_Seed.code(), "A");
        assert_eq!(MatterCodex::Ed25519N.code(), "B");
        assert_eq!(MatterCodex::X25519.code(), "C");
        assert_eq!(MatterCodex::Ed25519.code(), "D");
        assert_eq!(MatterCodex::Blake3_256.code(), "E");
        assert_eq!(MatterCodex::Blake2b_256.code(), "F");
        assert_eq!(MatterCodex::Blake2s_256.code(), "G");
        assert_eq!(MatterCodex::SHA3_256.code(), "H");
        assert_eq!(MatterCodex::SHA2_256.code(), "I");
        assert_eq!(MatterCodex::ECDSA_256k1_Seed.code(), "J");
        assert_eq!(MatterCodex::Ed448_Seed.code(), "K");
        assert_eq!(MatterCodex::X448.code(), "L");
        assert_eq!(MatterCodex::Short.code(), "M");
        assert_eq!(MatterCodex::Big.code(), "N");
        assert_eq!(MatterCodex::X25519_Private.code(), "O");
        assert_eq!(MatterCodex::X25519_Cipher_Seed.code(), "P");
        assert_eq!(MatterCodex::Salt_128.code(), "0A");
        assert_eq!(MatterCodex::Ed25519_Sig.code(), "0B");
        assert_eq!(MatterCodex::ECDSA_256k1_Sig.code(), "0C");
        assert_eq!(MatterCodex::Blake3_512.code(), "0D");
        assert_eq!(MatterCodex::Blake2b_512.code(), "0E");
        assert_eq!(MatterCodex::SHA3_512.code(), "0F");
        assert_eq!(MatterCodex::SHA2_512.code(), "0G");
        assert_eq!(MatterCodex::Long.code(), "0H");
        assert_eq!(MatterCodex::ECDSA_256k1N.code(), "1AAA");
        assert_eq!(MatterCodex::ECDSA_256k1.code(), "1AAB");
        assert_eq!(MatterCodex::Ed448N.code(), "1AAC");
        assert_eq!(MatterCodex::Ed448.code(), "1AAD");
        assert_eq!(MatterCodex::Ed448_Sig.code(), "1AAE");
        assert_eq!(MatterCodex::Tern.code(), "1AAF");
        assert_eq!(MatterCodex::DateTime.code(), "1AAG");
        assert_eq!(MatterCodex::X25519_Cipher_Salt.code(), "1AAH");
        assert_eq!(MatterCodex::TBD1.code(), "2AAA");
        assert_eq!(MatterCodex::TBD2.code(), "3AAA");
        assert_eq!(MatterCodex::StrB64_L0.code(), "4A");
        assert_eq!(MatterCodex::StrB64_L1.code(), "5A");
        assert_eq!(MatterCodex::StrB64_L2.code(), "6A");
        assert_eq!(MatterCodex::StrB64_Big_L0.code(), "7AAA");
        assert_eq!(MatterCodex::StrB64_Big_L1.code(), "8AAA");
        assert_eq!(MatterCodex::StrB64_Big_L2.code(), "9AAA");
        assert_eq!(MatterCodex::Bytes_L0.code(), "4B");
        assert_eq!(MatterCodex::Bytes_L1.code(), "5B");
        assert_eq!(MatterCodex::Bytes_L2.code(), "6B");
        assert_eq!(MatterCodex::Bytes_Big_L0.code(), "7AAB");
        assert_eq!(MatterCodex::Bytes_Big_L1.code(), "8AAB");
        assert_eq!(MatterCodex::Bytes_Big_L2.code(), "9AAB");
    }

    #[test]
    fn test_matter_new() {
        let qb64 = "BGlOiUdp5sMmfotHfCWQKEzWR91C72AH0lT84c0um-Qj";

        // basic
        let mut m = Matter::new_with_qb64(qb64.to_owned()).unwrap();
        assert_eq!(m.code, MatterCodex::Ed25519N.code());

        // qb64
        let mut m2 =
            Matter::new_with_code_and_raw(m.code.clone(), m.raw.clone(), m.raw.len()).unwrap();
        assert_eq!(m.code, m2.code);
        assert_eq!(m.raw, m2.raw);
        assert_eq!(m.size, m2.size);
        assert_eq!(qb64, m2.qb64().unwrap());

        // qb64b
        m2 = Matter::new_with_qb64b(m.qb64b().unwrap()).unwrap();
        assert_eq!(m.code, m2.code);
        assert_eq!(m.raw, m2.raw);
        assert_eq!(m.size, m2.size);
        assert_eq!(qb64, m2.qb64().unwrap());

        // qb2
        m2 = Matter::new_with_qb2(m.qb2().unwrap()).unwrap();
        assert_eq!(m.code, m2.code);
        assert_eq!(m.raw, m2.raw);
        assert_eq!(m.size, m2.size);
        assert_eq!(qb64, m2.qb64().unwrap());

        // small variable b64(), ls = 0
        let raw: Vec<u8> = vec![0, 1, 2, 3, 4, 5, 6, 7, 8];
        m = Matter::new_with_code_and_raw(MatterCodex::StrB64_L0.code().to_owned(), raw, 9)
            .unwrap();
        m2 = Matter::new_with_qb64(m.qb64().unwrap()).unwrap();
        assert_eq!(m.code, m2.code);
        assert_eq!(m.raw, m2.raw);
        assert_eq!(m.size, m2.size);
        m2 = Matter::new_with_qb2(m.qb2().unwrap()).unwrap();
        assert_eq!(m.code, m2.code);
        assert_eq!(m.raw, m2.raw);
        assert_eq!(m.size, m2.size);

        // small variable b64(), ls = 1
        let raw: Vec<u8> = vec![0, 1, 2, 3, 4, 5, 6, 7];
        m = Matter::new_with_code_and_raw(MatterCodex::StrB64_L1.code().to_owned(), raw, 8)
            .unwrap();
        m2 = Matter::new_with_qb64(m.qb64().unwrap()).unwrap();
        assert_eq!(m.code, m2.code);
        assert_eq!(m.raw, m2.raw);
        assert_eq!(m.size, m2.size);
        m2 = Matter::new_with_qb2(m.qb2().unwrap()).unwrap();
        assert_eq!(m.code, m2.code);
        assert_eq!(m.raw, m2.raw);
        assert_eq!(m.size, m2.size);

        // small variable b64(), ls = 2
        let raw: Vec<u8> = vec![0, 1, 2, 3, 4, 5, 6];
        m = Matter::new_with_code_and_raw(MatterCodex::StrB64_L2.code().to_owned(), raw, 7)
            .unwrap();
        m2 = Matter::new_with_qb64(m.qb64().unwrap()).unwrap();
        assert_eq!(m.code, m2.code);
        assert_eq!(m.raw, m2.raw);
        assert_eq!(m.size, m2.size);
        m2 = Matter::new_with_qb2(m.qb2().unwrap()).unwrap();
        assert_eq!(m.code, m2.code);
        assert_eq!(m.raw, m2.raw);
        assert_eq!(m.size, m2.size);

        // small variable bytes is essentially the same as the above

        // large variable b64 is essentially the same as below

        // large variable bytes, ls = 0
        let raw: Vec<u8> = vec![0, 1, 2, 3, 4, 5, 6, 7, 8];
        m = Matter::new_with_code_and_raw(MatterCodex::Bytes_Big_L0.code().to_owned(), raw, 9)
            .unwrap();
        m2 = Matter::new_with_qb64(m.qb64().unwrap()).unwrap();
        assert_eq!(m.code, m2.code);
        assert_eq!(m.raw, m2.raw);
        assert_eq!(m.size, m2.size);
        m2 = Matter::new_with_qb2(m.qb2().unwrap()).unwrap();
        assert_eq!(m.code, m2.code);
        assert_eq!(m.raw, m2.raw);
        assert_eq!(m.size, m2.size);

        // large variable bytes, ls = 1
        let raw: Vec<u8> = vec![0, 1, 2, 3, 4, 5, 6, 7];
        m = Matter::new_with_code_and_raw(MatterCodex::Bytes_Big_L1.code().to_owned(), raw, 8)
            .unwrap();
        m2 = Matter::new_with_qb64(m.qb64().unwrap()).unwrap();
        assert_eq!(m.code, m2.code);
        assert_eq!(m.raw, m2.raw);
        assert_eq!(m.size, m2.size);
        m2 = Matter::new_with_qb2(m.qb2().unwrap()).unwrap();
        assert_eq!(m.code, m2.code);
        assert_eq!(m.raw, m2.raw);
        assert_eq!(m.size, m2.size);

        // large variable bytes, ls = 0
        let raw: Vec<u8> = vec![0, 1, 2, 3, 4, 5, 6];
        m = Matter::new_with_code_and_raw(MatterCodex::Bytes_Big_L2.code().to_owned(), raw, 7)
            .unwrap();
        m2 = Matter::new_with_qb64(m.qb64().unwrap()).unwrap();
        assert_eq!(m.code, m2.code);
        assert_eq!(m.raw, m2.raw);
        assert_eq!(m.size, m2.size);
        m2 = Matter::new_with_qb2(m.qb2().unwrap()).unwrap();
        assert_eq!(m.code, m2.code);
        assert_eq!(m.raw, m2.raw);
        assert_eq!(m.size, m2.size);

        // default
        m = Default::default();
        assert_eq!(m.code, "");

        // partial override
        m = Matter {
            size: 3,
            ..Default::default()
        };
        assert_eq!(m.size, 3);

        // full override
        m = Matter {
            raw: b"a".to_vec(),
            code: MatterCodex::X25519_Cipher_Seed.code().into(),
            size: 1,
        };

        assert_eq!(m.raw, b"a".to_vec());
        assert_eq!(m.code, MatterCodex::X25519_Cipher_Seed.code());
        assert_eq!(m.size, 1);
    }
}
