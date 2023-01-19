use std::borrow::Borrow;

use base64::{engine::general_purpose, Engine as _};

use crate::core::sizage::Sizage;
use crate::error::Error;

#[derive(Debug, Eq, PartialEq, Clone)]
pub enum MatterCodex {
    Ed25519Seed,
    Ed25519N,
    X25519,
    Ed25519,
    Blake3_256,
    X25519Private,
    X25519CipherSeed,
    X25519CipherSalt,
    Salt128,
    Ed25519Sig,
}

impl MatterCodex {
    pub(crate) fn code(&self) -> &'static str {
        match self {
            MatterCodex::Ed25519Seed => "A",
            MatterCodex::Ed25519N => "B", // Ed25519 verification key non-transferable, basic derivation.
            MatterCodex::X25519 => "C", // X25519 public encryption key, converted from Ed25519 or Ed25519N.
            MatterCodex::Ed25519 => "D", // Ed25519 verification key basic derivation
            MatterCodex::Blake3_256 => "E", // Blake3 256 bit digest self-addressing derivation.
            MatterCodex::X25519Private => "O", // X25519 private decryption key converted from Ed25519
            MatterCodex::X25519CipherSeed => "P", // X25519 124 char b64 Cipher of 44 char qb64 Seed
            MatterCodex::X25519CipherSalt => "1AAH", // X25519 100 char b64 Cipher of 24 char qb64 Salt
            MatterCodex::Salt128 => "0A", // 128 bit random salt or 128 bit number (see Huge)
            MatterCodex::Ed25519Sig => "0B", // Ed25519 signature.
        }
    }
}

#[derive(Debug)]
pub struct Matter {
    raw: Vec<u8>,
    code: String,
    size: u8,
    qb64: String,
    qb64b: Vec<u8>,
}

impl Matter {
    pub fn new_with_raw_and_code(raw: Vec<u8>, code: String) -> Result<Matter, Error> {
        // if (code.length === 0) {
        //     throw new Error("Improper initialization need either (raw and code) or qb64b or qb64 or qb2.")
        // }
        //
        // // Add support for variable size codes here if needed, this code only works for stable size codes
        // let sizage = Matter.Sizes.get(code)
        // if (sizage!.fs === -1) {  // invalid
        //     throw new Error(`Unsupported variable size code=${code}`)
        // }
        //
        // let rize = Matter._rawSize(code)
        // raw = raw.slice(0, rize)  // copy only exact size from raw stream
        // if (raw.length != rize) { // forbids shorter
        //     throw new Error(`Not enough raw bytes for code=${code} expected ${rize} got ${raw.length}.`)
        // }
        //
        // this._code = code  // hard value part of code
        // this._size = size  // soft value part of code in int
        // this._raw = raw    // crypto ops require bytes not bytearray
        Ok(Matter {
            ..Default::default()
        })
    }

    pub fn new_with_qb64(qb64: String) -> Result<Matter, Error> {
        let mut m: Matter = Default::default();
        match m.exfil(qb64) {
            Ok(_) => {}
            Err(e) => return Err(e),
        }

        let out = m;
        Ok(out)
    }

    pub fn new_with_qb64b(qb64b: Vec<u8>) -> Result<Matter, Error> {
        let qb64 = match String::from_utf8(qb64b) {
            Ok(v) => v,
            Err(e) => return Err(Error::ParseQb64Error(e.to_string())),
        };

        let mut m: Matter = Default::default();
        match m.exfil(qb64) {
            Ok(_) => {}
            Err(e) => return Err(e),
        }

        let out = m;
        Ok(out)
    }

    pub fn new_with_qb2(qb2: Vec<u8>) -> Result<Matter, Error> {
        let mut m: Matter = Default::default();
        let out = m;
        Ok(out)
    }

    pub fn code(&self) -> &str {
        self.code.as_str()
    }
    pub fn size(&self) -> u8 {
        self.size
    }
    pub fn raw(&self) -> Vec<u8> {
        self.raw.clone()
    }
    pub fn qb64(&self) {
        self.infil()
    }
    pub fn qb64b(&self) -> Vec<u8> {
        Vec::from(self.qb64.as_bytes())
    }
    pub fn transferable() {}

    fn exfil(&mut self, qb64: String) -> Result<(), Error> {
        if qb64.len() == 0 {
            return Err(Error::EmptyMaterialError());
        }

        let first: char;
        match qb64.chars().next() {
            None => return Err(Error::EmptyQb64Error()),
            Some(c) => first = c,
        }

        let hs: usize;
        match hardage(first) {
            Ok(h) => hs = h as usize,
            Err(e) => {
                return Err(e);
            }
        }

        if qb64.len() < hs {
            return Err(Error::ShortageError());
        }

        // bounds already checked
        let size;
        let mut hard = String::new();
        hard.push_str(&qb64[..hs]);

        match sizage(hard.as_str()) {
            Ok(s) => size = s,
            Err(e) => {
                return Err(e);
            }
        }

        let cs = size.hs + size.ss;
        if size.fs == u16::MAX {
            return Err(Error::UnsupportedSizeError());
        }

        let full_size = size.fs as usize;
        if qb64.len() < full_size as usize {
            let s = full_size - qb64.len();
            return Err(Error::TooSmallError(s));
        }

        let trim = &qb64[..full_size];
        let ps = cs % 4;
        let pbs = (2 * (if ps == 0 { size.ls } else { ps })) as i32;
        let raw: Vec<u8>;
        if ps != 0 {
            let mut base = "A".repeat((ps + 1) as usize);
            base.push_str(&trim[0..(cs as usize)]);

            println!("{:?}", base);
            // decode base to leave pre-padded raw
            let mut buf = Vec::<u8>::new();
            general_purpose::URL_SAFE
                .decode_vec(base, &mut buf)
                .unwrap();

            let mut pi: i32 = 0;
            // readInt
            for b in &buf[..(ps as usize)] {
                pi = (pi * 256) + (*b as i32)
            }

            if (pi & pbs.pow(2) - 1) == 1 {
                return Err(Error::PrepadError());
            }

            raw = buf[0..(ps as usize)].to_owned();
            buf.clear();
        } else {
            let base = &trim[..(cs as usize)];
            let mut buf = Vec::<u8>::new();
            general_purpose::URL_SAFE
                .decode_vec(base, &mut buf)
                .unwrap();

            let mut li: u32 = 0;
            for b in &buf[..(size.ls as usize)] {
                li = (li * 256) + (*b as u32);
            }

            if li != 0 {
                return if li == 1 {
                    Err(Error::NonZeroedLeadByte())
                } else {
                    Err(Error::NonZeroedLeadByte())
                };
            }
            raw = buf[0..(size.ls as usize)].to_owned();
            buf.clear();
        }

        self.code = hard;
        self.size = full_size as u8;
        self.raw = raw.clone();

        Ok(())
    }

    fn infil(&self) {
        todo!()
    }
}

impl Default for Matter {
    fn default() -> Self {
        Matter {
            raw: vec![],
            code: "".to_string(),
            size: 0,
            qb64: "".to_string(),
            qb64b: vec![],
        }
    }
}

fn hardage(c: char) -> Result<i32, Error> {
    match c {
        'A'..='Z' | 'a'..='z' => Ok(1),
        '0' | '4' | '5' | '6' => Ok(2),
        '1' | '2' | '3' | '7' | '8' | '9' => Ok(4),
        _ => Err(Error::UnknownHardage(c.to_string())),
    }
}

fn sizage(s: &str) -> Result<Sizage, Error> {
    match s {
        "A" => Ok(Sizage::new(1, 0, 44, 0)),
        "B" => Ok(Sizage::new(1, 0, 44, 0)),
        "C" => Ok(Sizage::new(1, 0, 44, 0)),
        "D" => Ok(Sizage::new(1, 0, 44, 0)),
        "E" => Ok(Sizage::new(1, 0, 44, 0)),
        "O" => Ok(Sizage::new(1, 0, 44, 0)),
        "P" => Ok(Sizage::new(1, 0, 124, 0)),
        "1AAH" => Ok(Sizage::new(2, 0, 24, 0)),
        "0A" => Ok(Sizage::new(1, 0, 88, 0)),
        "0B" => Ok(Sizage::new(4, 0, 100, 0)),
        _ => Err(Error::UnknownSizage(s.to_string())),
    }
}

#[cfg(test)]
mod matter_codex_tests {
    use crate::core::matter::{hardage, sizage, Matter, MatterCodex};

    #[test]
    fn test_codes() {
        assert_eq!(MatterCodex::Ed25519Seed.code(), "A");
        assert_eq!(MatterCodex::Ed25519N.code(), "B");
        assert_eq!(MatterCodex::X25519.code(), "C");
        assert_eq!(MatterCodex::Ed25519.code(), "D");
        assert_eq!(MatterCodex::Blake3_256.code(), "E");
        assert_eq!(MatterCodex::X25519Private.code(), "O");
        assert_eq!(MatterCodex::X25519CipherSeed.code(), "P");
        assert_eq!(MatterCodex::X25519CipherSalt.code(), "1AAH");
        assert_eq!(MatterCodex::Salt128.code(), "0A");
        assert_eq!(MatterCodex::Ed25519Sig.code(), "0B");
    }

    #[test]
    fn test_sizage() {
        let mut s = sizage(MatterCodex::Ed25519Seed.code()).unwrap();
        assert_eq!(s.hs, 1);
        assert_eq!(s.ss, 0);
        assert_eq!(s.fs, 44);
        assert_eq!(s.ls, 0);

        s = sizage(MatterCodex::Ed25519N.code()).unwrap();
        assert_eq!(s.hs, 1);
        assert_eq!(s.ss, 0);
        assert_eq!(s.fs, 44);
        assert_eq!(s.ls, 0);

        s = sizage(MatterCodex::X25519.code()).unwrap();
        assert_eq!(s.hs, 1);
        assert_eq!(s.ss, 0);
        assert_eq!(s.fs, 44);
        assert_eq!(s.ls, 0);

        s = sizage(MatterCodex::Ed25519.code()).unwrap();
        assert_eq!(s.hs, 1);
        assert_eq!(s.ss, 0);
        assert_eq!(s.fs, 44);
        assert_eq!(s.ls, 0);

        s = sizage(MatterCodex::Blake3_256.code()).unwrap();
        assert_eq!(s.hs, 1);
        assert_eq!(s.ss, 0);
        assert_eq!(s.fs, 44);
        assert_eq!(s.ls, 0);

        s = sizage(MatterCodex::X25519Private.code()).unwrap();
        assert_eq!(s.hs, 1);
        assert_eq!(s.ss, 0);
        assert_eq!(s.fs, 44);
        assert_eq!(s.ls, 0);

        s = sizage(MatterCodex::X25519CipherSeed.code()).unwrap();
        assert_eq!(s.hs, 1);
        assert_eq!(s.ss, 0);
        assert_eq!(s.fs, 124);
        assert_eq!(s.ls, 0);

        s = sizage(MatterCodex::X25519CipherSalt.code()).unwrap();
        assert_eq!(s.hs, 2);
        assert_eq!(s.ss, 0);
        assert_eq!(s.fs, 24);
        assert_eq!(s.ls, 0);

        s = sizage(MatterCodex::Salt128.code()).unwrap();
        assert_eq!(s.hs, 1);
        assert_eq!(s.ss, 0);
        assert_eq!(s.fs, 88);
        assert_eq!(s.ls, 0);

        s = sizage(MatterCodex::Ed25519Sig.code()).unwrap();
        assert_eq!(s.hs, 4);
        assert_eq!(s.ss, 0);
        assert_eq!(s.fs, 100);
        assert_eq!(s.ls, 0);
    }

    #[test]
    fn test_hardage() {
        assert_eq!(hardage('A').unwrap(), 1);
        assert_eq!(hardage('G').unwrap(), 1);
        assert_eq!(hardage('b').unwrap(), 1);
        assert_eq!(hardage('z').unwrap(), 1);
        assert_eq!(hardage('1').unwrap(), 4);
        assert_eq!(hardage('0').unwrap(), 2);
    }

    #[test]
    fn test_matter_new() {
        // let m = Matter::new_with_qb64(
        //     "BGlOiUdp5sMmfotHfCWQKEzWR91C72AH0lT84c0um-Qj".to_string()).unwrap();
        // assert_eq!(m.code(), MatterCodex::Ed25519N.code())

        // let mut m: Matter = Default::default();
        // assert_eq!(m.code.unwrap(), MatterCodex::Ed25519N.code());
        // assert_eq!(m.qb64.unwrap(), "");
        //
        // // partial override
        // m = Matter {
        //     qb64: Some("qb64".into()),
        //     ..Default::default()
        // };
        // assert_eq!(m.qb64.unwrap(), "qb64");
        //
        // // full override
        // m = Matter {
        //     raw: Some(b"a".to_vec()),
        //     code: Some(MatterCodex::X25519CipherSeed.code()),
        //     qb64b: Some(b"b".to_vec()),
        //     qb64: Some("qb64".into()),
        //     qb2: Some(b"c".to_vec()),
        //     strip: Some(true),
        // };
        //
        // assert_eq!(m.raw.unwrap(), b"a".to_vec());
        // assert_eq!(m.code.unwrap(), MatterCodex::X25519CipherSeed.code());
        // assert_eq!(m.qb64b.unwrap(), b"b".to_vec());
        // assert_eq!(m.qb64.unwrap(), "qb64");
        // assert_eq!(m.qb2.unwrap(), b"c".to_vec());
        // assert_eq!(m.strip.unwrap(), true);
    }
}
