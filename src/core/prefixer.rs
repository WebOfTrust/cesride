use crate::{
    core::{
        common::{sizeify, Ids, Ilkage, DUMMY},
        diger::Diger,
        matter::{tables as matter, Matter},
        verfer::Verfer,
    },
    crypto::hash,
    data::Value,
    error::{err, Error, Result},
};

#[derive(Debug, Clone, PartialEq)]
pub struct Prefixer {
    code: String,
    raw: Vec<u8>,
    size: u32,
}

impl Default for Prefixer {
    fn default() -> Self {
        Prefixer { code: matter::Codex::Blake3_256.to_string(), raw: vec![], size: 0 }
    }
}

fn validate_code(code: &str) -> Result<()> {
    const CODES: &[&str] = &[
        // non-transferable
        matter::Codex::Ed25519N,
        matter::Codex::ECDSA_256k1N,
        // transferable
        matter::Codex::Ed25519,
        matter::Codex::ECDSA_256k1,
        // digests
        matter::Codex::Blake3_256,
        matter::Codex::Blake3_512,
        matter::Codex::Blake2b_256,
        matter::Codex::Blake2b_512,
        matter::Codex::Blake2s_256,
        matter::Codex::SHA3_256,
        matter::Codex::SHA3_512,
        matter::Codex::SHA2_256,
        matter::Codex::SHA2_512,
    ];

    if !CODES.contains(&code) {
        return err!(Error::UnexpectedCode(code.to_string()));
    }

    Ok(())
}

fn derive(ked: &Value, code: &str) -> Result<(Vec<u8>, String)> {
    const ILKS: &[&str] = &[Ilkage::icp, Ilkage::dip, Ilkage::vcp];

    let label = Ids::t;
    let ilk = ked[label].to_string()?;
    if !ILKS.contains(&ilk.as_str()) {
        return err!(Error::Value(format!("non-incepting ilk {ilk} found for prefix derivation")));
    }

    match code {
        // non-transferable codes
        matter::Codex::Ed25519N | matter::Codex::ECDSA_256k1N => derive_nontransferable(ked, code),
        // transferable codes
        matter::Codex::Ed25519 | matter::Codex::ECDSA_256k1 => derive_transferable(ked, code),
        // digests
        matter::Codex::Blake3_256
        | matter::Codex::Blake3_512
        | matter::Codex::Blake2b_256
        | matter::Codex::Blake2b_512
        | matter::Codex::Blake2s_256
        | matter::Codex::SHA3_256
        | matter::Codex::SHA3_512
        | matter::Codex::SHA2_256
        | matter::Codex::SHA2_512 => derive_digest(ked, code),
        // should unreachable since we only call this private function after validating code
        _ => err!(Error::UnexpectedCode(code.to_string())),
    }
}

fn derive_nontransferable(ked: &Value, code: &str) -> Result<(Vec<u8>, String)> {
    let ked = ked.clone();
    let map = ked.to_map()?;

    let label = Ids::k;
    let verfer = if map.contains_key(label) {
        let keys = ked[label].to_vec()?;

        if keys.len() != 1 {
            return err!(Error::Derivation(format!(
                "basic derivation needs exactly 1 key, got {} keys instead",
                keys.len()
            )));
        }

        Verfer::new(None, None, None, Some(&keys[0].to_string()?), None)?
    } else {
        return err!(Error::Derivation("error extracting public key".to_string()));
    };

    if verfer.code() != *code {
        return err!(Error::Derivation("code mismatch".to_string()));
    }

    let label = Ids::n;
    if map.contains_key(label) && !ked[label].to_string()?.is_empty() {
        return err!(Error::Derivation("non-empty nxt for transferable derivation".to_string()));
    }

    let label = Ids::b;
    if map.contains_key(label) && !ked[label].to_string()?.is_empty() {
        return err!(Error::Derivation("non-empty 'b' for transferable derivation".to_string()));
    }

    let label = Ids::a;
    if map.contains_key(label) && !ked[label].to_string()?.is_empty() {
        return err!(Error::Derivation("non-empty 'a' for transferable derivation".to_string()));
    }

    Ok((verfer.raw(), verfer.code()))
}

fn derive_transferable(ked: &Value, code: &str) -> Result<(Vec<u8>, String)> {
    let ked = ked.clone();
    let map = ked.to_map()?;

    let label = Ids::k;
    let verfer = if map.contains_key(label) {
        let keys = ked[label].to_vec()?;

        if keys.len() != 1 {
            return err!(Error::Derivation(format!(
                "basic derivation needs exactly 1 key, got {} keys instead",
                keys.len()
            )));
        }

        Verfer::new(None, None, None, Some(&keys[0].to_string()?), None)?
    } else {
        return err!(Error::Derivation("error extracting public key".to_string()));
    };

    if verfer.code() != *code {
        return err!(Error::Derivation("code mismatch".to_string()));
    }

    Ok((verfer.raw(), verfer.code()))
}

fn derive_digest(ked: &Value, code: &str) -> Result<(Vec<u8>, String)> {
    let mut ked = ked.clone();

    let label_i = Ids::i;
    let label_d = Ids::d;
    let szg = matter::sizage(code)?;
    let dummy = String::from_utf8(vec![DUMMY; szg.fs as usize])?;

    ked[label_i] = data!(&dummy);
    ked[label_d] = data!(&dummy);

    let result = sizeify(&ked, None)?;
    let dig = hash::digest(code, &result.raw)?;

    Ok((dig, code.to_string()))
}

fn verify_nontransferable(ked: &Value, pre: &str, prefixed: bool) -> Result<bool> {
    let map = ked.to_map()?;

    let label = Ids::k;
    if !map.contains_key(label) {
        return Ok(false);
    }

    let keys = ked[label].to_vec()?;
    if keys.len() != 1 {
        return Ok(false);
    }

    if keys[0].to_string()? != *pre {
        return Ok(false);
    }

    let label = Ids::i;
    if prefixed && (!map.contains_key(label) || ked[label].to_string()? != *pre) {
        return Ok(false);
    }

    let label = Ids::n;
    if map.contains_key(label) {
        if ked[label].to_vec().is_ok() && !ked[label].to_vec()?.is_empty() {
            return Ok(false);
        }

        // unsure if 'n' can be a single key. if it can't we can simplify all this
        if ked[label].to_string().is_ok() && !ked[label].to_string()?.is_empty() {
            return Ok(false);
        }
    }

    Ok(true)
}

fn verify_transferable(ked: &Value, pre: &str, prefixed: bool) -> Result<bool> {
    let map = ked.to_map()?;

    let label = Ids::k;
    if !map.contains_key(label) {
        return Ok(false);
    }

    let keys = ked[label].to_vec()?;
    if keys.len() != 1 {
        return Ok(false);
    }

    if keys[0].to_string()? != *pre {
        return Ok(false);
    }

    let label = Ids::i;
    if prefixed && (!map.contains_key(label) || ked[label].to_string()? != *pre) {
        return Ok(false);
    }

    Ok(true)
}

fn verify_digest(ked: &Value, pre: &str, prefixed: bool, code: &str) -> Result<bool> {
    let (raw, code) = derive_digest(ked, code)?;
    let crymat = Diger::new(None, Some(&code), Some(&raw), None, None, None)?;

    if crymat.qb64()? != *pre {
        return Ok(false);
    }

    let label = Ids::i;
    let map = ked.to_map()?;
    if prefixed && (!map.contains_key(label) || ked[label].to_string()? != *pre) {
        return Ok(false);
    }

    Ok(true)
}

impl Prefixer {
    pub fn new(
        ked: Option<&Value>,
        allows: Option<&[&str]>,
        code: Option<&str>,
        raw: Option<&[u8]>,
        qb64b: Option<&[u8]>,
        qb64: Option<&str>,
        qb2: Option<&[u8]>,
    ) -> Result<Self> {
        let prefixer: Prefixer = if raw.is_some()
            || qb64b.is_some()
            || qb64.is_some()
            || qb2.is_some()
        {
            validate_code(code.unwrap_or(matter::Codex::Ed25519N))?;
            Matter::new(code, raw, qb64b, qb64, qb2)?
        } else {
            let ked = if let Some(ked) = ked {
                if code.is_none() && !ked.to_map()?.contains_key(Ids::i) {
                    return err!(Error::Validation(
                        "must supply one of raw, qb64b, qb64, qb2, or ked with 'i'".to_string()
                    ));
                }

                ked
            } else {
                return err!(Error::Validation(
                    "must supply one of raw, qb64b, qb64, qb2, or ked with 'i'".to_string()
                ));
            };

            let code = if let Some(code) = code {
                code.to_string()
            } else {
                let label = Ids::i;
                <Prefixer as Matter>::new(None, None, None, Some(&ked[label].to_string()?), None)?
                    .code()
            };

            validate_code(&code)?;

            let allows = allows.unwrap_or(&[]);
            if !allows.is_empty() && !allows.contains(&code.as_str()) {
                return err!(Error::UnexpectedCode(code));
            }

            let (raw, code) = derive(ked, &code)?;

            Matter::new(Some(&code), Some(&raw), None, None, None)?
        };

        Ok(prefixer)
    }

    pub fn new_with_ked(ked: &Value, allows: Option<&[&str]>, code: Option<&str>) -> Result<Self> {
        Self::new(Some(ked), allows, code, None, None, None, None)
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

    pub fn verify(&self, ked: &Value, prefixed: Option<bool>) -> Result<bool> {
        const ILKS: &[&str] = &[Ilkage::icp, Ilkage::dip, Ilkage::vcp];

        let prefixed = prefixed.unwrap_or(false);
        let label = Ids::t;
        let ilk = ked[label].to_string()?;
        if !ILKS.contains(&ilk.as_str()) {
            return err!(Error::Value(format!(
                "non-incepting ilk {ilk} found for prefix verification"
            )));
        }

        match self.code().as_str() {
            // non-transferable codes
            matter::Codex::Ed25519N | matter::Codex::ECDSA_256k1N => {
                verify_nontransferable(ked, &self.qb64()?, prefixed)
            }
            // transferable codes
            matter::Codex::Ed25519 | matter::Codex::ECDSA_256k1 => {
                verify_transferable(ked, &self.qb64()?, prefixed)
            }
            // digests
            matter::Codex::Blake3_256
            | matter::Codex::Blake3_512
            | matter::Codex::Blake2b_256
            | matter::Codex::Blake2b_512
            | matter::Codex::Blake2s_256
            | matter::Codex::SHA3_256
            | matter::Codex::SHA3_512
            | matter::Codex::SHA2_256
            | matter::Codex::SHA2_512 => verify_digest(ked, &self.qb64()?, prefixed, &self.code()),
            // unreachable - unless someone crafed a prefixer manually this should be validated
            _ => err!(Error::UnexpectedCode(self.code())),
        }
    }

    pub fn digestive(&self) -> bool {
        const CODES: &[&str] = &[
            matter::Codex::Blake3_256,
            matter::Codex::Blake3_512,
            matter::Codex::Blake2b_256,
            matter::Codex::Blake2b_512,
            matter::Codex::Blake2s_256,
            matter::Codex::SHA3_256,
            matter::Codex::SHA3_512,
            matter::Codex::SHA2_256,
            matter::Codex::SHA2_512,
        ];

        CODES.contains(&self.code().as_str())
    }
}

impl Matter for Prefixer {
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
    use crate::{
        core::{
            common::{sizeify, versify, Ilkage, Serialage, CURRENT_VERSION},
            diger::Diger,
            matter::{tables as matter, Matter},
            prefixer::Prefixer,
            signer::Signer,
            verfer::Verfer,
        },
        data::data,
    };
    use rstest::rstest;

    #[test]
    fn convenience() {
        let code = matter::Codex::Ed25519N;
        let vkey = b"\xacr\xda\xc83~\x99r\xaf\xeb`\xc0\x8cR\xd7\xd7\xf69\xc8E\x1e\xd2\xf0=`\xf7\xbf\x8a\x18\x8a`q";
        let prefix = "BKxy2sgzfplyr-tgwIxS19f2OchFHtLwPWD3v4oYimBx";

        let verfer = Verfer::new(Some(code), Some(vkey), None, None, None).unwrap();
        let ked = data!({
            "k": [&verfer.qb64().unwrap()],
            "n": "",
            "t": "icp",
            "i": prefix
        });
        let prefixer = Prefixer::new(Some(&ked), None, Some(code), None, None, None, None).unwrap();

        assert!(Prefixer::new_with_ked(&ked, None, None).is_ok());
        assert!(Prefixer::new_with_raw(&prefixer.raw(), Some(&prefixer.code())).is_ok());
        assert!(Prefixer::new_with_qb64b(&prefixer.qb64b().unwrap()).is_ok());
        assert!(Prefixer::new_with_qb64(&prefixer.qb64().unwrap()).is_ok());
        assert!(Prefixer::new_with_qb2(&prefixer.qb2().unwrap()).is_ok());
    }

    #[rstest]
    fn new_unhappy_paths_by_values(
        #[values(b"\xacr\xda\xc83~\x99r\xaf\xeb`\xc0\x8cR\xd7\xd7\xf69\xc8E\x1e\xd2\xf0=`\xf7\xbf\x8a\x18\x8a`q")]
        _verkey: &[u8],
        #[values(
            Prefixer::new(None, None, None, None, None, None, None).is_err(),
            Prefixer::new(None, None, None, Some(_verkey), None, None, None).is_err(),
            Prefixer::new(None, None, Some(""), Some(_verkey), None, None, None).is_err(),
            Prefixer::new(
                None,
                None,
                Some(matter::Codex::Bytes_Big_L0),
                Some(_verkey),
                None,
                None,
                None
            ).is_err()
        )]
        result: bool,
    ) {
        assert!(result);
    }

    fn build_verfer(code: &str, raw: &[u8]) -> Verfer {
        Verfer::new(Some(code), Some(raw), None, None, None).unwrap()
    }

    #[rstest]
    #[case(
        None,
        &["DKxy2sgzfplyr-tgwIxS19f2OchFHtLwPWD3v4oYimBx"],
        "",
        Ilkage::icp,
        None, // this will make sure we test with no prefix at all, rather than an empty string
        None,
    )]
    // code mismatch
    #[case(
        None,
        &["DKxy2sgzfplyr-tgwIxS19f2OchFHtLwPWD3v4oYimBx"], // transferable ed25519
        "",
        Ilkage::icp,
        Some("BKxy2sgzfplyr-tgwIxS19f2OchFHtLwPWD3v4oYimBx"), // pre_n
        None,
    )]
    // code mismatch
    #[case(
        None,
        &["BKxy2sgzfplyr-tgwIxS19f2OchFHtLwPWD3v4oYimBx"], // nontransferable ed25519
        "",
        Ilkage::icp,
        Some("DKxy2sgzfplyr-tgwIxS19f2OchFHtLwPWD3v4oYimBx"), // pre
        Some(matter::Codex::Ed25519),
    )]
    // bad ilk
    #[case(
        Some("KERI10JSON000000_"),
        &["EKxy2sgzfplyr-tgwIxS19f2OchFHtLwPWD3v4oYimBx"], // blake3_256 digest
        "",
        Ilkage::ksn,
        Some(""),
        Some(matter::Codex::Blake3_256),
    )]
    // too many keys
    #[case(
        None,
        &["DKxy2sgzfplyr-tgwIxS19f2OchFHtLwPWD3v4oYimBx", "DKxy2sgzfplyr-tgwIxS19f2OchFHtLwPWD3v4oYimBx"],
        "",
        Ilkage::icp,
        Some(""),
        Some(matter::Codex::Ed25519N),
    )]
    // too many keys
    #[case(
        None,
        &["DKxy2sgzfplyr-tgwIxS19f2OchFHtLwPWD3v4oYimBx", "DKxy2sgzfplyr-tgwIxS19f2OchFHtLwPWD3v4oYimBx"],
        "",
        Ilkage::icp,
        Some(""),
        Some(matter::Codex::Ed25519),
    )]
    // no keys
    #[case(
        None,
        &[],
        "",
        Ilkage::icp,
        Some(""),
        Some(matter::Codex::Ed25519N),
    )]
    // no keys
    #[case(
        None,
        &[],
        "",
        Ilkage::icp,
        Some(""),
        Some(matter::Codex::Ed25519),
    )]
    fn new_unhappy_paths(
        #[case] version_string: Option<&str>,
        #[case] keys: &[&str],
        #[case] next_keys: &str,
        #[case] ilk: &str,
        #[case] prefix: Option<&str>,
        #[case] code: Option<&str>,
    ) {
        let mut ked = data!({});

        if let Some(version_string) = version_string {
            ked["v"] = data!(version_string);
        }
        if !keys.is_empty() {
            let mut v = vec![];
            for key in keys {
                v.push(data!(*key))
            }
            ked["k"] = data!(v.as_slice());
        }
        ked["n"] = data!(next_keys);
        ked["t"] = data!(ilk);
        if let Some(prefix) = prefix {
            ked["i"] = data!(prefix);
        }

        assert!(Prefixer::new(Some(&ked), None, code, None, None, None, None).is_err());
    }

    #[rstest]
    #[case("ABC", None, None)]
    #[case("", Some("ABC"), None)]
    #[case("", None, Some("ABC"))]
    fn new_nontransferable_unhappy_paths(
        #[case] next_key: &str,
        #[case] a: Option<&str>,
        #[case] b: Option<&str>,
        #[values(matter::Codex::Ed25519N)] code: &str,
    ) {
        let pre_n = "BKxy2sgzfplyr-tgwIxS19f2OchFHtLwPWD3v4oYimBx";
        let verkey = b"\xacr\xda\xc83~\x99r\xaf\xeb`\xc0\x8cR\xd7\xd7\xf69\xc8E\x1e\xd2\xf0=`\xf7\xbf\x8a\x18\x8a`q";

        let verfer = Verfer::new(Some(code), Some(verkey), None, None, None).unwrap();

        let mut ked = data!({
            "k": [&verfer.qb64().unwrap()],
            "n": next_key,
            "t": "icp",
            "i": pre_n,
        });
        if let Some(a) = a {
            ked["a"] = data!(a);
        }
        if let Some(b) = b {
            ked["b"] = data!(b);
        }

        assert!(Prefixer::new(Some(&ked), None, Some(code), None, None, None, None).is_err());
    }

    #[rstest]
    fn verify_unhappy_paths(#[values(matter::Codex::Ed25519N, matter::Codex::Ed25519)] code: &str) {
        let pre = "DKxy2sgzfplyr-tgwIxS19f2OchFHtLwPWD3v4oYimBx";
        let pre_n = "BKxy2sgzfplyr-tgwIxS19f2OchFHtLwPWD3v4oYimBx";

        let verkey = b"\xacr\xda\xc83~\x99r\xaf\xeb`\xc0\x8cR\xd7\xd7\xf69\xc8E\x1e\xd2\xf0=`\xf7\xbf\x8a\x18\x8a`q";
        let nxtkey = b"\xa6_\x894J\xf25T\xc1\x83#\x06\x98L\xa6\xef\x1a\xb3h\xeaA:x'\xda\x04\x88\xb2\xc4_\xf6\x00";

        // missing key
        let verfer = Verfer::new(Some(code), Some(verkey), None, None, None).unwrap();
        let mut ked = data!({
            "k": [&verfer.qb64().unwrap()],
            "n": "",
            "t": "icp",
            "i": pre_n,
        });
        let prefixer = Prefixer::new(Some(&ked), None, Some(code), None, None, None, None).unwrap();

        let mut map = ked.to_map().unwrap();
        map.remove("k");
        ked = data!(&map);

        assert!(!prefixer.verify(&ked, None).unwrap());

        // multiple keys
        let verfer = Verfer::new(Some(code), Some(verkey), None, None, None).unwrap();
        let mut ked = data!({
            "k": [&verfer.qb64().unwrap()],
            "n": "",
            "t": "icp",
            "i": pre_n,
        });
        let prefixer = Prefixer::new(Some(&ked), None, Some(code), None, None, None, None).unwrap();

        ked["k"] = data!([&verfer.qb64().unwrap(), &verfer.qb64().unwrap()]);

        assert!(!prefixer.verify(&ked, None).unwrap());

        // key != prefix
        let verfer = Verfer::new(Some(code), Some(verkey), None, None, None).unwrap();
        let mut ked = data!({
            "k": [&verfer.qb64().unwrap()],
            "n": "",
            "t": "icp",
            "i": pre,
        });
        let prefixer = Prefixer::new(Some(&ked), None, Some(code), None, None, None, None).unwrap();

        ked["k"] = data!(["ABC"]);

        assert!(!prefixer.verify(&ked, None).unwrap());

        // bad key (doesn't match)
        let verfer = Verfer::new(Some(code), Some(verkey), None, None, None).unwrap();
        let mut ked = data!({
            "k": [&verfer.qb64().unwrap()],
            "n": "",
            "t": "icp",
            "i": pre_n,
        });
        let prefixer = Prefixer::new(Some(&ked), None, Some(code), None, None, None, None).unwrap();

        let nxtfer = Verfer::new(Some(code), Some(nxtkey), None, None, None).unwrap();
        ked["k"] = data!([&nxtfer.qb64().unwrap()]);

        assert!(!prefixer.verify(&ked, None).unwrap());

        // non-incepting
        let verfer = Verfer::new(Some(code), Some(verkey), None, None, None).unwrap();
        let mut ked = data!({
            "k": [&verfer.qb64().unwrap()],
            "n": "",
            "t": "icp",
            "i": pre_n,
        });
        let prefixer = Prefixer::new(Some(&ked), None, Some(code), None, None, None, None).unwrap();

        ked["t"] = data!("ksn");

        assert!(prefixer.verify(&ked, None).is_err());
    }

    #[test]
    fn verify_unhappy_non_transferable() {
        let pre_n = "BKxy2sgzfplyr-tgwIxS19f2OchFHtLwPWD3v4oYimBx";
        let verkey = b"\xacr\xda\xc83~\x99r\xaf\xeb`\xc0\x8cR\xd7\xd7\xf69\xc8E\x1e\xd2\xf0=`\xf7\xbf\x8a\x18\x8a`q";

        // next keys present, non-transferable
        let verfer =
            Verfer::new(Some(matter::Codex::Ed25519N), Some(verkey), None, None, None).unwrap();
        let mut ked = data!({
            "k": [&verfer.qb64().unwrap()],
            "n": "",
            "t": "icp",
            "i": pre_n,
        });
        let prefixer =
            Prefixer::new(Some(&ked), None, Some(matter::Codex::Ed25519N), None, None, None, None)
                .unwrap();

        ked["n"] = data!([&verfer.qb64().unwrap()]);

        assert!(!prefixer.verify(&ked, None).unwrap());
    }

    #[rstest]
    #[case(matter::Codex::Ed25519N, b"\xacr\xda\xc83~\x99r\xaf\xeb`\xc0\x8cR\xd7\xd7\xf69\xc8E\x1e\xd2\xf0=`\xf7\xbf\x8a\x18\x8a`q")]
    #[case(matter::Codex::Ed25519, b"\xacr\xda\xc83~\x99r\xaf\xeb`\xc0\x8cR\xd7\xd7\xf69\xc8E\x1e\xd2\xf0=`\xf7\xbf\x8a\x18\x8a`q")]
    #[case(matter::Codex::ECDSA_256k1N, b"\x03\xff\x76\x8f\xb2\xb8\x37\x13\x46\x02\xe4\x85\xf5\x1d\x4e\x6f\x2f\xd5\x68\xed\xe6\xbb\x7c\xc3\xc3\x70\x4e\xfd\x1c\xfd\xa0\x7c\x92")]
    #[case(matter::Codex::ECDSA_256k1, b"\x03\xff\x76\x8f\xb2\xb8\x37\x13\x46\x02\xe4\x85\xf5\x1d\x4e\x6f\x2f\xd5\x68\xed\xe6\xbb\x7c\xc3\xc3\x70\x4e\xfd\x1c\xfd\xa0\x7c\x92")]
    fn code(
        #[case] _code: &str,
        #[case] _verkey: &[u8],
        #[values(Prefixer::new(
            None,
            None,
            Some(_code),
            Some(_verkey),
            None,
            None,
            None,
        )
        .unwrap())]
        prefixer: Prefixer,
    ) {
        assert_eq!(prefixer.code(), _code);
    }

    #[rstest]
    #[case(
        matter::Codex::Ed25519N,
        b"\xacr\xda\xc83~\x99r\xaf\xeb`\xc0\x8cR\xd7\xd7\xf69\xc8E\x1e\xd2\xf0=`\xf7\xbf\x8a\x18\x8a`q",
        "", true, false
    )]
    #[case(
        matter::Codex::Ed25519N,
        b"\xacr\xda\xc83~\x99r\xaf\xeb`\xc0\x8cR\xd7\xd7\xf69\xc8E\x1e\xd2\xf0=`\xf7\xbf\x8a\x18\x8a`q",
        "ABC", false, false
    )]
    #[case(
        matter::Codex::Ed25519,
        b"\xacr\xda\xc83~\x99r\xaf\xeb`\xc0\x8cR\xd7\xd7\xf69\xc8E\x1e\xd2\xf0=`\xf7\xbf\x8a\x18\x8a`q",
        "", true, false
    )]
    #[case(
        matter::Codex::Ed25519,
        b"\xacr\xda\xc83~\x99r\xaf\xeb`\xc0\x8cR\xd7\xd7\xf69\xc8E\x1e\xd2\xf0=`\xf7\xbf\x8a\x18\x8a`q",
        "ABC", true, false
    )]
    #[case(
        matter::Codex::ECDSA_256k1N,
        b"\x03\xff\x76\x8f\xb2\xb8\x37\x13\x46\x02\xe4\x85\xf5\x1d\x4e\x6f\x2f\xd5\x68\xed\xe6\xbb\x7c\xc3\xc3\x70\x4e\xfd\x1c\xfd\xa0\x7c\x92",
        "", true, false
    )]
    #[case(
        matter::Codex::ECDSA_256k1N,
        b"\x03\xff\x76\x8f\xb2\xb8\x37\x13\x46\x02\xe4\x85\xf5\x1d\x4e\x6f\x2f\xd5\x68\xed\xe6\xbb\x7c\xc3\xc3\x70\x4e\xfd\x1c\xfd\xa0\x7c\x92",
        "ABC", false, false
    )]
    #[case(
        matter::Codex::ECDSA_256k1,
        b"\x03\xff\x76\x8f\xb2\xb8\x37\x13\x46\x02\xe4\x85\xf5\x1d\x4e\x6f\x2f\xd5\x68\xed\xe6\xbb\x7c\xc3\xc3\x70\x4e\xfd\x1c\xfd\xa0\x7c\x92",
        "", true, false
    )]
    #[case(
        matter::Codex::ECDSA_256k1,
        b"\x03\xff\x76\x8f\xb2\xb8\x37\x13\x46\x02\xe4\x85\xf5\x1d\x4e\x6f\x2f\xd5\x68\xed\xe6\xbb\x7c\xc3\xc3\x70\x4e\xfd\x1c\xfd\xa0\x7c\x92",
        "ABC", true, false
    )]
    fn verification_basic(
        #[case] code: &str,
        #[case] raw: &[u8],
        #[case] n: &str,
        #[case] unprefixed_result: bool,
        #[case] prefixed_result: bool,
    ) {
        let prefixer = Prefixer::new(None, None, Some(code), Some(raw), None, None, None).unwrap();
        let ked = data!({
            "k": [&prefixer.qb64().unwrap()],
            "n": n,
            "t": "icp"
        });

        assert_eq!(prefixer.verify(&ked, None).unwrap(), unprefixed_result);
        assert_eq!(prefixer.verify(&ked, Some(true)).unwrap(), prefixed_result);
    }

    #[rstest]
    #[case(
        matter::Codex::Ed25519N,
        b"\xacr\xda\xc83~\x99r\xaf\xeb`\xc0\x8cR\xd7\xd7\xf69\xc8E\x1e\xd2\xf0=`\xf7\xbf\x8a\x18\x8a`q",
        true, false
    )]
    #[case(
        matter::Codex::Ed25519,
        b"\xacr\xda\xc83~\x99r\xaf\xeb`\xc0\x8cR\xd7\xd7\xf69\xc8E\x1e\xd2\xf0=`\xf7\xbf\x8a\x18\x8a`q",
        true, false
    )]
    #[case(
        matter::Codex::ECDSA_256k1N,
        b"\x03\xff\x76\x8f\xb2\xb8\x37\x13\x46\x02\xe4\x85\xf5\x1d\x4e\x6f\x2f\xd5\x68\xed\xe6\xbb\x7c\xc3\xc3\x70\x4e\xfd\x1c\xfd\xa0\x7c\x92",
        true, false
    )]
    #[case(
        matter::Codex::ECDSA_256k1,
        b"\x03\xff\x76\x8f\xb2\xb8\x37\x13\x46\x02\xe4\x85\xf5\x1d\x4e\x6f\x2f\xd5\x68\xed\xe6\xbb\x7c\xc3\xc3\x70\x4e\xfd\x1c\xfd\xa0\x7c\x92",
        true, false
    )]
    fn verification(
        #[case] code: &str,
        #[case] raw: &[u8],
        #[case] unprefixed_result: bool,
        #[case] prefixed_result: bool,
    ) {
        let prefixer = Prefixer::new(None, None, Some(code), Some(raw), None, None, None).unwrap();
        let ked = data!({
            "k": [&prefixer.qb64().unwrap()],
            "t": "icp"
        });

        assert_eq!(prefixer.verify(&ked, None).unwrap(), unprefixed_result);
        assert_eq!(prefixer.verify(&ked, Some(true)).unwrap(), prefixed_result);
    }

    #[rstest]
    #[case(
        matter::Codex::Ed25519,
        b"\xacr\xda\xc83~\x99r\xaf\xeb`\xc0\x8cR\xd7\xd7\xf69\xc8E\x1e\xd2\xf0=`\xf7\xbf\x8a\x18\x8a`q",
        matter::Codex::Ed25519,
        true, false
    )]
    fn verification_verfer_no_prefix(
        #[case] vcode: &str,
        #[case] vkey: &[u8],
        #[case] code: &str,
        #[case] unprefixed_result: bool,
        #[case] prefixed_result: bool,
    ) {
        let verfer = Verfer::new(Some(vcode), Some(vkey), None, None, None).unwrap();
        let ked = data!({
            "k": [&verfer.qb64().unwrap()],
            "n": "",
            "t": "icp"
        });
        let prefixer = Prefixer::new(Some(&ked), None, Some(code), None, None, None, None).unwrap();
        assert_eq!(prefixer.qb64().unwrap(), verfer.qb64().unwrap());
        assert_eq!(prefixer.verify(&ked, None).unwrap(), unprefixed_result);
        assert_eq!(prefixer.verify(&ked, Some(true)).unwrap(), prefixed_result);
    }

    #[rstest]
    #[case(
        matter::Codex::Ed25519N,
        b"\xacr\xda\xc83~\x99r\xaf\xeb`\xc0\x8cR\xd7\xd7\xf69\xc8E\x1e\xd2\xf0=`\xf7\xbf\x8a\x18\x8a`q",
        matter::Codex::Ed25519N,
        "DKxy2sgzfplyr-tgwIxS19f2OchFHtLwPWD3v4oYimBx",
        true, false
    )]
    #[case(
        matter::Codex::Ed25519N,
        b"\xacr\xda\xc83~\x99r\xaf\xeb`\xc0\x8cR\xd7\xd7\xf69\xc8E\x1e\xd2\xf0=`\xf7\xbf\x8a\x18\x8a`q",
        matter::Codex::Ed25519N,
        "BKxy2sgzfplyr-tgwIxS19f2OchFHtLwPWD3v4oYimBx",
        true, true
    )]
    fn verification_verfer(
        #[case] vcode: &str,
        #[case] vkey: &[u8],
        #[case] code: &str,
        #[case] prefix: &str,
        #[case] unprefixed_result: bool,
        #[case] prefixed_result: bool,
    ) {
        let verfer = Verfer::new(Some(vcode), Some(vkey), None, None, None).unwrap();
        let ked = data!({
            "k": [&verfer.qb64().unwrap()],
            "n": "",
            "t": "icp",
            "i": prefix
        });
        let prefixer = Prefixer::new(Some(&ked), None, Some(code), None, None, None, None).unwrap();
        assert_eq!(prefixer.qb64().unwrap(), verfer.qb64().unwrap());
        assert_eq!(prefixer.verify(&ked, None).unwrap(), unprefixed_result);
        assert_eq!(prefixer.verify(&ked, Some(true)).unwrap(), prefixed_result);
    }

    #[rstest]
    fn digests(
        #[values(
            matter::Codex::Blake3_256,
            matter::Codex::Blake3_512,
            matter::Codex::Blake2b_256,
            matter::Codex::Blake2b_512,
            matter::Codex::Blake2s_256,
            matter::Codex::SHA3_256,
            matter::Codex::SHA3_512,
            matter::Codex::SHA2_256,
            matter::Codex::SHA2_512
        )]
        code: &str,
    ) {
        let diger = Diger::new(Some(b""), Some(code), None, None, None, None).unwrap();
        let vs = versify(None, Some(CURRENT_VERSION), Some(Serialage::JSON), Some(0)).unwrap();
        let ked = data!({
            "v": &vs,
            "k": [&diger.qb64().unwrap()],
            "n": "",
            "t": "icp",
        });
        let result = sizeify(&ked, None).unwrap();

        let prefixer =
            Prefixer::new(Some(&result.ked), None, Some(code), None, None, None, None).unwrap();
        assert!(prefixer.verify(&result.ked, None).unwrap());
        assert!(!prefixer.verify(&result.ked, Some(true)).unwrap());
    }

    #[rstest]
    fn digests_prefixed(
        #[values(
            matter::Codex::Blake3_256,
            matter::Codex::Blake3_512,
            matter::Codex::Blake2b_256,
            matter::Codex::Blake2b_512,
            matter::Codex::Blake2s_256,
            matter::Codex::SHA3_256,
            matter::Codex::SHA3_512,
            matter::Codex::SHA2_256,
            matter::Codex::SHA2_512
        )]
        code: &str,
    ) {
        let diger = Diger::new(Some(b""), Some(code), None, None, None, None).unwrap();
        let vs = versify(None, Some(CURRENT_VERSION), Some(Serialage::JSON), Some(0)).unwrap();
        let ked = data!({
            "v": &vs,
            "k": [&diger.qb64().unwrap()],
            "n": "",
            "t": "icp",
            "i": "",
            "d": ""
        });
        let result = sizeify(&ked, None).unwrap();
        let mut ked = result.ked;
        let prefixer = Prefixer::new(Some(&ked), None, Some(code), None, None, None, None).unwrap();

        assert!(prefixer.verify(&ked, None).unwrap());
        assert!(!prefixer.verify(&ked, Some(true)).unwrap());

        ked["i"] = data!(&prefixer.qb64().unwrap());
        ked["d"] = data!(&prefixer.qb64().unwrap());

        assert!(prefixer.verify(&ked, None).unwrap());
        assert!(prefixer.verify(&ked, Some(true)).unwrap());
    }

    #[test]
    fn python_interop() {
        let pre_n = "BKxy2sgzfplyr-tgwIxS19f2OchFHtLwPWD3v4oYimBx";

        let verkey = b"\xacr\xda\xc83~\x99r\xaf\xeb`\xc0\x8cR\xd7\xd7\xf69\xc8E\x1e\xd2\xf0=`\xf7\xbf\x8a\x18\x8a`q";
        let verfer = Verfer::new(None, Some(verkey), None, None, None).unwrap();

        assert_eq!(verfer.qb64().unwrap(), pre_n);

        let nxtkey = b"\xa6_\x894J\xf25T\xc1\x83#\x06\x98L\xa6\xef\x1a\xb3h\xeaA:x'\xda\x04\x88\xb2\xc4_\xf6\x00";
        let nxtfer =
            Verfer::new(Some(matter::Codex::Ed25519), Some(nxtkey), None, None, None).unwrap();

        assert_eq!(nxtfer.qb64().unwrap(), "DKZfiTRK8jVUwYMjBphMpu8as2jqQTp4J9oEiLLEX_YA");

        let vs = versify(None, Some(CURRENT_VERSION), Some(Serialage::JSON), Some(0)).unwrap();
        let sn = "0"; // hex string
        let ilk = Ilkage::icp;
        let sith = "1";
        let keys = data!([&Prefixer::new(
            None,
            None,
            Some(matter::Codex::Ed25519),
            Some(verkey),
            None,
            None,
            None
        )
        .unwrap()
        .qb64()
        .unwrap()]);
        let nxt = "";
        let toad = "0"; // hex string
        let wits = data!([]);
        let cnfg = data!([]);

        let ked = data!({
            "v": &vs,
            "i": "",
            "s": sn,
            "t": ilk,
            "kt": sith,
            "k": keys.clone(),
            "n": nxt,
            "wt": toad,
            "w": wits.clone(),
            "c": cnfg.clone()
        });

        let prefixer = Prefixer::new(
            Some(&ked),
            None,
            Some(matter::Codex::Blake3_256),
            None,
            None,
            None,
            None,
        )
        .unwrap();
        assert_eq!(prefixer.qb64().unwrap(), "ELEjyRTtmfyp4VpTBTkv_b6KONMS1V8-EW-aGJ5P_QMo");
        assert!(prefixer.verify(&ked, None).unwrap());
        assert!(!prefixer.verify(&ked, Some(true)).unwrap());

        let n_digs =
            data!([&Diger::new(Some(&nxtfer.qb64b().unwrap()), None, None, None, None, None)
                .unwrap()
                .qb64()
                .unwrap()]);
        let ked = data!({
            "v": &vs,
            "i": "",
            "s": sn,
            "t": ilk,
            "kt": sith,
            "k": keys.clone(),
            "n": n_digs,
            "wt": toad,
            "w": wits.clone(),
            "c": cnfg.clone()
        });

        let prefixer = Prefixer::new(
            Some(&ked),
            None,
            Some(matter::Codex::Blake3_256),
            None,
            None,
            None,
            None,
        )
        .unwrap();
        assert_eq!(prefixer.qb64().unwrap(), "EHZUmVPq9cXFvGwWP4ohwA27XlsWHBxxu4xFiXp8UOol");
        assert!(prefixer.verify(&ked, None).unwrap());
        assert!(!prefixer.verify(&ked, Some(true)).unwrap());

        // python code used this salt and derivation:
        // salt = b"g\x15\x89\x1a@\xa4\xa47\x07\xb9Q\xb8\x18\xcdJW"
        // secrets = generateSecrets(salt=salt,  count=8)

        // test with fractionally weighted sith
        let secrets = [
            "AK8F6AAiYDpXlWdj2O5F5-6wNCCNJh2A4XOlqwR_HwwH",
            "AOs8-zNPPh0EhavdrCfCiTk9nGeO8e6VxUCzwdKXJAd0",
            "AHMBU5PsIJN2U9m7j0SGyvs8YD8fkym2noELzxIrzfdG",
            "AJZ7ZLd7unQ4IkMUwE69NXcvDO9rrmmRH_Xk3TPu9BpP",
            "ANfkMQ5LKPfjEdQPK2c_zWsOn4GgLWsnWvIa25EVVbtR",
            "ACrmDHtPQjnM8H9pyKA-QBNdfZ-xixTlRZTS8WXCrrMH",
            "AMRXyU3ErhBNdRSDX1zKlrbZGRp1GfCmkRIa58gF07I8",
            "AC6vsNVCpHa6acGcxk7c-D1mBHlptPrAx8zr-bKvesSW",
        ];

        let mut signers: Vec<Signer> = vec![];
        for secret in secrets {
            signers.push(Signer::new(None, None, None, None, Some(secret), None).unwrap());
        }

        for i in 0..secrets.len() {
            assert_eq!(secrets[i], signers[i].qb64().unwrap());
        }

        let keys = data!([
            &signers[0].verfer().qb64().unwrap(),
            &signers[1].verfer().qb64().unwrap(),
            &signers[2].verfer().qb64().unwrap(),
        ]);
        let sith = data!([["1/2", "1/2", "1"]]);
        let n_dig =
            Diger::new(Some(&signers[3].verfer().qb64b().unwrap()), None, None, None, None, None)
                .unwrap()
                .qb64()
                .unwrap();
        let n_digs = data!([&n_dig]);
        let ked = data!({
            "v": &vs,
            "i": "",
            "s": sn,
            "t": ilk,
            "kt": sith,
            "k": keys.clone(),
            "n": n_digs.clone(),
            "wt": toad,
            "w": wits.clone(),
            "c": cnfg.clone()
        });

        let prefixer = Prefixer::new(
            Some(&ked),
            None,
            Some(matter::Codex::Blake3_256),
            None,
            None,
            None,
            None,
        )
        .unwrap();
        assert_eq!(prefixer.qb64().unwrap(), "EBfPkd-A2CQfJmfpmtc1V-yuleSeCcyWBIrTAygUgQ_T");
        assert!(prefixer.verify(&ked, None).unwrap());
        assert!(!prefixer.verify(&ked, Some(true)).unwrap());

        let sith = data!([["1/2", "1/2"], ["1"]]);
        let ked = data!({
            "v": &vs,
            "i": "",
            "s": sn,
            "t": ilk,
            "kt": sith,
            "k": keys.clone(),
            "n": n_digs.clone(),
            "wt": toad,
            "w": wits.clone(),
            "c": cnfg.clone()
        });
        let prefixer2 = Prefixer::new(
            Some(&ked),
            None,
            Some(matter::Codex::Blake3_256),
            None,
            None,
            None,
            None,
        )
        .unwrap();
        assert_eq!(prefixer2.qb64().unwrap(), "EB0_D51cTh_q6uOQ-byFiv5oNXZ-cxdqCqBAa4JmBLtb");
        assert!(prefixer2.verify(&ked, None).unwrap());
        assert!(!prefixer.verify(&ked, Some(true)).unwrap());

        let sith = "1";
        let seal = data!({
            "i": "EBfPkd-A2CQfJmfpmtc1V-yuleSeCcyWBIrTAygUgQ_T",
            "s": "2",
            "t": Ilkage::ixn,
            "d": "EB0_D51cTh_q6uOQ-byFiv5oNXZ-cxdqCqBAa4JmBLtb"
        });
        let ilk2 = Ilkage::dip;
        let ked = data!({
            "v": &vs,
            "i": "",
            "s": sn,
            "t": ilk2,
            "kt": sith,
            "k": keys.clone(),
            "n": n_digs.clone(),
            "wt": toad,
            "w": wits.clone(),
            "c": cnfg.clone(),
            "da": seal
        });

        let prefixer = Prefixer::new(
            Some(&ked),
            None,
            Some(matter::Codex::Blake3_256),
            None,
            None,
            None,
            None,
        )
        .unwrap();
        assert_eq!(prefixer.qb64().unwrap(), "EBabiu_JCkE0GbiglDXNB5C4NQq-hiGgxhHKXBxkiojg");
        assert!(prefixer.verify(&ked, None).unwrap());
        assert!(!prefixer.verify(&ked, Some(true)).unwrap());

        assert!(Prefixer::new(
            Some(&ked),
            Some(&[matter::Codex::Ed25519, matter::Codex::Ed25519N]),
            Some(matter::Codex::Blake3_256),
            None,
            None,
            None,
            None
        )
        .is_err());

        let prefixer = Prefixer::new(
            Some(&ked),
            Some(&[matter::Codex::Blake3_256, matter::Codex::Ed25519]),
            Some(matter::Codex::Blake3_256),
            None,
            None,
            None,
            None,
        )
        .unwrap();
        assert_eq!(prefixer.qb64().unwrap(), "EBabiu_JCkE0GbiglDXNB5C4NQq-hiGgxhHKXBxkiojg");
        assert!(prefixer.verify(&ked, None).unwrap());
        assert!(!prefixer.verify(&ked, Some(true)).unwrap());
    }
}
