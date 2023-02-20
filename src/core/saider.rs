use crate::core::common::{deversify, dumps, sizeify, Ids, Serialage, DUMMY};
use crate::core::matter::{tables as matter, Matter};
use crate::crypto::hash;
use crate::data::{data, Value};
use crate::error::{err, Error, Result};

#[derive(Debug, Clone, PartialEq)]
pub struct Saider {
    pub raw: Vec<u8>,
    pub code: String,
    pub size: u32,
}

impl Default for Saider {
    fn default() -> Self {
        Saider { raw: vec![], code: matter::Codex::Blake3_256.to_string(), size: 0 }
    }
}

fn validate_code(code: &str) -> Result<()> {
    const CODES: &[&str] = &[
        matter::Codex::Blake3_256,
        matter::Codex::Blake2b_256,
        matter::Codex::Blake2s_256,
        matter::Codex::SHA3_256,
        matter::Codex::SHA2_256,
        matter::Codex::Blake3_512,
        matter::Codex::Blake2b_512,
        matter::Codex::SHA3_512,
        matter::Codex::SHA2_512,
    ];

    if !CODES.contains(&code) {
        return err!(Error::UnexpectedCode(code.to_string()));
    }

    Ok(())
}

fn serialize(sad: &Value, kind: Option<&str>) -> Result<Vec<u8>> {
    let knd = if sad.to_map()?.contains_key("v") {
        let result = deversify(&sad["v"].to_string()?)?;
        result.kind
    } else {
        Serialage::JSON.to_string()
    };
    let kind = if let Some(kind) = kind { Some(kind) } else { Some(knd.as_str()) };
    dumps(sad, kind)
}

fn derive(
    sad: &Value,
    code: Option<&str>,
    kind: Option<&str>,
    label: Option<&str>,
    ignore: Option<&[&str]>,
) -> Result<(Vec<u8>, Value)> {
    let label = label.unwrap_or(Ids::d);
    let code = code.unwrap_or(matter::Codex::Blake3_256);

    validate_code(code)?;

    let szg = matter::sizage(code)?;
    let mut sad = sad.clone();

    sad[label] = data!(&String::from_utf8(vec![DUMMY; szg.fs as usize])?);

    let (kind, sad) = if sad.to_map()?.contains_key("v") {
        let result = sizeify(&sad, kind)?;
        (Some(result.kind), result.ked)
    } else {
        let kind = kind.map(|kind| kind.to_string());
        (kind, sad)
    };

    let mut map = sad.to_map()?;
    for key in ignore.unwrap_or(&[]) {
        if map.contains_key(*key) {
            map.remove(*key);
        }
    }
    let ser = data!(&map);

    let cpa =
        if let Some(kind) = kind { serialize(&ser, Some(&kind))? } else { serialize(&ser, None)? };
    let digest = hash::digest(code, &cpa)?;

    Ok((digest, sad))
}

impl Saider {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sad: Option<&Value>,
        label: Option<&str>,
        kind: Option<&str>,
        ignore: Option<&[&str]>,
        code: Option<&str>,
        raw: Option<&[u8]>,
        qb64b: Option<&[u8]>,
        qb64: Option<&str>,
        qb2: Option<&[u8]>,
    ) -> Result<Self> {
        if raw.is_some() || sad.is_some() {
            let label = label.unwrap_or(Ids::d);
            let (code, raw) = if code.is_none() || raw.is_none() {
                let code = if let Some(sad) = sad {
                    let map = sad.to_map()?;
                    if !map.contains_key(label) {
                        return err!(Error::Value(format!(
                            "cannot find label {label} in sad, code or raw is empty"
                        )));
                    }

                    if let Some(code) = code {
                        // raw must be empty
                        code.to_string()
                    } else if sad[label].to_string().is_err() {
                        return err!(Error::Validation(format!(
                            "label {label} present but value not a string"
                        )));
                    } else if sad[label].to_string()?.is_empty() {
                        matter::Codex::Blake3_256.to_string()
                    } else {
                        <Saider as Matter>::new(
                            None,
                            None,
                            None,
                            Some(&sad[label].to_string()?),
                            None,
                        )?
                        .code()
                    }
                } else {
                    return err!(Error::Validation(
                        "sad or raw and code must be present".to_string()
                    ));
                };

                validate_code(&code)?;

                let sad = if let Some(sad) = sad { sad.clone() } else { data!({}) };
                let (raw, _) = derive(&sad, Some(&code), kind, Some(label), ignore)?;

                (code, raw)
            } else if let Some(code) = code {
                validate_code(code)?;
                if let Some(raw) = raw {
                    (code.to_string(), raw.to_vec())
                } else {
                    // unreachable because we have validated that raw is some above.
                    unreachable!();
                }
            } else {
                // unreachable because we have validated that code is some above.
                unreachable!();
            };

            Matter::new(Some(&code), Some(&raw), None, None, None)
        } else {
            let saider: Saider = Matter::new(code, raw, qb64b, qb64, qb2)?;
            validate_code(&saider.code())?;
            Ok(saider)
        }
    }

    pub fn saidify(
        sad: &Value,
        code: Option<&str>,
        kind: Option<&str>,
        label: Option<&str>,
        ignore: Option<&[&str]>,
    ) -> Result<(Saider, Value)> {
        let code = code.unwrap_or(matter::Codex::Blake3_256);
        let label = label.unwrap_or(Ids::d);

        if !sad.to_map()?.contains_key(label) {
            return err!(Error::Validation(format!("missing id field labelled={label}")));
        }

        let (_, sad) = derive(sad, Some(code), kind, Some(label), ignore)?;
        let saider =
            Self::new(Some(&sad), Some(label), kind, ignore, Some(code), None, None, None, None)?;
        let mut sad = sad;
        sad[label] = data!(&saider.qb64()?);

        Ok((saider, sad))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        &self,
        sad: &Value,
        prefixed: Option<bool>,
        versioned: Option<bool>,
        kind: Option<&str>,
        label: Option<&str>,
        ignore: Option<&[&str]>,
    ) -> Result<bool> {
        let label = label.unwrap_or(Ids::d);
        let prefixed = prefixed.unwrap_or(false);
        let versioned = versioned.unwrap_or(true);

        let (raw, dsad) = match derive(sad, Some(&self.code()), kind, Some(label), ignore) {
            Ok(r) => r,
            Err(_) => return Ok(false),
        };

        let saider = match Self::new(
            None,
            None,
            None,
            None,
            Some(&self.code()),
            Some(&raw),
            None,
            None,
            None,
        ) {
            Ok(s) => s,
            // should be unreachable
            Err(_) => return Ok(false),
        };

        if self.qb64()? != saider.qb64()? {
            return Ok(false);
        }

        if versioned
            && sad.to_map()?.contains_key("v")
            && sad["v"].to_string()? != dsad["v"].to_string()?
        {
            return Ok(false);
        }

        if prefixed && sad[label].to_string()? != self.qb64()? {
            return Ok(false);
        }

        Ok(true)
    }

    pub fn new_with_sad(
        sad: &Value,
        label: Option<&str>,
        kind: Option<&str>,
        ignore: Option<&[&str]>,
        code: Option<&str>,
    ) -> Result<Self> {
        Self::new(Some(sad), label, kind, ignore, code, None, None, None, None)
    }

    pub fn new_with_raw(raw: &[u8], code: Option<&str>) -> Result<Self> {
        Self::new(None, None, None, None, code, Some(raw), None, None, None)
    }

    pub fn new_with_qb64b(qb64b: &[u8]) -> Result<Self> {
        Self::new(None, None, None, None, None, None, Some(qb64b), None, None)
    }

    pub fn new_with_qb64(qb64: &str) -> Result<Self> {
        Self::new(None, None, None, None, None, None, None, Some(qb64), None)
    }

    pub fn new_with_qb2(qb2: &[u8]) -> Result<Self> {
        Self::new(None, None, None, None, None, None, None, None, Some(qb2))
    }
}

impl Matter for Saider {
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
    use super::{derive, validate_code};
    use crate::core::common::{versify, Identage, Ids, Serialage, Version};
    use crate::core::matter::{tables as matter, Matter};
    use crate::core::saider::Saider;
    use crate::data::data;
    use rstest::rstest;

    #[test]
    fn convenience() {
        let sad = data!({"d":""});

        let saider =
            Saider::new(Some(&sad), None, None, None, None, None, None, None, None).unwrap();

        assert!(Saider::new_with_sad(&sad, None, None, None, None).is_ok());
        assert!(Saider::new_with_raw(&saider.raw(), Some(&saider.code())).is_ok());
        assert!(Saider::new_with_qb64b(&saider.qb64b().unwrap()).is_ok());
        assert!(Saider::new_with_qb64(&saider.qb64().unwrap()).is_ok());
        assert!(Saider::new_with_qb2(&saider.qb2().unwrap()).is_ok());
    }

    #[test]
    fn new() {
        let saider = Saider::new(
            Some(&data!({"d":""})),
            Some(Ids::d),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();

        assert!(Saider::new(
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(&saider.qb64().unwrap()),
            None
        )
        .is_ok());
    }

    #[rstest]
    #[case(matter::Codex::Blake3_256, "EBG9LuUbFzV4OV5cGS9IeQWzy9SuyVFyVrpRc4l1xzPA")]
    #[case(matter::Codex::Blake2b_256, "FG1_1lgNJ69QPnJK-pD5s8cinFFYhnGN8nuyz8Mdrezg")]
    fn new_with_qb64(#[case] code: &str, #[case] said: &str) {
        // Test with valid said qb64
        let saider =
            Saider::new(None, None, None, None, None, None, None, Some(said), None).unwrap();
        assert_eq!(saider.code(), code);
        assert_eq!(saider.qb64().unwrap(), said);
    }

    #[rstest]
    #[case("EMRvS7lGxc1eDleXBkvSHkFs8vUrslRcla6UXOJdcczw", None, None, Some(Ids::dollar))]
    #[case(
        "EMRvS7lGxc1eDleXBkvSHkFs8vUrslRcla6UXOJdcczw",
        Some(matter::Codex::Blake3_256),
        None,
        Some(Ids::dollar)
    )]
    #[case(
        "EMRvS7lGxc1eDleXBkvSHkFs8vUrslRcla6UXOJdcczw",
        None,
        Some(Serialage::JSON),
        Some(Ids::dollar)
    )]
    #[case(
        "EMRvS7lGxc1eDleXBkvSHkFs8vUrslRcla6UXOJdcczw",
        Some(matter::Codex::Blake3_256),
        Some(Serialage::JSON),
        Some(Ids::dollar)
    )]
    #[case(
        "FFtf9ZYDSevUD5ySvqQ-bPHIpxRWIZxjfJ7ss_DHa3s4",
        Some(matter::Codex::Blake2b_256),
        None,
        Some(Ids::dollar)
    )]
    fn basic(
        #[case] said: &str,
        #[case] code: Option<&str>,
        #[case] kind: Option<&str>,
        #[case] label: Option<&str>,
    ) {
        let sad1 = data!({
            "$id": "",
            "$schema": "http://json-schema.org/draft-07/schema#",
            "type": "object",
            "properties": {
                "a": {"type":"string"},
                "b": {"type":"number"},
                "c": {"type":"string","format":"date-time"}
            }
        });

        let (saider, _) = Saider::saidify(&sad1, code, kind, label, None).unwrap();
        assert_eq!(saider.qb64().unwrap(), said);

        let sad2 = data!({
            "$id": said,
            "$schema": "http://json-schema.org/draft-07/schema#",
            "type": "object",
            "properties": {
                "a": {"type":"string"},
                "b": {"type":"number"},
                "c": {"type":"string","format":"date-time"}
            }
        });

        assert!(saider.verify(&sad2, Some(true), None, None, label, None).unwrap());
        assert!(saider.verify(&sad1, Some(false), None, None, label, None).unwrap());
        assert!(!saider.verify(&sad1, Some(true), None, None, label, None).unwrap());
    }

    #[test]
    fn keri() {
        // test with default id field label Ids.d == 'd' and contains 'v' field
        let label = Ids::d;
        let code = matter::Codex::Blake3_256;

        let vs = versify(
            Some(Identage::KERI),
            Some(&Version { major: 1, minor: 0 }),
            Some(Serialage::JSON),
            Some(0),
        )
        .unwrap();
        assert_eq!(vs, "KERI10JSON000000_");
        let sad6 = data!({
            "v": &vs,
            "t": "rep",
            "d": "",
            "dt": "2020-08-22T17:50:12.988921+00:00",
            "r": "logs/processor",
            "a": {
                "d":"EBabiu_JCkE0GbiglDXNB5C4NQq-hiGgxhHKXBxkiojg",
                "i":"EB0_D51cTh_q6uOQ-byFiv5oNXZ-cxdqCqBAa4JmBLtb",
                "name":"John Jones",
                "role":"Founder",
            },
        });
        let saider =
            Saider::new(Some(&sad6), Some(label), None, None, Some(code), None, None, None, None)
                .unwrap();
        assert_eq!(saider.code(), code);
        assert_eq!(saider.qb64().unwrap(), "ELzewBpZHSENRP-sL_G_2Ji4YDdNkns9AzFzufleJqdw");
        assert!(saider.verify(&sad6, Some(false), Some(false), None, None, None).unwrap());
        assert!(!saider.verify(&sad6, Some(false), None, None, None, None).unwrap());
        assert!(!saider.verify(&sad6, Some(true), Some(false), None, None, None).unwrap());

        let mut sad7 = sad6.clone();
        sad7[label] = data!(&saider.qb64().unwrap());
        assert!(saider.verify(&sad7, Some(true), Some(false), None, None, None).unwrap());

        let mut sad8 = sad7.clone();
        let (_, dsad) = derive(&sad6, Some(code), None, Some(label), None).unwrap();
        sad8["v"] = data!(&dsad["v"].to_string().unwrap());
        assert!(saider.verify(&sad8, Some(true), None, None, None, None).unwrap());

        // let said8 = saider.qb64().unwrap();

        let sad9 = data!({
            "d": "",
            "first": "John",
            "last": "Doe",
            "read": false
        });

        let saider = Saider::new(
            Some(&sad9),
            None,
            None,
            Some(&vec!["read"]),
            Some(code),
            None,
            None,
            None,
            None,
        )
        .unwrap();
        let said9 = "EBam6rzvfq0yF6eI7Czrg3dUVhqg2cwNkSoJvyHWPj3p";
        assert_eq!(saider.qb64().unwrap(), said9);

        let (saider1, mut sad10) =
            Saider::saidify(&sad9, Some(code), None, Some(Ids::d), Some(&vec!["read"])).unwrap();
        assert_eq!(saider.qb64().unwrap(), saider1.qb64().unwrap());
        assert_eq!(sad10[Ids::d].to_string().unwrap(), said9);
        assert!(!sad10["read"].to_bool().unwrap());

        assert!(saider1
            .verify(&sad10, Some(true), None, None, Some(Ids::d), Some(&vec!["read"]))
            .unwrap());

        // Change the 'read' field that is ignored and make sure it still verifies
        sad10["read"] = data!(true);
        assert!(saider1
            .verify(&sad10, Some(true), None, None, Some(Ids::d), Some(&vec!["read"]))
            .unwrap());

        let saider2 = Saider::new(
            Some(&sad10),
            None,
            None,
            Some(&vec!["read"]),
            Some(code),
            None,
            None,
            None,
            None,
        )
        .unwrap();
        assert_eq!(saider1.qb64().unwrap(), saider2.qb64().unwrap());
        assert_eq!(sad10["read"].to_bool().unwrap(), true);
    }

    #[test]
    fn new_with_things() {
        let saider = Saider::new(
            Some(&data!({"d":""})),
            Some(Ids::d),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();
        let saider2 = Saider::new(
            Some(&data!({"d":&saider.qb64().unwrap()})),
            Some(Ids::d),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();
        assert_eq!(saider.code(), saider2.code());
        assert_eq!(saider.qb64().unwrap(), saider2.qb64().unwrap());
        let saider3 = Saider::new(
            None,
            None,
            None,
            None,
            None,
            None,
            Some(&saider.qb64b().unwrap()),
            None,
            None,
        )
        .unwrap();
        assert_eq!(saider.code(), saider3.code());
        assert_eq!(saider.qb64().unwrap(), saider3.qb64().unwrap());
        let mut saider4 = Saider::new(
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(&saider.qb2().unwrap()),
        )
        .unwrap();
        assert_eq!(saider.code(), saider4.code());
        assert_eq!(saider.qb64().unwrap(), saider2.qb64().unwrap());
        let mut v = vec![saider4.raw[0] ^ 0xff];
        v.append(&mut saider4.raw[1..].to_vec());
        saider4.raw = v;
        assert!(!saider4
            .verify(&data!({"d":&saider.qb64().unwrap()}), None, None, None, None, None)
            .unwrap());
    }

    #[test]
    fn unhappy_paths() {
        assert!(validate_code(matter::Codex::Ed25519).is_err());

        assert!(Saider::new(None, None, None, None, None, Some(&[]), None, None, None).is_err());
        assert!(Saider::new(
            Some(&data!({})),
            Some(Ids::d),
            None,
            None,
            None,
            None,
            None,
            None,
            None
        )
        .is_err());
        assert!(Saider::new(
            Some(&data!({"d":true})),
            Some(Ids::d),
            None,
            None,
            None,
            None,
            None,
            None,
            None
        )
        .is_err());
        assert!(Saider::new(None, None, None, None, None, None, None, None, None).is_err());
        assert!(!Saider { code: "CESR".to_string(), raw: vec![], size: 0 }
            .verify(&data!({}), None, None, None, None, None)
            .unwrap());
        assert!(Saider::saidify(&data!({}), None, None, None, None).is_err());
    }
}
