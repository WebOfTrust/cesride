use crate::data::{data, Data, Value};
use crate::error::{err, Error, Result};

use lazy_static::lazy_static;
use regex::Regex;

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct SizeifyResult {
    pub(crate) raw: Vec<u8>,
    pub(crate) ident: String,
    pub(crate) kind: String,
    pub(crate) ked: Value,
    pub(crate) version: Version,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct DeversifyResult {
    pub(crate) ident: String,
    pub(crate) kind: String,
    pub(crate) version: Version,
    pub(crate) size: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Version {
    pub(crate) major: u8,
    pub(crate) minor: u8,
}

#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
pub(crate) mod Serialage {
    pub const JSON: &str = "JSON";
}

#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
pub(crate) mod Identage {
    pub const ACDC: &str = "ACDC";
    pub const KERI: &str = "KERI";
}

#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
pub(crate) mod Ids {
    pub const dollar: &str = "$id";
    pub const at: &str = "@id";
    pub const id: &str = "id";
    pub const i: &str = "i";
    pub const d: &str = "d";
}

const REVER_STRING: &str = "(?P<ident>[A-Z]{4})(?P<major>[0-9a-f])(?P<minor>[0-9a-f])(?P<kind>[A-Z]{4})(?P<size>[0-9a-f]{6})_";
const IDENTS: &[&str] = &[Identage::ACDC, Identage::KERI];
const SERIALS: &[&str] = &[Serialage::JSON];

const CURRENT_VERSION: &Version = &Version { major: 1, minor: 0 };

pub(crate) fn deversify(vs: &str) -> Result<DeversifyResult> {
    lazy_static! {
        static ref REVER: Regex = Regex::new(REVER_STRING).unwrap();
    };

    if REVER.is_match(vs) {
        let ident = REVER.replace_all(vs, "$ident").to_string();
        let major = u8::from_str_radix(&REVER.replace_all(vs, "$major"), 16)?;
        let minor = u8::from_str_radix(&REVER.replace_all(vs, "$minor"), 16)?;
        let kind = REVER.replace_all(vs, "$kind").to_string();
        let size = u32::from_str_radix(&REVER.replace_all(vs, "$size"), 16)?;

        if !IDENTS.contains(&ident.as_str()) {
            return err!(Error::Validation(format!("invalid ident {ident}")));
        }

        if !SERIALS.contains(&kind.as_str()) {
            return err!(Error::Validation(format!("invalid serialization kind {kind}")));
        }

        return Ok(DeversifyResult { ident, kind, version: Version { major, minor }, size });
    }

    err!(Error::Validation(format!("invalid version string {vs}")))
}

pub(crate) fn sizeify(ked: &Value, kind: Option<&str>) -> Result<SizeifyResult> {
    lazy_static! {
        static ref REVER: Regex = Regex::new(REVER_STRING).unwrap();
    };

    if !ked.to_map()?.contains_key("v") {
        return err!(Error::Value("missing or empty version string".to_string()));
    }

    let result = deversify(&ked["v"].to_string()?)?;
    if result.version != *CURRENT_VERSION {
        return err!(Error::Value(format!(
            "unsupported version {}.{}",
            result.version.major, result.version.minor
        )));
    }

    let kind = if let Some(kind) = kind { kind.to_string() } else { result.kind };

    if !SERIALS.contains(&kind.as_str()) {
        return err!(Error::Value(format!("invalid serialization kind {kind}")));
    }

    let raw = &dumps(ked, Some(&kind))?;
    let size = raw.len();

    let start = match REVER.shortest_match(&String::from_utf8(raw.clone())?) {
        Some(m) => m - 17,
        // unreachable - deversify has been called which ensures this will match
        None => return err!(Error::Value(format!("invalid version string in raw = {raw:?}"))),
    };

    if start > 12 {
        return err!(Error::Value(format!(
            "invalid version string in raw = {raw:?} start = {start}"
        )));
    }

    let fore = raw[..start].to_vec();
    let mut back = raw[start + 17..].to_vec();
    let vs = versify(Some(&result.ident), Some(&result.version), Some(&kind), Some(size as u32))?;

    let mut raw = fore;
    raw.append(&mut vs.as_bytes().to_vec());
    raw.append(&mut back);

    if raw.len() != size {
        // unreachable as we constructed this
        return err!(Error::Value(format!("malformed version string size, version string = {vs}")));
    }

    let mut ked = ked.clone();
    ked["v"] = data!(&vs);

    Ok(SizeifyResult { raw, ident: result.ident, kind, ked, version: result.version })
}

pub(crate) fn versify(
    ident: Option<&str>,
    version: Option<&Version>,
    kind: Option<&str>,
    size: Option<u32>,
) -> Result<String> {
    let ident = ident.unwrap_or(Identage::KERI);
    let version = version.unwrap_or(CURRENT_VERSION);
    let kind = kind.unwrap_or(Serialage::JSON);
    let size = size.unwrap_or(0);

    if !IDENTS.contains(&ident) {
        return err!(Error::Validation(format!("invalid ident {ident}")));
    }

    if !SERIALS.contains(&kind) {
        return err!(Error::Validation(format!("invalid serialization kind {kind}")));
    }

    Ok(format!(
        "{ident}{major:01x}{minor:01x}{kind}{size:06x}_",
        major = version.major,
        minor = version.minor
    ))
}

pub(crate) fn dumps(ked: &Value, kind: Option<&str>) -> Result<Vec<u8>> {
    let kind = kind.unwrap_or(Serialage::JSON);
    match kind {
        Serialage::JSON => Ok(ked.to_json()?.as_bytes().to_vec()),
        _ => err!(Error::Value(format!("invalid serialization kind = {kind}"))),
    }
}

#[cfg(test)]
mod test {
    use crate::core::common;
    use crate::data::data;
    use rstest::rstest;

    #[test]
    fn sizeify_sad_paths() {
        assert!(common::sizeify(&data!({}), None).is_err());
        assert!(common::sizeify(&data!({"v":"KERIffJSON000000_"}), None).is_err());
        assert!(common::sizeify(&data!({"v":"KERI10JSON000000_"}), Some("CESR")).is_err());
        assert!(
            common::sizeify(&data!({"i":"filler entry","v":"KERI10JSON000000_"}), None).is_err()
        );
    }

    #[test]
    fn versify_sad_paths() {
        assert!(common::versify(Some("CESR"), None, None, None).is_err());
        assert!(common::versify(None, None, Some("CESR"), None).is_err());
    }

    #[rstest]
    fn deversify_sad_paths(
        #[values("CESR10JSON000000_", "KERI10CESR000000_", "KERIXXJSON000000_")] vs: &str,
    ) {
        assert!(common::deversify(vs).is_err());
    }

    #[test]
    fn dumps_sad_paths() {
        assert!(common::dumps(&data!({}), Some("CESR")).is_err());
    }
}
