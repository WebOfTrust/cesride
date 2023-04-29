use crate::{
    common::{Identage, Ids, Serialage, Version, CURRENT_VERSION},
    core::matter::tables as matter,
    core::sadder::Sadder,
    core::saider::Saider,
    data::{dat, Value},
    error::{err, Error, Result}
};

#[derive(Clone, Debug, PartialEq)]
pub struct Creder {
    code: String,
    raw: Vec<u8>,
    ked: Value,
    ident: String,
    kind: String,
    size: u32,
    version: Version,
    saider: Saider,
}

fn validate_ident(ident: &str) -> Result<()> {
    if ident != Identage::ACDC {
        return err!(Error::Value("creder must be an ACDC".to_string()));
    }

    Ok(())
}

impl Creder {
    pub fn new(
        code: Option<&str>,
        raw: Option<&[u8]>,
        kind: Option<&str>,
        ked: Option<&Value>,
        sad: Option<&Self>,
    ) -> Result<Self> {
        let code = code.unwrap_or(matter::Codex::Blake3_256);
        let creder = Sadder::new(Some(code), raw, kind, ked, sad)?;
        validate_ident(&creder.ident())?;

        Ok(creder)
    }

    pub fn new_with_ked(ked: &Value, code: Option<&str>, kind: Option<&str>) -> Result<Self> {
        Self::new(code, None, kind, Some(ked), None)
    }

    pub fn new_with_raw(raw: &[u8]) -> Result<Self> {
        Self::new(None, Some(raw), None, None, None)
    }

    pub fn crd(&self) -> Value {
        self.ked()
    }

    pub fn issuer(&self) -> Result<String> {
        self.ked()[Ids::i].to_string()
    }

    pub fn schema(&self) -> Result<String> {
        self.ked()[Ids::s].to_string()
    }

    pub fn subject(&self) -> Value {
        self.ked()[Ids::a].clone()
    }

    pub fn status(&self) -> Result<Option<String>> {
        let map = self.ked().to_map()?;

        if map.contains_key("ri") {
            Ok(Some(map["ri"].to_string()?))
        } else {
            Ok(None)
        }
    }

    pub fn chains(&self) -> Result<Value> {
        let map = self.ked().to_map()?;

        if map.contains_key("e") {
            Ok(map["e"].clone())
        } else {
            Ok(dat!({}))
        }
    }
}

impl Default for Creder {
    fn default() -> Self {
        Creder {
            code: matter::Codex::Blake3_256.to_string(),
            raw: vec![],
            ked: dat!({}),
            ident: Identage::ACDC.to_string(),
            kind: Serialage::JSON.to_string(),
            size: 0,
            version: CURRENT_VERSION.clone(),
            saider: Saider::default(),
        }
    }
}

impl Sadder for Creder {
    fn code(&self) -> String {
        self.code.clone()
    }

    fn raw(&self) -> Vec<u8> {
        self.raw.clone()
    }

    fn ked(&self) -> Value {
        self.ked.clone()
    }

    fn ident(&self) -> String {
        self.ident.clone()
    }

    fn kind(&self) -> String {
        self.kind.clone()
    }

    fn size(&self) -> u32 {
        self.size
    }

    fn version(&self) -> Version {
        self.version.clone()
    }

    fn saider(&self) -> Saider {
        self.saider.clone()
    }

    fn set_code(&mut self, code: &str) {
        self.code = code.to_string();
    }

    fn set_raw(&mut self, raw: &[u8]) {
        self.raw = raw.to_vec();
    }

    fn set_ked(&mut self, ked: &Value) {
        self.ked = ked.clone();
    }

    fn set_ident(&mut self, ident: &str) {
        self.ident = ident.to_string();
    }

    fn set_kind(&mut self, kind: &str) {
        self.kind = kind.to_string();
    }

    fn set_size(&mut self, size: u32) {
        self.size = size;
    }

    fn set_version(&mut self, version: &Version) {
        self.version = version.clone();
    }

    fn set_saider(&mut self, saider: &Saider) {
        self.saider = saider.clone();
    }
}
