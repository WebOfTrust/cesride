use crate::{
    common::{Identage, Ids, Serialage, Version, CURRENT_VERSION},
    core::matter::tables as matter,
    core::sadder::Sadder,
    core::saider::Saider,
    data::{dat, Value},
    error::{err, Error, Result},
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

#[cfg(test)]
mod test {
    use super::Creder;

    #[test]
    fn sanity() {
        let keri_value = dat!({"v":"KERI10JSON0001e7_","t":"icp","d":"EA_1ZGv4tEhJW2AYH0wLh2lLlllmH3dwpH3RGs2GtgXr","i":"EA_1ZGv4tEhJW2AYH0wLh2lLlllmH3dwpH3RGs2GtgXr","s":"0","kt":"2","k":["DID6gcblxh8yiILkx_tratCNdDiYHWInyrZOF0dHgn-s","DJgKrw-dQFtDUZ6ahEzc-HJqe5NOXF_F4xMXy41bvApe","DMEijEab-eqt7AEhLyrMcHH8I36HPYOn1rjnvwycPURK"],"nt":"2","n":["EP7pWgkdErxn23QcvAH5ovQQrjZgtgc2qv-X79JKctUV","ENJus7HZN9Dsm7jHkn8vTC5Wk2VRhjtGQ9NaOa57OydR","EMLWypoar99qGWhnlaX_07W8bbqchTILXH96SGbSV42I"],"bt":"0","b":[],"c":[],"a":[]});
        let acdc_value = dat!({"v":"ACDC10JSON00022b_","d":"ENIcZJXSgLgz5whOszoME4DPe7B93Qltk6n6C6E9YxF2","i":"ENayINhHQnx6525EpcTmkvo6ZixiJyiskwkVNbMPohYa","ri":"EINZnO3Z30Q7y2oV1sDCQphieRH244-XJFRAbzuFbU7n","s":"EE5uDJTq5cc6AEdqbyMpvARUjsK_chNdInf3xyRoCBcT","a":{"d":"EOsCUbK6Ve7qb-h15ljNyvVhLz2rq6iaCcA86AAoeZyX","dt":"2023-04-30T00:34:11.853572+00:00"},"e":{"d":"ECuynR9pRY6A6dWRlc2DTSF7AWY2a-w-6qhx7vd-pWT-","acceptedBlock":{"d":"EOvQJIx58cCC-xB5LIWeApUH80Jxo8WxGNsLb-1HKLcy","n":"EE_Wrv2OHqIOptEni3mE3Ckc4C6jO1RvgtxdpDZBiuB0","s":"EDiWb-53cI8FBPOpF69LrLCSElNjG-BAChHp2-OsLmbC"}}});
        let keri_json = keri_value.to_json().unwrap();
        let keri_message = keri_json.as_bytes();
        let acdc_json = acdc_value.to_json().unwrap();
        let acdc_message = acdc_json.as_bytes();

        assert!(Creder::new_with_raw(keri_message).is_err());
        assert!(Creder::new(None, Some(acdc_message), None, None, None).is_ok());
    }
}
