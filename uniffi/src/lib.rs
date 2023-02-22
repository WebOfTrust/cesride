uniffi::include_scaffolding!("cesride");

use cesride::Verfer as VerferClass;
use cesride::Result;
pub use cesride::Error as CESRError;

fn Verfer(
    code: Option<String>,
    raw: Option<Vec<u8>>,
    qb64b: Option<Vec<u8>>,
    qb64: Option<String>,
    qb2: Option<Vec<u8>>
) -> Result<VerferInterface> {
    Ok(VerferClass::new(
        code.map_or(None, |code| Some(&code)),
        raw.map_or(None, |raw| Some(&raw)),
        qb64b.map_or(None, |qb64b| Some(&mut qb64b)),
        qb64.map_or(None, |qb64| Some(&qb64)),
        qb2.map_or(None, |qb2| Some(&mut qb2)),
        None
    )?)
}

