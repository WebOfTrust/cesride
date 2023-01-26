pub(crate) mod tables;
use crate::{
    core::indexer::tables::CurrentSigCodex,
    error::{Error, Result},
};

/// Indexer is fully qualified cryptographic material primitive base class for
/// indexed primitives. Indexed codes are a mix of indexed and variable length
/// because code table has two char codes for compact variable length.
pub(crate) struct Indexer {
    /// stable (hard) part of derivation code
    code: String,
    /// unqualified crypto material usable for crypto operations
    raw: Vec<u8>,
    ///  main index offset into list or length of material
    index: u32,
    ///  other index offset into list or length of material
    ondex: Option<u32>,
}

pub fn new_with_code_and_raw(
    code: &str,
    raw: &[u8],
    raw_size: usize,
    index: u32,
    ondex: Option<u32>,
) -> Result<Indexer> {
    if code.is_empty() {
        return Err(Box::new(Error::EmptyMaterial("empty code".to_string())));
    }

    let mut code = code.to_string();
    let mut size: u32 = 0;
    let first = code.chars().next().unwrap();

    let sizage_ = tables::sizage(&code)?;
    if sizage_.fs == 0 {
        return Err(Box::new(Error::InvalidVarRawSize(format!(
            "unsupported variable size: code = [{}]",
            code
        ))));
    }
    ();

    // both hard + soft code size
    let cs = sizage_.hs + sizage_.ss;
    let ms = sizage_.ss - sizage_.os;

    const SIXTY_FOUR: u32 = 64;
    if index < 0 || index > (SIXTY_FOUR.pow(ms - 1)) {
        return Err(Box::new(Error::InvalidVarIndex(format!(
            "Invalid index {index} for code {code}"
        ))));
    }

    if let Some(o) = ondex {
        if sizage_.os > 0 && !(o >= 0 && o <= SIXTY_FOUR.pow(sizage_.os)) {
            return Err(Box::new(Error::InvalidVarIndex(format!(
                "Invalid ondex {o} for code {code}"
            ))));
        }
    }

    if let Ok(c) = CurrentSigCodex::from_code(&code) {
        if ondex != None {
            return Err(Box::new(Error::InvalidVarIndex(format!(
                "Non None ondex {o} for code {code}",
                o = ondex.unwrap()
            ))));
        }
    }

    Ok(Indexer {
        code,
        raw: Vec::new(),
        index: todo!(),
        ondex: todo!(),
    })
}
