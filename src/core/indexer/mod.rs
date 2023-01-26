pub(crate) mod tables;
use crate::error::{Error, Result};

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
    /// fully qualified Base64 crypto material
    qb64b: Vec<u8>,
    ///   fully qualified Base64 crypto material
    qb64: String,
    ///  fully qualified binary crypto material
    qb2: Vec<u8>,
}
