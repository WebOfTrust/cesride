// TODO: remove before 1.0.0
#![allow(dead_code)]

#[macro_use]
mod data;
mod core;
mod crypto;
mod error;

pub use crate::core::{
    cigar::Cigar,
    counter::{tables as counter, Counter}, // This seems like it shoudl be an abstract class
    dater::Dater,
    diger::Diger,
    indexer::{tables as indexer, Indexer},
    matter::{tables as matter, Matter},
    prefixer::Prefixer,
    saider::Saider,
    seqner::Seqner,
    siger::Siger,
    signer::Signer,
    util,
    verfer::Verfer,
};
pub use crate::error::{Error, Result};

#[cfg(feature = "ffi")]
use crate::data::Value;

#[cfg(feature = "ffi")]
pub mod ffi;
#[cfg(feature = "ffi")]
pub use self::ffi::*;
#[cfg(feature = "ffi")]
uniffi_macros::include_scaffolding!("cesride");

// We must implement the UniffiCustomTypeWrapper trait.
#[cfg(feature = "ffi")]
impl UniffiCustomTypeConverter for Value {
    type Builtin = String;

    fn into_custom(val: Self::Builtin) -> uniffi::Result<Self> {
        Ok(Value::from(&val))
    }

    fn from_custom(obj: Self) -> Self::Builtin {
        obj.to_string().expect("unable unwrap value")
    }
}
