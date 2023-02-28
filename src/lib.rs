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
pub mod ffi;
#[cfg(feature = "ffi")]
pub use self::ffi::*;
#[cfg(feature = "ffi")]
uniffi_macros::include_scaffolding!("cesride");
