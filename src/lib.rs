// TODO: remove before 1.0.0
#![allow(dead_code)]

#[macro_use]
mod data;
mod core;
mod crypto;
mod error;

// Rust objects
pub use crate::core::{
    // cigar::Cigar,
    // counter::{tables as counter, Counter}, // This seems like it shoudl be an abstract class
    // dater::Dater,
    // diger::Diger,
    // indexer::{tables as indexer, Indexer},
    matter::{tables as matter, Matter},
    // saider::Saider,
    // siger::Siger,
    // signer::Signer,
    verfer::Verfer,
};
pub use error::{Error, Result};

pub mod constructors {
    pub use crate::core::verfer::Constructor as Verfer;
}
