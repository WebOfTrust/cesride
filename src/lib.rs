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
    saider::Saider,
    siger::Siger,
    signer::Signer,
    util,
    verfer::Verfer,
};

pub type Seqner = Verfer; // FIXME: Implement and export
pub type Prefixer = Verfer; // FIXME: Implement and export
