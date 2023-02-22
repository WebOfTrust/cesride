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
    diger::Diger,
    indexer::tables as indexer,
    matter::tables as matter,
    saider::Saider,
    seqner::Seqner,
    siger::Siger,
    signer::Signer,
    util,
    verfer::Verfer,
};
