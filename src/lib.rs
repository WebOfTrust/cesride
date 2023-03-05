// TODO: remove before 1.0.0
#![allow(dead_code)]

#[macro_use]
mod data;
mod core;
mod crypto;
mod error;

pub use crate::{
    core::{
        cigar::Cigar,
        common,
        counter::{tables as counter, Counter}, // This seems like it shoudl be an abstract class
        diger::Diger,
        indexer::{tables as indexer, Indexer},
        matter::{tables as matter, Matter},
        number::{tables as number, Number},
        prefixer::Prefixer,
        sadder::Sadder,
        saider::Saider,
        seqner::Seqner,
        siger::Siger,
        signer::Signer,
        verfer::Verfer,
    },
    data::Value,
    error::Error,
};
