// TODO: remove before 1.0.0
#![allow(dead_code)]

#[macro_use]
mod data;
mod core;
mod crypto;
mod error;

pub use crate::{
    core::{
        bexter::Bexter,
        cigar::Cigar,
        common,
        counter::{tables as counter, Counter}, // This seems like it shoudl be an abstract class
        dater::Dater,
        diger::Diger,
        indexer::{tables as indexer, Indexer},
        matter::{tables as matter, Matter},
        number::{tables as number, Number},
        prefixer::Prefixer,
        sadder::Sadder,
        saider::Saider,
        salter::Salter,
        seqner::Seqner,
        serder::Serder,
        siger::Siger,
        signer::Signer,
        tholder::Tholder,
        verfer::Verfer,
    },
    data::Value,
    error::Error,
    error::Result,
};
