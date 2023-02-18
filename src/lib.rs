// TODO: remove before 1.0.0
#![allow(dead_code)]

mod core;
mod error;

pub use crate::core::{
    cigar::Cigar,
    counter::{tables as counter, Counter},
    diger::Diger,
    matter::{tables as matter, Matter},
    siger::Siger,
    signer::Signer,
    util,
    verfer::Verfer,
};
