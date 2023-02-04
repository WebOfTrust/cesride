// TODO: remove before 1.0.0
#![allow(dead_code)]

mod core;
mod error;

pub use crate::core::cigar::Cigar;
pub use crate::core::counter::{tables as counter, Counter};
pub use crate::core::diger::Diger;
pub use crate::core::matter::{tables as matter, Matter};
pub use crate::core::util;
pub use crate::core::verfer::Verfer;
