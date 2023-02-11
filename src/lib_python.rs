// TODO: remove before 1.0.0
#![allow(dead_code)]

use pyo3::prelude::*;

mod core;
mod error;
mod python;

use crate::core::diger::Diger; 

#[pymodule]
fn cesride(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<Diger>()?;
    Ok(())
}
