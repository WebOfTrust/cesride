use pyo3::{
    prelude::*,
    exceptions::{PyException, PyValueError},
};

use crate::core::matter::Matter;

#[pymethods]
impl Matter {
    #[new]
    fn py_new(
        code: Option<&str>,
        raw: Option<&[u8]>,
        raw_size: Option<usize>,
        qb64: Option<&str>,
        qb64b: Option<&[u8]>,
        qb2: Option<&[u8]>,
    ) -> PyResult<Self> {
        let result = if let Some(code) = code {
            let (raw, raw_size) = if raw.is_none() || raw_size.is_none() {
                return Err(PyValueError::new_err("code present, raw and raw_size missing"));
            } else {
                (raw.unwrap(), raw_size.unwrap())
            };

            Self::new_with_code_and_raw(code, raw, raw_size)
        } else if let Some(qb64) = qb64 {
            Self::new_with_qb64(qb64)
        } else if let Some(qb64b) = qb64b {
            Self::new_with_qb64b(qb64b)
        } else if let Some(qb2) = qb2 {
            Self::new_with_qb2(qb2)
        } else {
            return Err(PyValueError::new_err("must specify some parameters"));
        };

        match result {
            Ok(matter) => Ok(matter),
            Err(e) => Err(PyException::new_err(e.to_string())),
        }
    }

    #[pyo3(name = "code")]
    fn py_code(&self) -> String {
        self.code()
    }

    #[pyo3(name = "raw")]
    fn py_raw(&self) -> Vec<u8> {
        self.raw()
    }

    #[pyo3(name = "qb64")]
    fn py_qb64(&self) -> PyResult<String> {
        match self.qb64() {
            Ok(s) => Ok(s),
            Err(e) => Err(PyException::new_err(e.to_string())),
        }
    }

    #[pyo3(name = "qb64b")]
    fn py_qb64b(&self) -> PyResult<Vec<u8>> {
        match self.qb64b() {
            Ok(b) => Ok(b),
            Err(e) => Err(PyException::new_err(e.to_string())),
        }
    }

    #[pyo3(name = "qb2")]
    fn py_qb2(&self) -> PyResult<Vec<u8>> {
        match self.qb2() {
            Ok(b) => Ok(b),
            Err(e) => Err(PyException::new_err(e.to_string())),
        }
    }
}
