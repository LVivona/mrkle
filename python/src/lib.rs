use pyo3::prelude::*;

use crate::errors::register_exceptions;

pub mod errors;

/// A Python module implemented in Rust.
#[pymodule]
fn _mrkle_rs(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Register exception module within mrkle_rs [`Bound<'_, PyModule>`].
    register_exceptions(m)?;

    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}
