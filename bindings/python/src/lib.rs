use std::sync::OnceLock;

use pyo3::prelude::*;
use pyo3::Bound as PyBound;

use crate::crypto::register_crypto;
use crate::errors::register_exceptions;
use crate::proof::register_proof;
use crate::tree::register_tree;

pub mod crypto;
pub mod errors;
pub mod proof;
pub mod tree;

pub mod codec;
pub mod utils;

static MRKLE_MODULE: OnceLock<Py<PyModule>> = OnceLock::new();

/// A Python module implemented in Rust.
#[pymodule]
fn _mrkle_rs(m: &PyBound<'_, PyModule>) -> PyResult<()> {
    register_exceptions(m)?;
    register_crypto(m)?;
    register_tree(m)?;
    register_proof(m)?;

    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}
