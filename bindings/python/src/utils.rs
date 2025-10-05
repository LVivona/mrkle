use pyo3::exceptions::{PyModuleNotFoundError, PyTypeError};
use pyo3::prelude::*;
use pyo3::types::{PyByteArray, PyBytes};
use pyo3::Bound as PyBound;

use std::sync::OnceLock;

pub fn get_module<'py>(
    py: Python<'py>,
    cell: &'static OnceLock<Py<PyModule>>,
) -> PyResult<&'py PyBound<'py, PyModule>> {
    let module: &PyBound<'py, PyModule> = cell
        .get()
        .ok_or_else(|| PyModuleNotFoundError::new_err("Could not find module"))?
        .bind(py);
    Ok(module)
}

pub fn extract_to_bytes(obj: &Bound<'_, PyAny>) -> PyResult<Vec<u8>> {
    if let Ok(bytes) = obj.downcast::<PyBytes>() {
        return Ok(bytes.as_bytes().to_vec());
    }

    if let Ok(bytearray) = obj.downcast::<PyByteArray>() {
        return Ok(bytearray.to_vec());
    }

    if let Ok(s) = obj.extract::<String>() {
        return Ok(s.into_bytes());
    }

    if obj.hasattr("tobytes")? {
        if let Ok(tobytes) = obj.getattr("tobytes") {
            if let Ok(result) = tobytes.call0() {
                if let Ok(bytes) = result.downcast::<PyBytes>() {
                    return Ok(bytes.as_bytes().to_vec());
                }
            }
        }
    }

    if obj.hasattr("__bytes__")? {
        if let Ok(tobytes) = obj.getattr("__bytes__") {
            if let Ok(result) = tobytes.call0() {
                if let Ok(bytes) = result.downcast::<PyBytes>() {
                    return Ok(bytes.as_bytes().to_vec());
                }
            }
        }
    }

    Err(PyTypeError::new_err("Cannot convert to bytes"))
}
