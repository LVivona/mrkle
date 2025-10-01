use pyo3::exceptions::PyModuleNotFoundError;
use pyo3::prelude::*;
use pyo3::Bound as PyBound;
use std::sync::OnceLock;

pub fn get_module<'a>(
    py: Python<'a>,
    cell: &'static OnceLock<Py<PyModule>>,
) -> PyResult<&'a PyBound<'a, PyModule>> {
    let module: &PyBound<'a, PyModule> = cell
        .get()
        .ok_or_else(|| PyModuleNotFoundError::new_err("Could not find module"))?
        .bind(py);
    Ok(module)
}
