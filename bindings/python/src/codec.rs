use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

pub enum Codec {
    JSON,
    CBOR,
}

impl<'py> FromPyObject<'py> for Codec {
    fn extract_bound(ob: &Bound<'py, PyAny>) -> PyResult<Self> {
        if let Ok(value) = ob.extract::<String>() {
            match value.to_lowercase().as_str() {
                "json" => Ok(Codec::JSON),
                "cbor" => Ok(Codec::CBOR),
                _ => Err(PyValueError::new_err(
                    "Unable to convert into proper encoding.",
                )),
            }
        } else {
            return Err(PyValueError::new_err(
                "Unable to convert into proper encoding.",
            ));
        }
    }
}
