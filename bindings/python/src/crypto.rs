use blake2::{Blake2b512, Blake2s256};
use crypto::digest::{
    Digest, FixedOutput, FixedOutputReset, Output, OutputSizeUser, Reset, Update,
};
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyBytes};
use pyo3::{Bound as PyBound, Py};
use sha1::Sha1;
use sha2::{Sha224, Sha256, Sha384, Sha512};
use sha3::{Keccak224, Keccak256, Keccak384, Keccak512};

/// Trait for Python-exposed digest algorithms
pub trait PyDigest: Sized + Clone + Send + Sync {
    /// The underlying digest type from RustCrypto
    type Inner: Digest + FixedOutput + FixedOutputReset + Reset;

    /// Get the algorithm name (e.g., "sha256", "blake2b512")
    fn algorithm_name() -> &'static str;

    /// Get the output size in bytes
    fn output_size() -> usize;

    /// Create a new instance
    fn new() -> Self;

    /// Create a new instance with a prefix
    fn new_with_prefix(data: &[u8]) -> Self;

    /// Update the digest with data
    fn update(&mut self, data: &[u8]);

    /// Finalize and return the digest
    fn finalize(self) -> Output<Self::Inner>;

    /// Finalize and reset the digest
    fn finalize_reset(&mut self) -> Output<Self::Inner>;

    /// Reset the digest
    fn reset(&mut self);

    /// Compute digest of data in one step
    fn digest(data: &[u8]) -> Output<Self::Inner>;
}

macro_rules! py_digest {
    ($classname:tt, $name:ident, $digest:ty, $size:ty, $output:tt) => {
        #[derive(Debug, Clone)]
        #[pyclass(name = $classname, eq)]
        pub struct $name($digest);

        impl PartialEq for $name {
            fn eq(&self, other: &Self) -> bool {
                std::any::type_name_of_val(&self.0) == std::any::type_name_of_val(&other.0)
            }
        }

        impl PyDigest for $name {
            type Inner = $digest;

            fn algorithm_name() -> &'static str {
                $classname
            }

            fn output_size() -> usize {
                $output
            }

            fn new() -> Self {
                Self(<$digest>::new())
            }

            fn new_with_prefix(data: &[u8]) -> Self {
                Self(<$digest>::new_with_prefix(data))
            }

            fn update(&mut self, data: &[u8]) {
                Update::update(&mut self.0, data)
            }

            fn finalize(self) -> Output<Self::Inner> {
                self.0.finalize()
            }

            fn finalize_reset(&mut self) -> Output<Self::Inner> {
                FixedOutputReset::finalize_fixed_reset(&mut self.0)
            }

            fn reset(&mut self) {
                Reset::reset(&mut self.0)
            }

            fn digest(data: &[u8]) -> Output<Self::Inner> {
                <$digest>::digest(data)
            }
        }

        #[pymethods]
        impl $name {
            #[new]
            pub fn new() -> Self {
                <Self as PyDigest>::new()
            }

            #[staticmethod]
            #[pyo3(name = "new_with_prefix")]
            pub fn new_with_prefix_py(data: PyBound<'_, PyBytes>) -> Self {
                <Self as PyDigest>::new_with_prefix(data.as_bytes())
            }

            #[pyo3(name = "update")]
            pub fn update_bytes(&mut self, data: PyBound<'_, PyBytes>) {
                <Self as PyDigest>::update(self, data.as_bytes())
            }

            #[pyo3(name = "finalize")]
            pub fn finalize_py(slf: PyRef<Self>, py: Python<'_>) -> Py<PyBytes> {
                let result = slf.0.clone().finalize();
                PyBytes::new(py, &result).unbind()
            }

            #[pyo3(name = "finalize_reset")]
            pub fn finalize_reset_py(&mut self, py: Python<'_>) -> PyResult<Py<PyBytes>> {
                let result = <Self as PyDigest>::finalize_reset(self);
                Ok(PyBytes::new(py, &result).unbind())
            }

            #[pyo3(name = "reset")]
            pub fn reset_digest(&mut self) {
                <Self as PyDigest>::reset(self)
            }

            #[staticmethod]
            #[pyo3(name = "digest")]
            pub fn digest_bytes(py: Python<'_>, data: PyBound<'_, PyBytes>) -> Py<PyBytes> {
                let result = <Self as PyDigest>::digest(data.as_bytes());
                PyBytes::new(py, &result).unbind()
            }

            #[staticmethod]
            pub fn output_size() -> usize {
                <Self as PyDigest>::output_size()
            }

            #[staticmethod]
            pub fn name() -> String {
                <Self as PyDigest>::algorithm_name().to_string()
            }

            fn __setattr__(&self, _name: &str, _value: Py<PyAny>) -> PyResult<()> {
                Err(PyErr::new::<pyo3::exceptions::PyAttributeError, _>(
                    format!(
                        "{} objects are immutable",
                        <Self as PyDigest>::algorithm_name()
                    ),
                ))
            }

            fn __delattr__(&self, _name: &str) -> PyResult<()> {
                Err(PyErr::new::<pyo3::exceptions::PyAttributeError, _>(
                    format!(
                        "{} objects are immutable",
                        <Self as PyDigest>::algorithm_name()
                    ),
                ))
            }

            fn __repr__(&self) -> String {
                format!(
                    "<{} _mrkle_rs.crypto.Digest object at {:p}>",
                    <Self as PyDigest>::algorithm_name(),
                    self
                )
            }

            #[inline]
            fn __str__(&self) -> String {
                let classname = <Self as PyDigest>::algorithm_name();
                let mut chars = classname.chars();
                format!(
                    "{}()",
                    chars
                        .next()
                        .map(|f| f.to_uppercase().collect::<String>() + chars.as_str())
                        .unwrap_or_default()
                )
            }

            fn __format__(&self, _spec: &str) -> String {
                self.__str__()
            }
        }

        impl OutputSizeUser for $name {
            type OutputSize = $size;
        }

        impl Update for $name {
            fn update(&mut self, data: &[u8]) {
                Update::update(&mut self.0, data)
            }
        }

        impl Digest for $name {
            fn new() -> Self {
                Self(<$digest>::new())
            }

            fn new_with_prefix(data: impl AsRef<[u8]>) -> Self {
                Self(<$digest>::new_with_prefix(data))
            }

            fn update(&mut self, data: impl AsRef<[u8]>) {
                Update::update(&mut self.0, data.as_ref())
            }

            fn chain_update(mut self, data: impl AsRef<[u8]>) -> Self {
                Update::update(&mut self.0, data.as_ref());
                self
            }

            fn finalize_into_reset(&mut self, out: &mut Output<Self>)
            where
                Self: FixedOutputReset,
            {
                FixedOutputReset::finalize_into_reset(&mut self.0, out)
            }

            fn finalize_into(self, out: &mut Output<Self>) {
                FixedOutput::finalize_into(self.0, out)
            }

            fn finalize(self) -> crypto::digest::Output<Self> {
                self.0.finalize()
            }

            fn finalize_reset(&mut self) -> crypto::digest::Output<Self>
            where
                Self: FixedOutputReset,
            {
                FixedOutputReset::finalize_fixed_reset(&mut self.0)
            }

            fn reset(&mut self)
            where
                Self: Reset,
            {
                Reset::reset(&mut self.0)
            }

            fn output_size() -> usize {
                $output
            }

            fn digest(data: impl AsRef<[u8]>) -> crypto::digest::Output<Self> {
                <$digest>::digest(data)
            }
        }

        impl Reset for $name
        where
            $digest: Reset,
        {
            fn reset(&mut self) {
                Reset::reset(&mut self.0)
            }
        }

        impl FixedOutputReset for $name {
            fn finalize_into_reset(&mut self, out: &mut Output<Self>) {
                FixedOutputReset::finalize_into_reset(&mut self.0, out)
            }
        }

        impl FixedOutput for $name {
            fn finalize_into(self, out: &mut Output<Self>) {
                FixedOutput::finalize_into(self.0, out)
            }
        }

        unsafe impl Sync for $name {}
        unsafe impl Send for $name {}
    };
}

py_digest!("sha1", PySha1Wrapper, Sha1, crypto::digest::consts::U20, 20);
py_digest!(
    "sha224",
    PySha224Wrapper,
    Sha224,
    crypto::digest::consts::U28,
    28
);
py_digest!(
    "sha256",
    PySha256Wrapper,
    Sha256,
    crypto::digest::consts::U32,
    32
);
py_digest!(
    "sha384",
    PySha384Wrapper,
    Sha384,
    crypto::digest::consts::U48,
    48
);
py_digest!(
    "sha512",
    PySha512Wrapper,
    Sha512,
    crypto::digest::consts::U64,
    64
);

// SHA-3/Keccak family
py_digest!(
    "keccak224",
    PyKeccak224Wrapper,
    Keccak224,
    crypto::digest::consts::U28,
    28
);
py_digest!(
    "keccak256",
    PyKeccak256Wrapper,
    Keccak256,
    crypto::digest::consts::U32,
    32
);
py_digest!(
    "keccak384",
    PyKeccak384Wrapper,
    Keccak384,
    crypto::digest::consts::U48,
    48
);
py_digest!(
    "keccak512",
    PyKeccak512Wrapper,
    Keccak512,
    crypto::digest::consts::U64,
    64
);

// BLAKE2 family
py_digest!(
    "blake2s256",
    PyBlake2s256Wrapper,
    Blake2s256,
    crypto::digest::consts::U32,
    32
);
py_digest!(
    "blake2b512",
    PyBlake2b512Wrapper,
    Blake2b512,
    crypto::digest::consts::U64,
    64
);

/// Register all custom crypto with the Python module.
#[pymodule]
pub(crate) fn register_crypto(m: &Bound<'_, PyModule>) -> PyResult<()> {
    let exce_m = PyModule::new(m.py(), "crypto")?;

    exce_m.add_class::<PySha1Wrapper>()?;

    // sha2
    exce_m.add_class::<PySha224Wrapper>()?;
    exce_m.add_class::<PySha256Wrapper>()?;
    exce_m.add_class::<PySha384Wrapper>()?;
    exce_m.add_class::<PySha512Wrapper>()?;

    exce_m.add_class::<PyKeccak224Wrapper>()?;
    exce_m.add_class::<PyKeccak256Wrapper>()?;
    exce_m.add_class::<PyKeccak384Wrapper>()?;
    exce_m.add_class::<PyKeccak512Wrapper>()?;

    exce_m.add_class::<PyBlake2b512Wrapper>()?;
    exce_m.add_class::<PyBlake2s256Wrapper>()?;

    m.add_submodule(&exce_m)
}
