use blake2::{Blake2b512, Blake2s256};
use crypto::digest::{Digest, DynDigest};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use sha1::Sha1;
use sha2::{Sha224, Sha256, Sha384, Sha512};
use sha3::{Keccak224, Keccak256, Keccak384, Keccak512};

struct InnerHash(Box<dyn DynDigest + 'static>);

unsafe impl Sync for InnerHash {}
unsafe impl Send for InnerHash {}

impl InnerHash {
    fn new(value: Box<dyn DynDigest + 'static>) -> Self {
        Self(value)
    }

    fn from_digest<T: DynDigest + Send + Sync + 'static>(digest: T) -> Self {
        Self(Box::new(digest))
    }
}

impl InnerHash {
    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    fn finalize_reset(&mut self) -> Box<[u8]> {
        self.0.finalize_reset()
    }

    fn box_clone(&self) -> Box<dyn DynDigest> {
        self.0.box_clone()
    }

    fn output_size(&self) -> usize {
        self.0.output_size()
    }
}

#[pyclass(name = "HASH")]
struct PyHasher {
    hasher: InnerHash,
    name: String,
}

#[pymethods]
impl PyHasher {
    #[new]
    fn new(kind: &str) -> PyResult<Self> {
        let (hasher, name) = match kind.to_lowercase().as_str() {
            "sha1" => (InnerHash::from_digest(Sha1::new()), String::from("sha1")),
            "sha224" => (
                InnerHash::from_digest(Sha224::new()),
                String::from("sha224"),
            ),
            "sha256" => (
                InnerHash::from_digest(Sha256::new()),
                String::from("sha256"),
            ),
            "sha384" => (
                InnerHash::from_digest(Sha384::new()),
                String::from("sha384"),
            ),
            "sha512" => (
                InnerHash::from_digest(Sha512::new()),
                String::from("sha512"),
            ),
            "keccak224" => (
                InnerHash::from_digest(Keccak224::new()),
                String::from("keccak224"),
            ),
            "keccak256" => (
                InnerHash::from_digest(Keccak256::new()),
                String::from("keccak256"),
            ),
            "keccak384" => (
                InnerHash::from_digest(Keccak384::new()),
                String::from("keccak384"),
            ),
            "keccak512" => (
                InnerHash::from_digest(Keccak512::new()),
                String::from("keccak512"),
            ),
            "blake2b512" => (
                InnerHash::from_digest(Blake2b512::new()),
                String::from("blake2b512"),
            ),
            "blake2s256" => (
                InnerHash::from_digest(Blake2s256::new()),
                String::from("blake2s256"),
            ),
            _ => {
                return Err(PyValueError::new_err(format!(
                    "Unsupported hash kind: {}",
                    kind
                )))
            }
        };

        Ok(Self { hasher, name })
    }

    fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    #[inline]
    fn digest(&mut self) -> Vec<u8> {
        self.hasher.box_clone().finalize().to_vec()
    }

    fn hexdigest(&mut self) -> String {
        hex::encode(self.digest())
    }

    #[getter]
    fn digest_size(&self) -> usize {
        self.hasher.output_size()
    }

    fn copy(&self) -> Self {
        Self {
            hasher: InnerHash::new(self.hasher.box_clone()),
            name: self.name.clone(),
        }
    }

    #[getter]
    fn name(&self) -> &str {
        &self.name
    }

    #[getter]
    fn block_size(&self) -> usize {
        match self.name.as_str() {
            "sha1" => 64,
            "sha224" => 64,
            "sha256" => 64,
            "sha384" => 128,
            "sha512" => 128,
            "keccak224" => 144,
            "keccak256" => 136,
            "keccak384" => 104,
            "keccak512" => 72,
            "blake2b512" => 128,
            "blake2s256" => 64,
            _ => 64,
        }
    }

    fn __repr__(&self) -> String {
        format!("<{} _mrkle_rs.crypto.HASH object at {:p}>", self.name, self)
    }

    fn __str__(&self) -> String {
        self.__repr__()
    }
}

/// Register all custom crypto with the Python module.
///
/// This function should be called during module initialization to make
/// all custom exceptions available in Python.
///
/// # Arguments
/// * `m` - parent Python module
///
/// # Returns
/// * `PyResult<()>` - Success or error during registration
#[pymodule]
pub(crate) fn register_crypto(m: &Bound<'_, PyModule>) -> PyResult<()> {
    let exce_m = PyModule::new(m.py(), "crypto")?;
    exce_m.add_class::<PyHasher>()?;

    m.add_submodule(&exce_m)
}
