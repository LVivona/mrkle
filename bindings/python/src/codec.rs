use std::hash::Hash;
use std::marker::PhantomData;

use crate::crypto::PyDigest;

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

pub enum PyCodecFormat {
    #[allow(non_camel_case_types)]
    UTF_8,
    BYTES,
}

impl<'py> FromPyObject<'py> for PyCodecFormat {
    fn extract_bound(ob: &Bound<'py, PyAny>) -> PyResult<Self> {
        if let Ok(value) = ob.extract::<String>() {
            match value.to_lowercase().as_str() {
                "utf-8" => Ok(PyCodecFormat::UTF_8),
                "bytes" => Ok(PyCodecFormat::BYTES),
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

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct JsonCodec<T, D>
where
    T: Eq + PartialEq + Hash + Clone,
    D: PyDigest,
{
    pub hash_type: String,
    /// The hash output size in bytes
    pub hash_size: usize,
    #[serde(skip)]
    phantom: PhantomData<D>,
    /// The tree structure with hashes and values
    #[serde(flatten)]
    tree: MerkleTreeJson<T>,
}

impl<'de, T, D> JsonCodec<T, D>
where
    T: Eq + PartialEq + Hash + Clone + serde::Serialize + serde::Deserialize<'de>,
    D: PyDigest,
{
    pub fn new(tree: MerkleTreeJson<T>) -> Self {
        Self {
            tree,
            hash_type: D::algorithm_name().to_string(),
            hash_size: D::output_size(),
            phantom: PhantomData,
        }
    }

    pub fn to_vec(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    pub fn to_string(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    pub fn to_pretty_string(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    pub fn from_slice(data: &'de [u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(data)
    }

    pub fn from_str(data: &'de str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(data)
    }

    pub fn into_tree(self) -> MerkleTreeJson<T> {
        self.tree
    }

    pub fn validate_hash_type(&self) -> bool {
        self.hash_type == D::algorithm_name()
    }

    pub fn validate_hash_size(&self) -> bool {
        self.hash_size == D::output_size()
    }
}

/// A recursive JSON codec for Merkle tree structures
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum MerkleTreeJson<T>
where
    T: Eq + PartialEq + Hash + Clone,
{
    /// A leaf node with hash and value
    Leaf {
        #[serde(with = "hex_serde")]
        hash: Vec<u8>,
        value: T,
    },
    /// A parent node with hash and children
    Parent {
        #[serde(with = "hex_serde")]
        hash: Vec<u8>,
        children: Vec<MerkleTreeJson<T>>,
    },
}

// Custom hex serialization for Vec<u8>
mod hex_serde {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(faster_hex::hex_string(&bytes).as_str())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let mut buffer = vec![0; s.len() / 2];
        faster_hex::hex_decode(s.as_bytes(), &mut buffer)
            .map_err(|e| serde::de::Error::custom(e.to_string()))?;
        Ok(buffer)
    }
}
