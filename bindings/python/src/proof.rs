use pyo3::intern;
use pyo3::prelude::*;
use pyo3::sync::OnceLockExt;

use pyo3::Bound as PyBound;

use pyo3::exceptions::PyValueError;
use pyo3::types::{PyDict, PyModule, PyType};

use mrkle::error::ProofError;
use mrkle::{GenericArray, MrkleProof, MrkleProofNode, MutNode, Node, NodeIndex, Tree};

use crate::{
    codec::Codec,
    crypto::{
        PyBlake2b512Wrapper, PyBlake2s256Wrapper, PyKeccak224Wrapper, PyKeccak256Wrapper,
        PyKeccak384Wrapper, PyKeccak512Wrapper, PySha1Wrapper, PySha224Wrapper, PySha256Wrapper,
        PySha384Wrapper, PySha512Wrapper,
    },
    errors::ProofError as PyProofError,
    tree::{
        PyMrkleNode_Blake2b, PyMrkleNode_Blake2s, PyMrkleNode_Keccak224, PyMrkleNode_Keccak256,
        PyMrkleNode_Keccak384, PyMrkleNode_Keccak512, PyMrkleNode_Sha1, PyMrkleNode_Sha224,
        PyMrkleNode_Sha256, PyMrkleNode_Sha384, PyMrkleNode_Sha512, PyMrkleTreeBlake2b,
        PyMrkleTreeBlake2s, PyMrkleTreeKeccak224, PyMrkleTreeKeccak256, PyMrkleTreeKeccak384,
        PyMrkleTreeKeccak512, PyMrkleTreeSha1, PyMrkleTreeSha224, PyMrkleTreeSha256,
        PyMrkleTreeSha384, PyMrkleTreeSha512,
    },
    MRKLE_MODULE,
};

macro_rules! py_mrkle_proof {
    ($name:ident, $digest:ty, $tree:ty, $node:ty, $classname:literal) => {
        #[pyclass]
        #[derive(Clone)]
        #[pyo3(name = $classname)]
        pub struct $name {
            pub inner: MrkleProof<$digest, usize>,
        }

        unsafe impl Sync for $name {}
        unsafe impl Send for $name {}

        impl serde::Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                self.inner.serialize(serializer)
            }
        }

        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let inner = MrkleProof::deserialize(deserializer)?;
                Ok(Self { inner })
            }
        }

        #[pymethods]
        impl $name {
            #[inline]
            fn expected(&self) -> &[u8] {
                self.inner.expected()
            }

            #[inline]
            fn expected_hexdigest(&self) -> String {
                hex::encode(self.inner.expected())
            }

            #[classmethod]
            fn generate(
                _cls: &Bound<'_, PyType>,
                tree: Bound<'_, PyAny>,
                leaves: Vec<usize>,
            ) -> PyResult<Self> {
                Python::with_gil(|py| {
                    let module = PyModule::import(py, intern!(py, "mrkle"))?;
                    MRKLE_MODULE.get_or_init_py_attached(py, || module.clone().unbind());

                    let ttype = module.getattr(intern!(py, "MrkleTree"))?;

                    if !tree.is_instance(&ttype)? {
                        return Err(PyValueError::new_err("Expected a MrkleTree instance"));
                    }

                    // Get the _inner attribute
                    let inner_attr = tree.getattr(intern!(py, "_inner"))?;

                    // Extract the tree
                    let internal_tree = inner_attr.extract::<$tree>()?;

                    if leaves.is_empty() {
                        return Err(PyValueError::new_err(
                            "Must provide at least one leaf index",
                        ));
                    }

                    // Generate proof for all leaves, not just the first one
                    let proof = Self::generate_proof_from_leaf(
                        &internal_tree.inner,
                        NodeIndex::new(leaves[0]),
                    )
                    .map_err(|e| PyProofError::new_err(format!("{e}")))?;

                    Ok(proof)
                })
            }

            fn update(&mut self, leaves: PyBound<'_, PyAny>) -> PyResult<()> {
                // NOTE: update the MerkleTree leaf

                // Case 1: single bytes
                if let Ok(leaf) = leaves.extract::<&[u8]>() {
                    self.inner
                        .update_leaf_hash(0, GenericArray::<$digest>::clone_from_slice(leaf))
                        .map_err(|e| PyProofError::new_err(format!("{e}")))?;
                    return Ok(());
                }

                // Case 2: list of bytes
                if let Ok(multi) = leaves.extract::<Vec<Vec<u8>>>() {
                    for (idx, bytes) in multi.iter().enumerate() {
                        self.inner
                            .update_leaf_hash(idx, GenericArray::<$digest>::clone_from_slice(bytes))
                            .map_err(|e| PyProofError::new_err(format!("{e}")))?;
                    }
                    return Ok(());
                }

                // Case 3: hex string
                if let Ok(hex_str) = leaves.extract::<String>() {
                    let bytes = hex::decode(hex_str)
                        .map_err(|e| PyValueError::new_err(format!("{e}")))?;

                    self.inner
                        .update_leaf_hash(0, GenericArray::<$digest>::clone_from_slice(&bytes))
                        .map_err(|e| PyProofError::new_err(format!("{e}")))?;
                    return Ok(());
                }

                // Case 4: list of hex strings
                if let Ok(multi_hex) = leaves.extract::<Vec<String>>() {
                    for (idx, hex_str) in multi_hex.iter().enumerate() {
                        let bytes = hex::decode(hex_str)
                            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Invalid hex at index {idx}: {e}")))?;

                        self.inner
                            .update_leaf_hash(idx, GenericArray::<$digest>::clone_from_slice(&bytes))
                            .map_err(|e| PyProofError::new_err(format!("{e}")))?;
                    }
                    return Ok(());
                }

                Err(PyErr::new::<pyo3::exceptions::PyTypeError, _>(
                    "Expected bytes, list[bytes], hex string, or list[str] of hex string",
                ))
            }


            fn validate(&mut self) -> PyResult<bool> {
                self.inner.try_validate_basic().map_err(|e| PyProofError::new_err(format!("{e}")))
            }

            fn refresh(&mut self) {
                self.inner.refresh()
            }

            #[staticmethod]
            fn dtype() -> $digest {
                <$digest>::new()
            }

            fn __len__(&self) -> usize {
                self.inner.len()
            }

            fn __repr__(&self) -> String {
                format!("<_mrkle_rs.proof.{} object at {:p}>", $classname, self)
            }

            fn __str__(&self) -> String {
                self.__repr__()
            }

            fn to_string(&self) -> String {
                format!("{}", self.inner)
            }

            #[pyo3(text_signature = "(encoding, **kwargs)")]
            fn dumps<'py>(
                &self,
                py: Python<'py>,
                encoding: Option<Codec>,
                _kwargs: PyBound<'_, PyDict>,
            ) -> PyResult<Bound<'py, PyAny>> {
                match encoding {
                    Some(Codec::JSON) => {
                        let json_str = serde_json::to_string(&self).map_err(|e| {
                            PyValueError::new_err(format!("JSON serialization error: {}", e))
                        })?;
                        Ok(json_str.into_pyobject(py)?.into_any())
                    }
                    Some(Codec::CBOR) | None => {
                        let bytes = serde_cbor::to_vec(&self).map_err(|e| {
                            PyValueError::new_err(format!("CBOR serialization error: {}", e))
                        })?;
                        Ok(pyo3::types::PyBytes::new(py, &bytes).into_any())
                    }
                }
            }

            #[staticmethod]
            #[pyo3(text_signature = "(data : bytes, encoding : Optional[Literal['json', 'codec']] = None, **kwargs)")]
            fn loads(
                data: &PyBound<'_, PyAny>,
                encoding: Option<Codec>,
                _kwargs: PyBound<'_, PyDict>,
            ) -> PyResult<Self> {
                let bytes = data.extract::<&[u8]>()?;

                match encoding {
                    Some(Codec::JSON) => serde_json::from_slice(&bytes).map_err(|e| {
                        PyValueError::new_err(format!("JSON deserialization error: {}", e))
                    }),
                    Some(Codec::CBOR) | None => serde_cbor::from_slice(bytes).map_err(|e| {
                        PyValueError::new_err(format!("CBOR deserialization error: {}", e))
                    }),
                }
            }
        }

        impl $name {
            #[inline]
            pub(crate) fn generate_proof_from_leaf(
                tree: &Tree<$node, usize>,
                leaf: NodeIndex<usize>,
            ) -> Result<Self, ProofError> {
                let length = tree.len();
                if length <= 1 {
                    return Err(ProofError::InvalidSize);
                }

                // Validate if node exists and is a leaf within the tree.
                tree.get(leaf.index())
                    .filter(|&leaf| leaf.is_leaf())
                    .ok_or(ProofError::ExpectedLeafHash)?;

                // Obtain the root/public hash
                let expected = tree.root().hash().clone();

                // Collect siblings from leaf to root
                let mut siblings: Vec<(Option<GenericArray<$digest>>, bool)> = Vec::new();
                let mut parents = 0;
                let mut current = leaf;

                while let Some(node) = tree.get(current.index()) {
                    if let Some(parent_idx) = node.parent() {
                        let parent = tree
                            .get(parent_idx.index())
                            .ok_or_else(|| ProofError::out_of_bounds(tree.len(), parent_idx))?;

                        if parent.child_count() == 1 {
                            parents += 1;
                        } else {
                            for sibling_idx in parent.children() {
                                if sibling_idx != current {
                                    let sibling =
                                        tree.get(sibling_idx.index()).ok_or_else(|| {
                                            ProofError::out_of_bounds(tree.len(), sibling_idx)
                                        })?;
                                    siblings.push((
                                        Some(sibling.hash().clone()),
                                        sibling_idx < current,
                                    ));
                                }
                            }
                        }

                        current = parent_idx;
                    } else {
                        break; // reached root
                    }
                }

                // Build the proof tree structure
                let mut proof = Tree::new();

                // Start with the leaf proof node
                let leaf_idx = proof.push(MrkleProofNode::new(None, Vec::new(), None));
                let mut current = leaf_idx;

                for _ in 0..parents {
                    let parent = MrkleProofNode::new(None, vec![current], None);
                    let index = proof.push(parent);
                    proof.get_mut(current.index()).unwrap().set_parent(index);
                    current = index;
                }

                // Add binary parents with siblings
                for (sibling_hash, is_left) in siblings {
                    let sibling_idx =
                        proof.push(MrkleProofNode::new(None, Vec::new(), sibling_hash));

                    let children = if is_left {
                        vec![sibling_idx, current]
                    } else {
                        vec![current, sibling_idx]
                    };

                    let parent_idx = proof.push(MrkleProofNode::new(None, children, None));

                    proof
                        .get_mut(current.index())
                        .unwrap()
                        .set_parent(parent_idx);
                    proof
                        .get_mut(sibling_idx.index())
                        .unwrap()
                        .set_parent(parent_idx);

                    current = parent_idx;
                }

                proof.set_root(Some(current));

                Ok(Self {
                    inner: MrkleProof::new(proof, expected),
                })
            }
        }
    };
}

py_mrkle_proof!(
    PyMrkleProofSha1,
    PySha1Wrapper,
    PyMrkleTreeSha1,
    PyMrkleNode_Sha1,
    "MrkleProofSha1"
);

py_mrkle_proof!(
    PyMrkleProofSha224,
    PySha224Wrapper,
    PyMrkleTreeSha224,
    PyMrkleNode_Sha224,
    "MrkleProofSha224"
);

py_mrkle_proof!(
    PyMrkleProofSha256,
    PySha256Wrapper,
    PyMrkleTreeSha256,
    PyMrkleNode_Sha256,
    "MrkleProofSha256"
);

py_mrkle_proof!(
    PyMrkleProofSha384,
    PySha384Wrapper,
    PyMrkleTreeSha384,
    PyMrkleNode_Sha384,
    "MrkleProofSha384"
);

py_mrkle_proof!(
    PyMrkleProofSha512,
    PySha512Wrapper,
    PyMrkleTreeSha512,
    PyMrkleNode_Sha512,
    "MrkleProofSha512"
);

py_mrkle_proof!(
    PyMrkleProofBlake2b,
    PyBlake2b512Wrapper,
    PyMrkleTreeBlake2b,
    PyMrkleNode_Blake2b,
    "MrkleProofBlake2b"
);

py_mrkle_proof!(
    PyMrkleProofBlake2s,
    PyBlake2s256Wrapper,
    PyMrkleTreeBlake2s,
    PyMrkleNode_Blake2s,
    "MrkleProofBlake2s"
);

py_mrkle_proof!(
    PyMrkleProofKeccak224,
    PyKeccak224Wrapper,
    PyMrkleTreeKeccak224,
    PyMrkleNode_Keccak224,
    "MrkleProofKeccak224"
);

py_mrkle_proof!(
    PyMrkleProofKeccak256,
    PyKeccak256Wrapper,
    PyMrkleTreeKeccak256,
    PyMrkleNode_Keccak256,
    "MrkleProofKeccak256"
);

py_mrkle_proof!(
    PyMrkleProofKeccak384,
    PyKeccak384Wrapper,
    PyMrkleTreeKeccak384,
    PyMrkleNode_Keccak384,
    "MrkleProofKeccak384"
);

py_mrkle_proof!(
    PyMrkleProofKeccak512,
    PyKeccak512Wrapper,
    PyMrkleTreeKeccak512,
    PyMrkleNode_Keccak512,
    "MrkleProofKeccak512"
);

/// Register MrkleProof data structure.
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
pub(crate) fn register_proof(m: &Bound<'_, PyModule>) -> PyResult<()> {
    let proof_m = PyModule::new(m.py(), "proof")?;

    proof_m.add_class::<PyMrkleProofSha1>()?;

    proof_m.add_class::<PyMrkleProofSha224>()?;
    proof_m.add_class::<PyMrkleProofSha256>()?;
    proof_m.add_class::<PyMrkleProofSha384>()?;
    proof_m.add_class::<PyMrkleProofSha512>()?;

    proof_m.add_class::<PyMrkleProofKeccak224>()?;
    proof_m.add_class::<PyMrkleProofKeccak256>()?;
    proof_m.add_class::<PyMrkleProofKeccak384>()?;
    proof_m.add_class::<PyMrkleProofKeccak512>()?;

    proof_m.add_class::<PyMrkleProofBlake2b>()?;
    proof_m.add_class::<PyMrkleProofBlake2s>()?;

    m.add_submodule(&proof_m)
}
