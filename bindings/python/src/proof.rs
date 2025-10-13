use pyo3::intern;
use pyo3::prelude::*;
use pyo3::sync::OnceLockExt;

use pyo3::Bound as PyBound;

use pyo3::exceptions::{PyIndexError, PyTypeError, PyValueError};
use pyo3::types::{PyModule, PySequence, PyType};

use mrkle::error::{ProofError, TreeError};
use mrkle::{GenericArray, MrkleProof, Node, NodeIndex, ProofLevel, ProofPath};

use crate::{
    MRKLE_MODULE,
    crypto::{
        PyBlake2b512Wrapper, PyBlake2s256Wrapper, PyKeccak224Wrapper, PyKeccak256Wrapper,
        PyKeccak384Wrapper, PyKeccak512Wrapper, PySha1Wrapper, PySha224Wrapper, PySha256Wrapper,
        PySha384Wrapper, PySha512Wrapper,
    },
    errors::{ProofError as PyProofError, TreeError as PyTreeError},
    tree::{
        PyMrkleNode_Blake2b, PyMrkleNode_Blake2s, PyMrkleNode_Keccak224, PyMrkleNode_Keccak256,
        PyMrkleNode_Keccak384, PyMrkleNode_Keccak512, PyMrkleNode_Sha1, PyMrkleNode_Sha224,
        PyMrkleNode_Sha256, PyMrkleNode_Sha384, PyMrkleNode_Sha512, PyMrkleTreeBlake2b,
        PyMrkleTreeBlake2s, PyMrkleTreeKeccak224, PyMrkleTreeKeccak256, PyMrkleTreeKeccak384,
        PyMrkleTreeKeccak512, PyMrkleTreeSha1, PyMrkleTreeSha224, PyMrkleTreeSha256,
        PyMrkleTreeSha384, PyMrkleTreeSha512,
    },
};

macro_rules! py_mrkle_proof {
    ($name:ident, $digest:ty, $tree:ty, $node:ty, $classname:literal) => {
        #[pyclass]
        #[derive(Clone)]
        #[pyo3(name = $classname)]
        pub struct $name {
            pub inner: MrkleProof<$digest>,
        }

        unsafe impl Sync for $name {}
        unsafe impl Send for $name {}

        impl $name {
            fn generate_path(
                tree: &$tree,
                root: NodeIndex<usize>,
                leaf: NodeIndex<usize>,
            ) -> Result<ProofPath<$digest>, ProofError> {
                if leaf > tree.len() {
                    return Err(ProofError::InvalidSize);
                }

                if !tree.get(leaf.index()).unwrap().is_leaf() {
                    return Err(ProofError::UnexpectedInternalNode);
                }

                let mut path = Vec::new();
                let mut current_idx = leaf;

                // Walk up from leaf to root
                while let Some(node) = tree.get(current_idx.index()) {
                    if current_idx == root {
                        break;
                    }

                    if let Some(parent_idx) = node.parent() {
                        let parent = tree.get(parent_idx.index()).ok_or(ProofError::from(
                            TreeError::IndexOutOfBounds {
                                index: parent_idx.index(),
                                len: tree.len(),
                            },
                        ))?;

                        let children = parent.children();
                        let position = children.iter().position(|&idx| idx == current_idx).ok_or(
                            ProofError::from(TreeError::IndexOutOfBounds {
                                index: current_idx.index(),
                                len: tree.len(),
                            }),
                        )?;

                        let mut siblings = Vec::with_capacity(children.len() - 1);
                        for (i, &child_idx) in children.iter().enumerate() {
                            if i != position {
                                let sibling = tree.get(child_idx.index()).ok_or(
                                    ProofError::from(TreeError::IndexOutOfBounds {
                                        index: child_idx.index(),
                                        len: tree.len(),
                                    }),
                                )?;
                                siblings.push(sibling.hash().clone());
                            }
                        }

                        path.push(ProofLevel::new(position, siblings));

                        // Move to parent for next iteration
                        current_idx = parent_idx;
                    } else {
                        // Reached a node with no parent (should be root)
                        break;
                    }
                }
                Ok(ProofPath::new(path))
            }
        }

        #[pymethods]
        impl $name {
            #[inline]
            fn expected(&self) -> &[u8] {
                self.inner.expected_root().as_slice()
            }

            #[classmethod]
            fn generate(
                _cls: &PyBound<'_, PyType>,
                tree: &PyBound<'_, PyAny>,
                leaves: Vec<isize>,
            ) -> PyResult<Self> {
                Python::attach(|py| {
                    // Import the mrkle module to verify tree type
                    let module = PyModule::import(py, intern!(py, "mrkle"))?;
                    MRKLE_MODULE.get_or_init_py_attached(py, || module.clone().unbind());

                    let ttype = module.getattr(intern!(py, "MrkleTree"))?;

                    if !tree.is_instance(&ttype)? {
                        return Err(PyTypeError::new_err("Expected a MrkleTree instance"));
                    }

                    if leaves.is_empty() {
                        return Err(PyValueError::new_err(
                            "Must provide at least one leaf index",
                        ));
                    }

                    // Get the _inner attribute which contains the actual Rust tree
                    let inner_attr = tree.getattr(intern!(py, "_inner"))?;
                    let internal_tree = inner_attr.extract::<$tree>()?;

                    // Get tree information
                    let tree_len = internal_tree.len() as isize;
                    let root = internal_tree
                        .inner
                        .start()
                        .ok_or_else(|| PyTreeError::new_err("Tree has no root"))?;

                    // Convert Python indices (with negative indexing support) to NodeIndex
                    let mut node_indices = Vec::with_capacity(leaves.len());

                    for &index in &leaves {
                        let mut normalized_idx = index;

                        // Handle negative indexing
                        if normalized_idx < 0 {
                            normalized_idx = tree_len
                                .checked_add(normalized_idx)
                                .ok_or_else(|| PyIndexError::new_err("index out of range"))?;
                        }

                        // Validate bounds
                        if normalized_idx < 0 || normalized_idx >= tree_len {
                            return Err(PyIndexError::new_err(format!(
                                "leaf index {} out of range (tree has {} leaves)",
                                index, tree_len
                            )));
                        }

                        node_indices.push(NodeIndex::new(normalized_idx as usize));
                    }

                    // Generate paths for each leaf
                    let mut paths = Vec::with_capacity(node_indices.len());
                    for &leaf_idx in &node_indices {
                        let path = Self::generate_path(&internal_tree, root, leaf_idx)
                            .map_err(|e| PyProofError::new_err(format!("{e}")))?;
                        paths.push(path);
                    }

                    // Get expected root hash
                    let expected_root = internal_tree.inner.root().hash().clone();

                    // Create the proof
                    let proof = MrkleProof::new(paths, None, expected_root);
                    Ok(Self { inner: proof })
                })
            }

            fn verify(&self, leaves: PyBound<'_, PyAny>) -> PyResult<bool> {
                Python::attach(|py| {
                    // Import the mrkle module and cache it
                    let module = PyModule::import(py, "mrkle")?;
                    MRKLE_MODULE.get_or_init_py_attached(py, || module.clone().unbind());
                    let node_type = module.getattr("MrkleNode")?;

                    // Helper closure: decode hex string into bytes
                    let decode_hex = |hex_str: &str| -> PyResult<Vec<u8>> {
                        let mut buffer = vec![0; hex_str.len() / 2];
                        faster_hex::hex_decode(hex_str.as_bytes(), &mut buffer)
                            .map_err(|e| PyValueError::new_err(e.to_string()))?;
                        Ok(buffer)
                    };

                    // Convert leaves input into Vec<GenericArray<$digest>>
                    let leaves_vec: PyResult<Vec<GenericArray<$digest>>> = (|| {
                        if leaves.is_instance(&node_type)? {
                            // Single MrkleNode
                            let inner = leaves.getattr("_inner")?.extract::<$node>()?;
                            Ok(vec![GenericArray::<$digest>::clone_from_slice(
                                &inner.digest(),
                            )])
                        } else if let Ok(bytes) = leaves.extract::<&[u8]>() {
                            // Single bytes
                            Ok(vec![GenericArray::<$digest>::clone_from_slice(bytes)])
                        } else if let Ok(hex_str) = leaves.extract::<String>() {
                            // Single hex string
                            Ok(vec![GenericArray::<$digest>::clone_from_slice(
                                &decode_hex(&hex_str)?,
                            )])
                        } else if let Ok(vec_bytes) = leaves.extract::<Vec<Vec<u8>>>() {
                            // Multiple bytes
                            Ok(vec_bytes
                                .iter()
                                .map(|v| GenericArray::<$digest>::clone_from_slice(v))
                                .collect())
                        } else if let Ok(vec_hex) = leaves.extract::<Vec<String>>() {
                            // Multiple hex strings
                            let decoded: PyResult<Vec<GenericArray<$digest>>> = vec_hex
                                .iter()
                                .map(|s| {
                                    decode_hex(s).map(|bytes| {
                                        GenericArray::<$digest>::clone_from_slice(&bytes)
                                    })
                                })
                                .collect();
                            decoded
                        } else if let Ok(seq) = leaves.downcast::<PySequence>() {
                            // Generic sequence of MrkleNodes
                            let mut result = Vec::with_capacity(seq.len()?);
                            for item in seq.try_iter()? {
                                let item = item?;
                                if item.is_instance(&node_type)? {
                                    let inner = item.getattr("_inner")?.extract::<$node>()?;
                                    result.push(GenericArray::<$digest>::clone_from_slice(
                                        &inner.digest(),
                                    ));
                                } else {
                                    return Err(PyValueError::new_err(
                                        "Sequence contains non-MrkleNode item",
                                    ));
                                }
                            }
                            Ok(result)
                        } else {
                            Err(PyTypeError::new_err(
                                "Expected bytes, hex string, MrkleNode, or a sequence thereof",
                            ))
                        }
                    })();

                    // Verify using inner tree
                    self.inner
                        .verify(leaves_vec?)
                        .map_err(|e| PyProofError::new_err(format!("{e}")))
                })
            }

            #[inline]
            fn get_path(&self, index: usize) -> PyResult<String> {
                if index >= self.inner.paths().len() {
                    return Err(PyIndexError::new_err(format!(
                        "path index {} out of range (proof has {} paths)",
                        index,
                        self.inner.paths().len()
                    )));
                }

                serde_json::to_string_pretty(&self.inner.paths()[index])
                    .map_err(|e| PyValueError::new_err(format!("Serialization error: {e}")))
            }

            #[staticmethod]
            fn dtype() -> $digest {
                <$digest>::new()
            }

            fn __len__(&self) -> usize {
                self.inner.paths().len()
            }

            fn __repr__(&self) -> String {
                format!("<_mrkle_rs.proof.{} object at {:p}>", $classname, self)
            }

            fn __str__(&self) -> String {
                format!(
                    "{}(paths={}, root={})",
                    $classname,
                    self.inner.paths().len(),
                    &faster_hex::hex_string(self.inner.expected_root())
                )
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
pub(crate) fn register_proof(m: &PyBound<'_, PyModule>) -> PyResult<()> {
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
