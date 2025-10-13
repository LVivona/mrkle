#![allow(dead_code)]
#![allow(non_camel_case_types)]

use std::collections::HashMap;
use std::io::{Read, Write};

use serde::Serialize;

use crypto::digest::Digest;

use pyo3::exceptions::{PyIndexError, PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::pycell::PyRef;
use pyo3::sync::OnceLockExt;
use pyo3::types::{PyAny, PyBytes, PyDict, PyIterator, PyList, PySequence, PySlice, PyType};
use pyo3::{Bound as PyBound, Py, intern};

use pyo3_file::PyFileLikeObject;

use crate::{
    MRKLE_MODULE,
    codec::{JsonCodec, MerkleTreeJson, PyCodecFormat},
    crypto::{
        PyBlake2b512Wrapper, PyBlake2s256Wrapper, PyKeccak224Wrapper, PyKeccak256Wrapper,
        PyKeccak384Wrapper, PyKeccak512Wrapper, PySha1Wrapper, PySha224Wrapper, PySha256Wrapper,
        PySha384Wrapper, PySha512Wrapper,
    },
    errors::{NodeError as PyNodeError, SerdeError, TreeError},
    utils::extract_to_bytes,
};

use mrkle::error::NodeError;
use mrkle::{GenericArray, IndexType, Iter, MrkleNode, MutNode, Node, NodeIndex, Tree};

trait PyMrkleNode<D: Digest, Ix: IndexType>: Node<Ix> + MutNode<Ix> + Sized {
    fn hash(&self) -> &GenericArray<D>;
    fn leaf(data: impl AsRef<[u8]>) -> Self;
    fn internal(tree: &Tree<Self, Ix>, children: Vec<NodeIndex<Ix>>) -> Result<Self, NodeError>;
}

macro_rules! py_mrkle_node {
    ($name:ident, $digest:ty, $classname:literal) => {
        #[repr(C)]
        #[derive(Clone)]
        #[pyclass(name = $classname, frozen, eq)]
        pub struct $name {
            pub inner: MrkleNode<Box<[u8]>, $digest, usize>,
        }

        unsafe impl Sync for $name {}
        unsafe impl Send for $name {}

        impl PartialEq for $name {
            fn eq(&self, other: &Self) -> bool {
                self.inner == other.inner
            }
        }

        impl Eq for $name {}

        impl MutNode<usize> for $name {
            fn set_parent(&mut self, parent: NodeIndex<usize>) {
                self.parent = Some(parent);
            }
        }

        impl $name {
            pub(crate) fn internal(
                tree: &Tree<$name, usize>,
                children: Vec<NodeIndex<usize>>,
            ) -> Result<Self, NodeError> {
                let mut hasher = <$digest>::new();
                children.iter().try_for_each(|&idx| {
                    if let Some(node) = tree.get(idx.index()) {
                        if node.parent().is_some() {
                            return Err(NodeError::ParentConflict {
                                parent: node.parent().unwrap().index(),
                                child: idx.index(),
                            });
                        }
                        hasher.update(&node.hash());
                        Ok(())
                    } else {
                        Err(NodeError::NodeNotFound { index: idx.index() })
                    }
                })?;

                let hash = hasher.finalize();

                Ok(Self {
                    inner: MrkleNode::internal_with_hash(hash, children),
                })
            }
        }

        impl Node<usize> for $name {
            fn children(&self) -> Vec<NodeIndex<usize>> {
                self.inner.children()
            }

            fn parent(&self) -> Option<NodeIndex<usize>> {
                self.inner.parent()
            }
        }

        impl PyMrkleNode<$digest, usize> for $name {
            fn hash(&self) -> &GenericArray<$digest> {
                self.inner.hash()
            }

            fn leaf(data: impl AsRef<[u8]>) -> Self {
                Self {
                    inner: MrkleNode::<Box<[u8]>, $digest, usize>::leaf(data.as_ref().into()),
                }
            }

            fn internal(
                tree: &Tree<$name, usize>,
                children: Vec<NodeIndex<usize>>,
            ) -> Result<Self, NodeError> {
                Ok(<$name>::internal(tree, children)?)
            }
        }

        #[pymethods]
        impl $name {
            #[staticmethod]
            pub fn dtype() -> $digest {
                <$digest>::new()
            }

            #[pyo3(name = "parent")]
            pub fn parent_index(&self) -> PyResult<Option<usize>> {
                Ok(self.inner.parent().map(|parent| parent.index()))
            }

            #[inline]
            #[pyo3(name = "children")]
            pub fn children_indices(&self) -> PyResult<Vec<usize>> {
                Ok(self
                    .inner
                    .children()
                    .iter()
                    .map(|node| node.index())
                    .collect())
            }

            pub fn value(&self) -> Option<&[u8]> {
                self.inner.value().map(|value| value.as_ref())
            }

            #[inline]
            pub fn digest(&self) -> &[u8] {
                self.inner.hash()
            }

            #[inline]
            pub fn hexdigest(&self) -> String {
                faster_hex::hex_string(self.inner.hash())
            }

            #[inline]
            #[staticmethod]
            pub fn leaf(payload: Vec<u8>) -> Self {
                let bytes: Box<[u8]> = payload.into_boxed_slice();
                Self {
                    inner: MrkleNode::<Box<[u8]>, $digest, usize>::leaf(bytes),
                }
            }

            #[inline]
            #[staticmethod]
            pub fn leaf_with_digest(
                payload: PyBound<'_, PyBytes>,
                hash: PyBound<'_, PyBytes>,
            ) -> Self {
                let bytes: Box<[u8]> = payload.as_bytes().to_vec().into_boxed_slice();
                let value = GenericArray::<$digest>::clone_from_slice(&hash.as_bytes());

                Self {
                    inner: MrkleNode::<Box<[u8]>, $digest, usize>::leaf_with_hash(bytes, value),
                }
            }

            #[inline]
            pub fn is_leaf(&self) -> bool {
                self.inner.is_leaf()
            }

            #[inline]
            pub fn __repr__(&self) -> String {
                format!("<_mrkle_rs.tree.{} object at {:p}>", $classname, self)
            }

            #[inline]
            pub fn __str__(&self) -> String {
                self.__repr__()
            }
        }

        impl std::ops::Deref for $name {
            type Target = MrkleNode<Box<[u8]>, $digest, usize>;

            fn deref(&self) -> &Self::Target {
                &self.inner
            }
        }

        impl std::ops::DerefMut for $name {
            fn deref_mut(&mut self) -> &mut Self::Target {
                &mut self.inner
            }
        }

        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{:?}", self.inner)
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}", self.inner)
            }
        }

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
                let inner = MrkleNode::<Box<[u8]>, $digest, usize>::deserialize(deserializer)?;
                Ok(Self { inner })
            }
        }
    };
}

py_mrkle_node!(PyMrkleNode_Sha1, PySha1Wrapper, "MrkleNodeSha1");
py_mrkle_node!(PyMrkleNode_Sha224, PySha224Wrapper, "MrkleNodeSha224");
py_mrkle_node!(PyMrkleNode_Sha256, PySha256Wrapper, "MrkleNodeSha256");
py_mrkle_node!(PyMrkleNode_Sha384, PySha384Wrapper, "MrkleNodeSha384");
py_mrkle_node!(PyMrkleNode_Sha512, PySha512Wrapper, "MrkleNodeSha512");
py_mrkle_node!(PyMrkleNode_Blake2b, PyBlake2b512Wrapper, "MrkleNodeBlake2b");
py_mrkle_node!(PyMrkleNode_Blake2s, PyBlake2s256Wrapper, "MrkleNodeBlake2s");
py_mrkle_node!(
    PyMrkleNode_Keccak224,
    PyKeccak224Wrapper,
    "MrkleNodeKeccak224"
);
py_mrkle_node!(
    PyMrkleNode_Keccak256,
    PyKeccak256Wrapper,
    "MrkleNodeKeccak256"
);
py_mrkle_node!(
    PyMrkleNode_Keccak384,
    PyKeccak384Wrapper,
    "MrkleNodeKeccak384"
);
py_mrkle_node!(
    PyMrkleNode_Keccak512,
    PyKeccak512Wrapper,
    "MrkleNodeKeccak512"
);

macro_rules! py_mrkle_tree {
    ($name:ident, $iter_name:ident, $node:ty, $digest:ty, $classname:literal, $itername:literal) => {
        #[repr(C)]
        #[pyclass(name = $classname, eq)]
        pub struct $name {
            pub inner: Tree<$node, usize>,
        }

        impl Clone for $name {
            fn clone(&self) -> Self {
                Self {
                    inner: self.inner.clone(),
                }
            }
        }

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
                let inner = Tree::deserialize(deserializer)?;
                Ok(Self { inner })
            }
        }

        impl PartialEq for $name {
            fn eq(&self, other: &Self) -> bool {
                if self.root().as_ref().ok() != other.root().as_ref().ok() {
                    return false;
                }

                self.len() == other.len() && self.iter().eq(other.iter())
            }
        }
        impl Eq for $name {}

        #[pyclass(name = $itername)]
        struct $iter_name {
            tree: Py<$name>,
            queue: std::collections::VecDeque<usize>,
        }

        #[pymethods]
        impl $iter_name {
            fn __iter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
                slf
            }

            fn __next__(mut slf: PyRefMut<'_, Self>) -> PyResult<Option<$node>> {
                // Pop from queue first (mutable borrow of slf)
                let index = match slf.queue.pop_front() {
                    Some(idx) => idx,
                    None => return Ok(None),
                };

                // Now we can borrow tree and work with it
                Python::attach(|py| {
                    let tree = slf.tree.borrow(py);

                    if let Some(node) = tree.inner.get(index) {
                        // Get children indices before cloning
                        let children_indices = tree.get_children_indices(NodeIndex::new(index));
                        let node_clone = node.clone();

                        // Drop the tree borrow before mutating slf again
                        drop(tree);

                        // Now add children to queue (mutable borrow of slf)
                        for child_idx in children_indices {
                            slf.queue.push_back(child_idx.index());
                        }

                        Ok(Some(node_clone))
                    } else {
                        Ok(None)
                    }
                })
            }
        }

        #[pymethods]
        impl $name {
            #[inline]
            fn root(&self) -> PyResult<&[u8]> {
                Ok(self
                    .inner
                    .try_root()
                    .map_err(|e| TreeError::new_err(format!("{e}")))?
                    .hash())
            }

            #[inline]
            pub fn is_empty(&self) -> bool {
                self.inner.is_empty()
            }

            #[inline]
            pub fn capacity(&self) -> usize {
                self.inner.capacity()
            }

            #[inline]
            #[pyo3(name = "leaves")]
            pub fn leaves_py(&self) -> Vec<$node> {
                self.leaf_indices()
                    .iter()
                    .map(|&index| self.inner[index].clone())
                    .collect()
            }

            #[staticmethod]
            pub fn dtype() -> $digest {
                <$digest>::new()
            }

            #[inline]
            #[classmethod]
            #[pyo3(text_signature = "(cls, data : Dict[str, bytes])")]
            pub fn from_dict(
                _cls: &PyBound<'_, PyType>,
                data: PyBound<'_, PyDict>,
            ) -> PyResult<Self> {
                let mut inner = Tree::new();

                traverse_dict_depth(data, &mut inner)?;

                Ok(Self { inner })
            }

            #[inline]
            #[classmethod]
            pub fn from_leaves(
                _cls: &PyBound<'_, PyType>,
                leaves: PyBound<'_, PyAny>,
            ) -> PyResult<Self> {
                let mut tree = Tree::<$node, usize>::new();

                let mut leaves = if let Ok(leaves) = leaves.extract::<Vec<PyBound<'_, PyAny>>>() {
                    leaves
                        .into_iter()
                        .map(|obj| extract_to_bytes(&obj))
                        .collect::<PyResult<Vec<_>>>()
                } else if let Ok(leaves) = leaves.extract::<PyBound<'_, PyIterator>>() {
                    leaves
                        .try_iter()?
                        .map(|obj| obj.and_then(|obj| extract_to_bytes(&obj)))
                        .collect::<PyResult<Vec<_>>>()
                } else {
                    return Err(PyTypeError::new_err(
                        "Unable to construct tree due to wrong types",
                    ));
                }?;

                if leaves.is_empty() {
                    return Ok(Self { inner: tree });
                }

                if leaves.len() == 1 {
                    let payload = leaves.pop().unwrap();

                    let leaf = <$node>::leaf(payload);

                    let leaf_idx = tree.push(leaf);

                    let root = <$node>::internal(&tree, vec![leaf_idx])
                        .map_err(|e| PyNodeError::new_err(format!("{e}")))?;
                    let root_idx = tree.push(root);
                    tree[leaf_idx].parent = Some(root_idx);
                    tree.set_root(Some(root_idx));

                    return Ok(Self { inner: tree });
                }

                let mut queue: std::collections::VecDeque<NodeIndex<usize>> =
                    std::collections::VecDeque::new();

                for payload in leaves {
                    let idx = tree.push(<$node>::leaf(payload));
                    queue.push_back(idx);
                }

                while queue.len() > 1 {
                    let lhs = queue.pop_front().unwrap();
                    let rhs = queue.pop_front().unwrap();

                    let parent_idx = tree.push(
                        <$node>::internal(&tree, vec![lhs, rhs])
                            .map_err(|e| PyNodeError::new_err(format!("{e}")))?,
                    );

                    tree[lhs].parent = Some(parent_idx);
                    tree[rhs].parent = Some(parent_idx);

                    queue.push_back(parent_idx);
                }
                tree.set_root(queue.pop_front());

                Ok(Self { inner: tree })
            }

            fn __getitem__<'py>(
                &self,
                py: Python<'py>,
                key: &PyBound<'py, PyAny>,
            ) -> PyResult<PyBound<'py, PyAny>> {
                let module = PyModule::import(py, intern!(py, "mrkle"))?;
                MRKLE_MODULE.get_or_init_py_attached(py, || module.clone().unbind());
                let node_cls = module.getattr(intern!(py, "MrkleNode"))?;

                if let Ok(mut index) = key.extract::<isize>() {
                    let len = self.len() as isize;

                    if index < 0 {
                        index = len
                            .checked_add(index)
                            .ok_or_else(|| PyIndexError::new_err("index out of range"))?;
                    }

                    if index < 0 || index >= len {
                        return Err(PyIndexError::new_err("index out of range"));
                    }

                    let idx = index as usize;
                    let value = self
                        .get(idx)
                        .ok_or_else(|| PyIndexError::new_err("index out of range"))?;

                    let py_node = node_cls
                        .call_method1(intern!(py, "construct_from_node"), (value.clone(),))?;

                    return Ok(py_node);
                }

                if let Ok(slice) = key.extract::<PyBound<'_, PySlice>>() {
                    let indices = slice.indices(self.len() as isize)?;
                    let (start, stop, step) = (indices.start, indices.stop, indices.step);

                    let mut out = Vec::new();
                    let mut i = start;
                    while if step > 0 { i < stop } else { i > stop } {
                        let idx = i as usize;
                        if let Some(value) = self.get(idx) {
                            let py_node = node_cls.call_method1(
                                intern!(py, "construct_from_node"),
                                (value.clone(),),
                            )?;
                            out.push(py_node);
                        }
                        i += step;
                    }

                    return Ok(PyList::new(py, &out)?.into_any());
                }
                if let Ok(seq) = key.extract::<PyBound<'_, PySequence>>() {
                    let mut out = Vec::new();

                    for item in seq.try_iter()? {
                        let mut index: isize = item?.extract()?;
                        let len = self.len() as isize;

                        if index < 0 {
                            index = len
                                .checked_add(index)
                                .ok_or_else(|| PyIndexError::new_err("index out of range"))?;
                        }

                        if index < 0 || index >= len {
                            return Err(PyIndexError::new_err("index out of range"));
                        }

                        let idx = index as usize;
                        if let Some(value) = self.get(idx) {
                            let py_node = node_cls.call_method1(
                                intern!(py, "construct_from_node"),
                                (value.clone(),),
                            )?;
                            out.push(py_node);
                        }
                    }

                    return Ok(PyList::new(py, &out)?.into_any());
                }

                Err(PyTypeError::new_err(
                    "indices must be int, slice, or sequence of ints",
                ))
            }

            fn __iter__(slf: PyRef<'_, Self>) -> PyResult<$iter_name> {
                let mut queue = std::collections::VecDeque::new();

                if let Some(root) = slf.inner.start() {
                    queue.push_back(root.index());
                }

                Ok($iter_name {
                    tree: slf.into(),
                    queue,
                })
            }

            fn __len__(&self) -> usize {
                self.len()
            }

            fn __repr__(&self) -> String {
                format!("<_mrkle_rs.tree.{} object at {:p}>", $classname, self)
            }

            fn __str__(&self) -> String {
                self.__repr__()
            }

            fn to_string(&self) -> String {
                format!("{}", self.inner)
            }

            #[pyo3(text_signature = "(self, fp, *, indent : Optional[int] = None encoding : Literal['bytes', 'utf-8'])")]
            fn dumps<'py>(
                &self,
                py: Python<'py>,
                fp: Option<Py<PyAny>>,
                indent: Option<usize>,
                encoding: PyCodecFormat,
            ) -> PyResult<Bound<'py, PyAny>> {
                let buf = JsonCodec::<&[u8], $digest>::new(
                    self.inner
                        .start()
                        .and_then(|root| self.from_node(root, &mut HashMap::new()))
                        .ok_or_else(|| SerdeError::new_err("JSON could not be serialized."))?,
                );

                // Generate the JSON data
                let json_data = match encoding {
                    PyCodecFormat::UTF_8 => {
                        let json_string = match indent {
                            Some(spaces) if spaces > 0 => {
                                let indent_str = " ".repeat(spaces);
                                let formatter = serde_json::ser::PrettyFormatter::with_indent(
                                    indent_str.as_bytes(),
                                );
                                let mut vec = Vec::new();
                                let mut serializer =
                                    serde_json::Serializer::with_formatter(&mut vec, formatter);
                                buf.serialize(&mut serializer)
                                    .map_err(|e| SerdeError::new_err(format!("{}", e)))?;
                                String::from_utf8(vec)
                                    .map_err(|e| SerdeError::new_err(format!("{}", e)))?
                            }
                            _ => buf
                                .to_string()
                                .map_err(|e| SerdeError::new_err(format!("{}", e)))?,
                        };
                        json_string.into_bytes()
                    }
                    PyCodecFormat::BYTES => match indent {
                        Some(spaces) if spaces > 0 => {
                            let indent_str = " ".repeat(spaces);
                            let formatter = serde_json::ser::PrettyFormatter::with_indent(
                                indent_str.as_bytes(),
                            );
                            let mut vec = Vec::new();
                            let mut serializer =
                                serde_json::Serializer::with_formatter(&mut vec, formatter);
                            buf.serialize(&mut serializer)
                                .map_err(|e| SerdeError::new_err(format!("{}", e)))?;
                            vec
                        }
                        _ => buf
                            .to_vec()
                            .map_err(|e| SerdeError::new_err(format!("{}", e)))?,
                    },
                };

                // If fp is provided, write to file
                if let Some(file_obj) = fp {
                    let mut file = PyFileLikeObject::with_requirements(
                        file_obj.into(),
                        true,  // write
                        false, // read
                        false, // seek
                        false,
                    )?;

                    file.write_all(&json_data).map_err(|e| {
                        PyErr::new::<pyo3::exceptions::PyIOError, _>(format!(
                            "Failed to write to file: {}",
                            e
                        ))
                    })?;

                    // Return None to match Python's json.dump behavior
                    Ok(py.None().into_bound(py))
                } else {
                    // Return the data as string or bytes
                    let output = match encoding {
                        PyCodecFormat::UTF_8 => String::from_utf8(json_data)
                            .map_err(|e| SerdeError::new_err(format!("{}", e)))?
                            .into_pyobject(py)?
                            .into_any(),
                        PyCodecFormat::BYTES => json_data.into_pyobject(py)?.into_any(),
                    };
                    Ok(output)
                }
            }

            // Update the loads method in the macro
            #[staticmethod]
            #[pyo3(text_signature = "(data : Union[bytes, str])")]
            fn loads(
                py: Python<'_>,
                data: &Bound<'_, PyAny>,
            ) -> PyResult<Self> {
                // Try to extract as bytes or string
                let json_codec = if let Ok(bytes) = data.extract::<&[u8]>() {
                    JsonCodec::<Box<[u8]>, $digest>::from_slice(bytes)
                } else if let Ok(string) = data.extract::<String>() {
                    JsonCodec::<Box<[u8]>, $digest>::from_str(string.as_str())
                } else {
                    return Err(PyTypeError::new_err(
                        "Expected bytes or string for JSON deserialization",
                    ));
                }
                .map_err(|e| {
                    SerdeError::new_err(format!("{}", e))
                })?;

                // Validate hash type and size
                if !json_codec.validate_hash_type() {
                    return Err(SerdeError::new_err(format!(
                        "Hash type mismatch expected {}, got {}",
                        <$digest as crate::crypto::PyDigest>::algorithm_name().to_string(),
                        json_codec.hash_type
                    )));
                }

                if !json_codec.validate_hash_size() {
                    return Err(SerdeError::new_err(format!(
                        "Hash size mismatch expected {}, got {}",
                        <$digest>::output_size(),
                        json_codec.hash_size
                    )));
                }

                // Build tree from JSON structure
                let mut tree = Tree::<$node, usize>::new();
                let root_idx =
                    Self::build_tree_from_json(py, json_codec.into_tree(), &mut tree)?;
                tree.set_root(Some(root_idx));

                Ok(Self { inner: tree })
            }

            // Add a load method for reading from file
            #[staticmethod]
            #[pyo3(text_signature = "(fp)")]
            fn load(fp: Py<PyAny>) -> PyResult<Self> {
                Python::attach(|py| {

                    let mut file = PyFileLikeObject::with_requirements(
                        fp.into(),
                        false, // write
                        true,  // read
                        false, // seek
                        false,
                    )?;

                    let mut buffer = Vec::new();
                    file.read_to_end(&mut buffer).map_err(|e| {
                        PyErr::new::<pyo3::exceptions::PyIOError, _>(format!(
                            "Failed to read from file {}.",
                            e
                        ))
                    })?;

                    // Deserialize from the buffer
                    let json_codec = JsonCodec::<Box<[u8]>, $digest>::from_slice(&buffer)
                        .map_err(|e| {
                            SerdeError::new_err(format!(
                                "{}",
                                e
                            ))
                        })?;

                    // Validate hash type and size
                    if !json_codec.validate_hash_type() {
                        return Err(SerdeError::new_err(format!(
                            "Hash type mismatch expected {}, got {}.",
                            <$digest as crate::crypto::PyDigest>::algorithm_name().to_string(),
                            json_codec.hash_type,
                        )));
                    }

                    if !json_codec.validate_hash_size() {
                        return Err(SerdeError::new_err(format!(
                            "Hash size mismatch expected {}, got {}.",
                            <$digest>::output_size(),
                            json_codec.hash_size
                        )));
                    }

                    // Build tree from JSON structure
                    let mut tree = Tree::<$node, usize>::new();
                    let root_idx =
                        Self::build_tree_from_json(py, json_codec.into_tree(), &mut tree)?;
                    tree.set_root(Some(root_idx));

                    Ok(Self { inner: tree })
                })
            }
        }

        impl $name {
            /// Return the length of the [`Tree`] i.e # of nodes
            #[inline]
            pub fn len(&self) -> usize {
                self.inner.len()
            }

            /// Return children Nodes as immutable references of the given index.
            #[inline]
            pub fn get_children(&self, index: NodeIndex<usize>) -> Vec<&$node> {
                self.get(index.index()).map_or(Vec::new(), |node| {
                    node.children()
                        .iter()
                        .map(|&idx| self.get(idx.index()).unwrap())
                        .collect()
                })
            }

            /// Return a childen of the indexed node as a vector of [`NodeIndex<Ix>`].
            #[inline]
            pub fn get_children_indices(&self, index: NodeIndex<usize>) -> Vec<NodeIndex<usize>> {
                self.get(index.index())
                    .map(|node| node.children())
                    .unwrap_or_default()
            }

            /// Returns a reference to an element [`MrkleNode<T, D, Ix>`].
            pub fn get<I>(&self, index: I) -> Option<&I::Output>
            where
                I: std::slice::SliceIndex<[$node]>,
            {
                self.inner.get(index)
            }

            /// Return a vector of  [`NodeIndex<Ix>`].
            #[inline]
            pub fn leaf_indices(&self) -> Vec<NodeIndex<usize>> {
                self.inner.leaf_indices()
            }

            /// Return a vector of  [`Node`] references.
            #[inline]
            pub fn leaves(&self) -> Vec<&$node> {
                self.inner.leaves()
            }

            /// Searches for a node by checking its claimed parent-child relationship.
            ///
            /// Returns the node’s index if found and properly connected.
            pub fn find(&self, node: &$node) -> Option<NodeIndex<usize>> {
                self.inner.find(node)
            }

            /// Returns Iterator pattern [`Iter`] which returns a unmutable Node reference.
            pub fn iter(&self) -> Iter<'_, $node, usize> {
                self.inner.iter()
            }

            fn build_tree_from_json<'py>(
                py: Python<'py>,
                node: MerkleTreeJson<Box<[u8]>>,
                tree: &mut Tree<$node, usize>,
            ) -> PyResult<NodeIndex<usize>> {
                match node {
                    MerkleTreeJson::Leaf { hash, value } => {
                        // Create leaf node with pre-computed hash
                        let leaf = <$node>::leaf_with_digest(
                            PyBytes::new(py, &*value),
                            PyBytes::new(py, hash.as_slice()),
                        );
                        Ok(tree.push(leaf))
                    }
                    MerkleTreeJson::Parent { children, .. } => {
                        // Recursively build children first
                        let mut child_indices = Vec::new();
                        for child in children {
                            let child_idx = Self::build_tree_from_json(py, child, tree)?;
                            child_indices.push(child_idx);
                        }

                        // Create parent node with pre-computed hash
                        // We need a custom method to create parent with existing hash
                        let parent = Self::create_parent_with_hash(tree, child_indices.clone())?;
                        let parent_idx = tree.push(parent);

                        // Set parent references in children
                        for &child_idx in &child_indices {
                            tree[child_idx].set_parent(parent_idx);
                        }

                        Ok(parent_idx)
                    }
                }
            }

            fn create_parent_with_hash(
                tree: &Tree<$node, usize>,
                children: Vec<NodeIndex<usize>>,
            ) -> PyResult<$node> {
                <$node>::internal(tree, children).map_err(|e| PyNodeError::new_err(format!("{e}")))
            }

            fn from_node(
                &self,
                index: NodeIndex<usize>,
                visited: &mut HashMap<usize, ()>,
            ) -> Option<MerkleTreeJson<&[u8]>> {
                let idx = index.index();
                if visited.contains_key(&idx) {
                    return None;
                }
                visited.insert(idx, ());

                let node = &self.get(idx).unwrap();
                let hash = node.hash().to_vec();
                let children_indices = node.children();

                if node.is_leaf() {
                    // Leaf node
                    let value = node.value()?.clone();
                    Some(MerkleTreeJson::Leaf { hash, value })
                } else {
                    // Parent node
                    let children: Vec<_> = children_indices
                        .iter()
                        .filter_map(|&child_idx| self.from_node(child_idx, visited))
                        .collect();

                    Some(MerkleTreeJson::Parent { hash, children })
                }
            }
        }
    };
}

py_mrkle_tree!(
    PyMrkleTreeSha1,
    PyMrkleTreeIterSha1,
    PyMrkleNode_Sha1,
    PySha1Wrapper,
    "MrkleTreeSha1",
    "MrkleTreeIterSha1"
);

py_mrkle_tree!(
    PyMrkleTreeSha224,
    PyMrkleTreeIterSha224,
    PyMrkleNode_Sha224,
    PySha224Wrapper,
    "MrkleTreeSha224",
    "MrkleTreeIterSha224"
);

py_mrkle_tree!(
    PyMrkleTreeSha256,
    PyMrkleTreeIterSha256,
    PyMrkleNode_Sha256,
    PySha256Wrapper,
    "MrkleTreeSha256",
    "MrkleTreeIterSha256"
);

py_mrkle_tree!(
    PyMrkleTreeSha384,
    PyMrkleTreeIterSha384,
    PyMrkleNode_Sha384,
    PySha384Wrapper,
    "MrkleTreeSha384",
    "MrkleTreeIterSha384"
);

py_mrkle_tree!(
    PyMrkleTreeSha512,
    PyMrkleTreeIterSha512,
    PyMrkleNode_Sha512,
    PySha512Wrapper,
    "MrkleTreeSha512",
    "MrkleTreeIterSha512"
);

py_mrkle_tree!(
    PyMrkleTreeBlake2b,
    PyMrkleTreeIterBlake2b,
    PyMrkleNode_Blake2b,
    PyBlake2b512Wrapper,
    "MrkleTreeBlake2b",
    "MrkleTreeIterBlake2b"
);

py_mrkle_tree!(
    PyMrkleTreeBlake2s,
    PyMrkleTreeIterBlake2s,
    PyMrkleNode_Blake2s,
    PyBlake2s256Wrapper,
    "MrkleTreeBlake2s",
    "MrkleTreeIterBlake2s"
);

py_mrkle_tree!(
    PyMrkleTreeKeccak224,
    PyMrkleTreeIterKeccak224,
    PyMrkleNode_Keccak224,
    PyKeccak224Wrapper,
    "MrkleTreeKeccak224",
    "MrkleTreeIterKeccak224"
);

py_mrkle_tree!(
    PyMrkleTreeKeccak256,
    PyMrkleTreeIterKeccak256,
    PyMrkleNode_Keccak256,
    PyKeccak256Wrapper,
    "MrkleTreeKeccak256",
    "MrkleTreeIterKeccak256"
);

py_mrkle_tree!(
    PyMrkleTreeKeccak384,
    PyMrkleTreeIterKeccak384,
    PyMrkleNode_Keccak384,
    PyKeccak384Wrapper,
    "MrkleTreeKeccak384",
    "MrkleTreeIterKeccak384"
);

py_mrkle_tree!(
    PyMrkleTreeKeccak512,
    PyMrkleTreeIterKeccak512,
    PyMrkleNode_Keccak512,
    PyKeccak512Wrapper,
    "MrkleTreeKeccak512",
    "MrkleTreeIterKeccak512"
);

fn traverse_dict_depth<N: PyMrkleNode<D, usize>, D: Digest>(
    dict: PyBound<'_, PyDict>,
    tree: &mut Tree<N, usize>,
) -> PyResult<()> {
    if dict.len() != 1 {
        return Err(PyValueError::new_err(
            "The dictionary can not contain more than one root.",
        ));
    }

    let root: Vec<_> = dict.items().iter().collect();

    if let Ok((_, value)) = root[0].extract::<(Bound<PyAny>, Bound<PyAny>)>() {
        let root = process_traversal(&value, tree)?;
        tree.set_root(Some(root));
        Ok(())
    } else {
        Err(PyValueError::new_err(format!(
            "Invalid value type for expected dict or bytes",
        )))
    }
}

fn process_traversal<N: PyMrkleNode<D, usize>, D: Digest>(
    value: &Bound<'_, PyAny>,
    tree: &mut Tree<N, usize>,
) -> PyResult<NodeIndex<usize>> {
    if let Ok(child_dict) = value.downcast::<PyDict>() {
        let mut indices: Vec<NodeIndex<usize>> = Vec::new();

        // Process all children
        for (_, child) in child_dict.iter() {
            let child_id: NodeIndex<usize> = process_traversal(&child, tree)?;
            indices.push(child_id);
        }

        // Create internal node from children
        let node_id = tree
            .push(N::internal(tree, indices).map_err(|e| PyNodeError::new_err(format!("{e}")))?);

        for child in tree[node_id].children() {
            tree[child.index()].set_parent(node_id);
        }

        return Ok(node_id);
    }

    if let Ok(child) = extract_to_bytes(&value) {
        let leaf = N::leaf(child);
        let index = tree.push(leaf);
        return Ok(index);
    }

    Err(PyValueError::new_err(format!(
        "Invalid value type for: expected dict or bytes",
    )))
}

/// Register MerkleTree data structure.
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
pub(crate) fn register_tree(m: &Bound<'_, PyModule>) -> PyResult<()> {
    let tree_m = PyModule::new(m.py(), "tree")?;

    // Node(s)
    tree_m.add_class::<PyMrkleNode_Sha1>()?;

    tree_m.add_class::<PyMrkleNode_Sha224>()?;
    tree_m.add_class::<PyMrkleNode_Sha256>()?;
    tree_m.add_class::<PyMrkleNode_Sha384>()?;
    tree_m.add_class::<PyMrkleNode_Sha512>()?;

    tree_m.add_class::<PyMrkleNode_Keccak224>()?;
    tree_m.add_class::<PyMrkleNode_Keccak256>()?;
    tree_m.add_class::<PyMrkleNode_Keccak384>()?;
    tree_m.add_class::<PyMrkleNode_Keccak512>()?;

    tree_m.add_class::<PyMrkleNode_Blake2b>()?;
    tree_m.add_class::<PyMrkleNode_Blake2s>()?;

    // Tree(s)
    tree_m.add_class::<PyMrkleTreeSha1>()?;

    tree_m.add_class::<PyMrkleTreeSha224>()?;
    tree_m.add_class::<PyMrkleTreeSha256>()?;
    tree_m.add_class::<PyMrkleTreeSha384>()?;
    tree_m.add_class::<PyMrkleTreeSha512>()?;

    tree_m.add_class::<PyMrkleTreeKeccak224>()?;
    tree_m.add_class::<PyMrkleTreeKeccak256>()?;
    tree_m.add_class::<PyMrkleTreeKeccak384>()?;
    tree_m.add_class::<PyMrkleTreeKeccak512>()?;
    tree_m.add_class::<PyMrkleTreeKeccak512>()?;

    tree_m.add_class::<PyMrkleTreeBlake2b>()?;
    tree_m.add_class::<PyMrkleTreeBlake2s>()?;

    // Iter(s)
    tree_m.add_class::<PyMrkleTreeIterSha1>()?;

    tree_m.add_class::<PyMrkleTreeIterSha224>()?;
    tree_m.add_class::<PyMrkleTreeIterSha256>()?;
    tree_m.add_class::<PyMrkleTreeIterSha384>()?;
    tree_m.add_class::<PyMrkleTreeIterSha512>()?;

    tree_m.add_class::<PyMrkleTreeIterKeccak224>()?;
    tree_m.add_class::<PyMrkleTreeIterKeccak256>()?;
    tree_m.add_class::<PyMrkleTreeIterKeccak384>()?;
    tree_m.add_class::<PyMrkleTreeIterKeccak512>()?;

    tree_m.add_class::<PyMrkleTreeIterBlake2b>()?;
    tree_m.add_class::<PyMrkleTreeIterBlake2s>()?;

    m.add_submodule(&tree_m)
}
