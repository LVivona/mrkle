#![allow(dead_code)]
#![allow(non_camel_case_types)]

use std::collections::VecDeque;

use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyType};
use pyo3::Bound as PyBound;

use crate::crypto::{
    PyBlake2b512Wrapper, PyBlake2s256Wrapper, PyKeccak224Wrapper, PyKeccak256Wrapper,
    PyKeccak384Wrapper, PyKeccak512Wrapper, PySha1Wrapper, PySha224Wrapper, PySha256Wrapper,
    PySha384Wrapper, PySha512Wrapper,
};
use mrkle::{
    GenericArray, Hasher, HexDisplay, MrkleHasher, MrkleNode, Node, NodeIndex, Tree, TreeView,
};

macro_rules! py_mrkle_node {
    ($name:ident, $digest:ty, $classname:literal) => {
        #[repr(C)]
        #[derive(Clone)]
        #[pyclass(name = $classname, frozen)]
        pub struct $name {
            inner: MrkleNode<Box<[u8]>, $digest, usize>,
        }

        unsafe impl Sync for $name {}
        unsafe impl Send for $name {}

        impl PartialEq for $name {
            fn eq(&self, other: &Self) -> bool {
                self.inner == other.inner
            }
        }

        impl Eq for $name {}

        impl $name {
            #[inline]
            pub fn hash(&self) -> &GenericArray<$digest> {
                self.inner.hash()
            }

            pub fn internal(children: Vec<NodeIndex<usize>>, hash: GenericArray<$digest>) -> Self {
                Self {
                    inner: MrkleNode::<Box<[u8]>, $digest, usize>::internal(children, hash),
                }
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

        #[pymethods]
        impl $name {
            #[inline]
            #[pyo3(name = "hash")]
            fn hash_str(&self) -> String {
                format!("{}", self.inner.to_hex())
            }

            #[inline]
            #[staticmethod]
            pub fn leaf(payload: PyBound<'_, PyBytes>) -> Self {
                let bytes: Box<[u8]> = payload.as_bytes().to_vec().into_boxed_slice();
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
            fn is_leaf(&self) -> bool {
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
        #[pyclass(name = $classname)]
        struct $name {
            inner: Tree<$node, usize>,
        }

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
                Python::with_gil(|py| {
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
            #[pyo3(name = "root")]
            fn root(&self) -> String {
                format!("{}", self.root_hex())
            }

            #[inline]
            #[pyo3(name = "is_empty")]
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
                self.leaves()
                    .iter()
                    .map(|leaf| self.inner.get(leaf.index()).unwrap().clone())
                    .collect()
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

            fn tree_pretty_print(&self) -> String {
                format!("{}", self.inner)
            }

            #[inline]
            #[classmethod]
            pub fn from_leaves(
                _cls: &PyBound<'_, PyType>,
                mut leaves: Vec<PyBound<'_, PyBytes>>,
            ) -> PyResult<Self> {
                let mut tree = Tree::<$node, usize>::new();

                if leaves.is_empty() {
                    return Ok(Self { inner: tree });
                }

                let hasher = MrkleHasher::<$digest>::new();

                if leaves.len() == 1 {
                    let payload = leaves.pop().unwrap();

                    let leaf = <$node>::leaf(payload);
                    let hash = hasher.hash(leaf.hash());

                    let leaf_idx = tree.push(leaf);

                    let root = <$node>::internal(vec![leaf_idx], hash);
                    let root_idx = tree.push(root);
                    tree[leaf_idx].parent = Some(root_idx);
                    tree.set_root(Some(root_idx));

                    return Ok(Self { inner: tree });
                }

                let mut queue: VecDeque<NodeIndex<usize>> = VecDeque::new();
                for payload in leaves {
                    let idx = tree.push(<$node>::leaf(payload));
                    queue.push_back(idx);
                }

                while queue.len() > 1 {
                    let lhs = queue.pop_front().unwrap();
                    let rhs = queue.pop_front().unwrap();

                    let hash = hasher.concat(
                        &tree.get(lhs.index()).unwrap().hash(),
                        &tree.get(rhs.index()).unwrap().hash(),
                    );

                    let parent_idx = tree.push(<$node>::internal(vec![lhs, rhs], hash));

                    tree[lhs].parent = Some(parent_idx);
                    tree[rhs].parent = Some(parent_idx);

                    queue.push_back(parent_idx);
                }

                tree.set_root(queue.pop_front());
                Ok(Self { inner: tree })
            }

            fn __iter__(slf: PyRef<'_, Self>) -> PyResult<$iter_name> {
                let mut queue = VecDeque::new();

                // Start BFS from the root
                if let Some(root_idx) = slf.inner.start() {
                    queue.push_back(root_idx.index());
                }

                Ok($iter_name {
                    tree: slf.into(),
                    queue,
                })
            }
        }

        impl $name {
            /// Return reference to root [`HexDisplay<'_>`].
            pub fn root_hex(&self) -> HexDisplay<'_> {
                self.inner.root().to_hex()
            }

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
            pub fn leaves(&self) -> Vec<NodeIndex<usize>> {
                self.inner.leaves()
            }

            /// Return a vector of  [`Node`] references.
            #[inline]
            pub fn leaves_ref(&self) -> Vec<&$node> {
                self.inner.leaves_ref()
            }

            /// Searches for a node by checking its claimed parent-child relationship.
            ///
            /// Returns the node’s index if found and properly connected.
            pub fn find(&self, node: &$node) -> Option<NodeIndex<usize>> {
                self.inner.find(node)
            }

            /// Create a [`TreeView`] of the Merkle tree
            /// from a node reference as root if found, else return None.
            #[inline]
            pub fn subtree_view(
                &self,
                root: NodeIndex<usize>,
            ) -> Option<TreeView<'_, $node, usize>> {
                self.inner.subtree_view(root)
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

// #[pymethods]
// impl PyNode {
//     #[new]
//     fn new(obj: PyObject, parent: Option<usize>, children: Option<Vec<usize>>) -> Self {
//         let parent_index = parent.map(NodeIndex::new);

//         let children_indices = if let Some(c) = children {
//             c.into_iter().map(NodeIndex::new).collect()
//         } else {
//             Vec::new()
//         };

//         Self {
//             value: obj,
//             parent: parent_index,
//             children: children_indices,
//         }
//     }

//     fn value<'py>(&self, py: Python<'py>) -> &PyBound<'py, PyAny> {
//         self.value.bind(py)
//     }

//     #[getter]
//     fn children(&self) -> Vec<usize> {
//         self.children.iter().map(|c| c.index()).collect()
//     }

//     #[getter]
//     fn parent(&self) -> Option<usize> {
//         self.parent.map(|p| p.index())
//     }

//     fn __repr__(&self) -> String {
//         format!("<_mrkle_rs.tree.Tree object at {:p}>", self)
//     }

//     fn __str__(&self) -> String {
//         format!("{}", self)
//     }
// }

// #[pyclass(name = "Tree", frozen)]
// struct PyMrkleTreeObject {
//     inner: Tree<PyMrkleNode, usize>,
// }

// #[pymethods]
// impl PyMrkleTreeObject {
//     #[new]
//     fn new() -> Self {
//         Self { inner: Tree::new() }
//     }

//     fn __repr__(&self) -> String {
//         format!("<_mrkle_rs.tree.Tree object at {:p}>", self)
//     }

//     fn __str__(&self) -> String {
//         format!("{}", self.inner)
//     }
// }

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
    tree_m.add_class::<PyMrkleTreeIterKeccak512>()?;

    tree_m.add_class::<PyMrkleTreeIterBlake2b>()?;
    tree_m.add_class::<PyMrkleTreeIterBlake2s>()?;

    m.add_submodule(&tree_m)
}
