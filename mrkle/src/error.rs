use crate::prelude::*;
use crate::{IndexType, NodeIndex};

/// Errors that may occur when performing operations on a [`Node`](crate::tree::Node).
#[derive(Debug, thiserror::Error)]
pub enum NodeError {
    /// The node already contains the specified child index.
    #[error("Node already contains child {child}.")]
    Duplicate {
        /// The duplicate child index.
        child: usize,
    },
}

/// Errors that may occur when converting a byte slice into an [`entry`](crate::entry).
#[derive(Debug, thiserror::Error)]
pub enum EntryError {
    /// The given slice has an invalid length for initializing a hash.
    #[error("Cannot construct hash from digest of length {0}.")]
    InvalidByteSliceLength(usize),
}

/// Errors that may occur when constructing or manipulating a [`Tree`](crate::tree::Tree).
#[derive(Debug, thiserror::Error)]
pub enum TreeError {
    /// The tree has no root node.
    #[error("Tree is missing a root node.")]
    MissingRoot,

    /// The designated root node was found to have a parent.
    ///
    /// In a valid tree, the root must never have a parent.
    #[error("Root node {0} cannot have a parent.")]
    InvalidRoot(usize),

    /// A cycle was detected in the tree structure.
    ///
    /// Trees must be acyclic.
    #[error("Tree structure contains a cycle.")]
    CycleDetected,

    /// A node exists in the tree without a parent.
    ///
    /// All non-root nodes must have exactly one parent.
    #[error("Node is disjoint (no parent).")]
    DisjointNode,

    /// An index was used that is outside the bounds of the tree.
    #[error("Index {index} is out of bounds for tree of length {len}.")]
    IndexOutOfBounds {
        /// The out-of-bounds index.
        index: usize,
        /// The number of nodes in the tree.
        len: usize,
    },

    /// Attempted to assign a parent to a node that already has one.
    ///
    /// Each non-root node must have a single unique parent.
    #[error(
        "Cannot add child {child} to {expected:?}: \
         {parent:?} is already its parent."
    )]
    ParentConflict {
        /// The node that was expected to be the parent.
        expected: usize,
        /// The node that is already the parent.
        parent: usize,
        /// The child node in conflict.
        child: usize,
    },

    /// Attemped to search for node with refrecne.
    ///
    /// Could not find node from reference.
    #[error("Could not find node from reference.")]
    InvalidNodeReference,

    /// An error occurred while operating on a [`Node`](crate::tree::Node).
    #[error("{0}")]
    NodeError(#[from] NodeError),
}

/// Errors that may occur when constructing [`MrkleTree`](crate::MrkleTree) & [`MrkleProof`](crate::proof::MrkleProof).
#[derive(Debug, thiserror::Error)]
pub enum MrkleError {
    /// Errors that may occur when constructing or manipulating a [`Tree`](crate::tree::Tree).
    #[error("{0}")]
    TreeError(#[from] TreeError),

    /// Errors that may occur when verifying or constructing a Merkle proof.
    #[error("{0}")]
    ProofError(#[from] ProofError),
}

/// Errors that may occur when verifying or constructing a Merkle proof.
#[derive(Debug, thiserror::Error)]
pub enum ProofError {
    /// Minimum size of tree length is 2.
    #[error("Expected a tree length greater then 1.")]
    InvalidSize,

    /// The computed root hash does not match the expected root hash.
    ///
    /// This typically indicates that the leaves are not ordered as expected
    /// or that the data has been tampered with.
    #[error("Expected {expected:?}, found {actual:?}.")]
    RootHashMissMatch {
        /// The expected root hash.
        expected: Vec<u8>,
        /// The computed root hash.
        actual: Vec<u8>,
    },

    /// The Leaf should have a hash value.
    #[error("Expected a leaf hash but no leaf hash was allocated.")]
    ExpectedLeafHash,

    /// An error occurred while constructing or manipulating a [`Tree`](crate::tree::Tree).
    #[error("{0}")]
    TreeError(#[from] TreeError),
}

impl ProofError {
    #[inline]
    #[allow(dead_code)]
    pub(crate) fn out_of_bounds<Ix: IndexType>(len: usize, index: NodeIndex<Ix>) -> ProofError {
        ProofError::from(TreeError::IndexOutOfBounds {
            index: index.index(),
            len,
        })
    }
}
