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

    /// Attempted to assign a parent to a node that already has one.
    ///
    /// Each non-root node must have a single unique parent.
    #[error(
        "Cannot add child {child} to {parent}: \
         node already has a parent."
    )]
    ParentConflict {
        /// The node that is already the parent.
        parent: usize,
        /// The child node in conflict.
        child: usize,
    },

    /// An index was used that is outside the bounds of the tree.
    #[error("Node at {index:?} could not be found with in tree.")]
    NodeNotFound {
        /// node index within tree.
        index: usize,
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

    /// An error occurred while operating on a [`Node`](crate::tree::Node).
    #[error("{0}")]
    NodeError(#[from] NodeError),

    /// The builder has already been finalized and cannot be modified.
    ///
    /// Once a builder is finalized with `finish()`, no further modifications
    /// are allowed to maintain tree integrity.
    #[error("Builder has already been finalized and cannot be modified.")]
    AlreadyFinalized,

    /// An invalid operation was attempted on the tree or builder.
    ///
    /// This error provides context about what operation failed and why.
    #[error("Invalid operation '{operation}': {reason}.")]
    InvalidOperation {
        /// The name of the operation that failed.
        operation: &'static str,
        /// A human-readable description of why the operation failed.
        reason: String,
    },

    /// The tree is in an inconsistent state.
    ///
    /// This error indicates that the tree's internal state has become
    /// inconsistent, possibly due to concurrent modification or corruption.
    #[error("Tree is in an inconsistent state: {details}.")]
    InconsistentState {
        /// Details about the inconsistency.
        details: String,
    },

    /// A validation error occurred during tree construction or verification.
    ///
    /// This error aggregates multiple validation failures that occurred
    /// during tree validation operations.
    #[error("Validation failed with {count} error(s): {summary}.")]
    ValidationFailed {
        /// The number of validation errors.
        count: usize,
        /// A summary of the validation failures.
        summary: String,
        /// The individual validation errors.
        errors: Vec<TreeError>,
    },
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

    /// Number of expected leaf hashes not met to finish proof.
    #[error("Expected {expected} hashes, and got only {len}.")]
    IncompleteProof {
        /// lengths of leaves to verify.
        len: usize,
        /// expected leaves to verify.
        expected: usize,
    },

    /// Invalid path cannot start with an internal node.
    #[error("Invalid path, cannot start with an internal node.")]
    UnexpectedInternalNode,

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

    /// The path from the node does not meet the root.
    #[error("Expected root index {0}, got {1}.")]
    PathRootMismatch(usize, usize),

    /// An error occurred while constructing or manipulating a [`Tree`](crate::tree::Tree).
    #[error("{0}")]
    TreeError(#[from] TreeError),
}

impl ProofError {
    /// helper function
    #[inline]
    #[allow(dead_code)]
    pub fn out_of_bounds<Ix: IndexType>(len: usize, index: NodeIndex<Ix>) -> ProofError {
        ProofError::from(TreeError::IndexOutOfBounds {
            index: index.index(),
            len,
        })
    }
}
