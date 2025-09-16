/// Errors returned when trying preform operation on `Node` trait
#[derive(Debug, thiserror::Error)]
pub enum NodeError {
    /// Node already contains node index.
    #[error("Node already contains {child}.")]
    Duplicate {
        /// child already exist within Node.
        child: usize,
    },
}

/// Errors returned when trying to convert a byte slice to an [`entry`]
#[derive(Debug, thiserror::Error)]
pub enum EntryError {
    /// entry can not init hash from the digest.
    #[error("Can not instantiate hash from a digest of length {0}")]
    InvalidByteSliceLength(usize),
}

/// Errors that may occur while constructing or manipulating a [`Tree`].
#[derive(Debug, thiserror::Error)]
pub enum TreeError {
    /// The tree has no root node assigned.
    #[error("Root of the tree is missing.")]
    MissingRoot,

    /// The designated root node was found to already have a parent.
    ///
    /// In a valid tree, the root must never have a parent.
    #[error("Root node {0} cannot have a parent.")]
    InvalidRoot(usize),

    /// A cycle was detected in the tree structure.
    ///
    /// Trees must be acyclic graphs.
    #[error("Tree data structure cannot contain cycles.")]
    CycleDetected,

    /// A node exists in the tree without any parent reference.
    ///
    /// All nodes except the root must have exactly one parent.
    #[error("Tree contains a disjoint node {node} with no parent.")]
    DisjointNode {
        /// Node index that is disjoint
        node: usize,
    },

    /// Attempt to index out of bounds.
    #[error("Index {index} is out of bounds for tree with {len} leaves")]
    IndexOutOfBounds {
        /// Index out of bounds.
        index: usize,
        /// Number of nodes.
        len: usize,
    },

    /// Attempted to assign a new parent to a node that already has one.
    ///
    /// Each node (except the root) must have a single unique parent.
    #[error(
        "Illegal operation: tried to add child {child} to {expected:?}, \
         but {parent:?} is already its parent."
    )]
    ParentConflict {
        /// The node that was expected to be the parent.
        expected: usize,
        /// The node that is already assigned as the parent.
        parent: usize,
        /// The child node being reassigned.
        child: usize,
    },

    /// The error returned when trying preform operation on `Node` trait
    #[error("{0}")]
    NodeError(#[from] NodeError),
}

///
#[derive(Debug, thiserror::Error)]
pub enum ProofError {
    /// Errors that may occur while constructing or manipulating a [`Tree`].
    #[error("{0}")]
    TreeError(#[from] TreeError),
}
