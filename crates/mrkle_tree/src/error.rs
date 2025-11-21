/// Errors that may occur when performing operations on a [`Node`](crate::tree::Node).
#[derive(Debug, thiserror::Error)]
pub enum NodeError {
    /// The node already contains the specified child index.
    #[error("{child} already exist within children.")]
    Duplicate {
        /// The duplicate child index.
        child: usize,
    },

    /// Attempted to assign a parent to a node that already has one.
    ///
    /// Each non-root node must have a single unique parent.
    #[error(
        "Cannot add child {child} to {parent}, \
         node already contains a parent node reference."
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

/// Errors that occur within the builder pattern.
#[derive(Debug, thiserror::Error)]
pub enum TreeBuilderError {
    /// Error occurs when the range exceeds the the buffer.
    #[error("Tried to access outside the bounds of the buffer.")]
    InvalidRange,

    /// Error occurs when there is not enough number of nodes to preform the join.
    #[error("Insufficent number of nodes to preform a join.")]
    InsufficientNodes,

    /// Errors that may occur when constructing or manipulating a [`Tree`](crate::tree::Tree).
    #[error("{0}")]
    TreeError(#[from] TreeError),
}

/// Errors that may occur when constructing or manipulating a [`Tree`](crate::tree::Tree).
#[derive(Debug, thiserror::Error)]
pub enum TreeError {
    /// The tree has no root node.
    #[error("Tree is missing a root node.")]
    MissingRoot,

    /// An index was used that is outside the bounds of the tree.
    #[error("Index {index} is out of bounds for tree of length {len}.")]
    IndexOutOfBounds {
        /// The out-of-bounds index.
        index: usize,
        /// The number of nodes in the tree.
        len: usize,
    },

    /// A node exists in the tree without a parent.
    ///
    /// All non-root nodes must have exactly one parent.
    #[error("Node is disjoint (no parent).")]
    DisjointNode,

    /// An error occurred while operating on a [`Node`](crate::tree::Node).
    #[error("{0}")]
    NodeError(#[from] NodeError),
}
