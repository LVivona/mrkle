mod node;

use crate::error::TreeError;
use crate::prelude::*;
pub use node::{DefaultIx, IndexType, MrkleNode, NodeIndex, NodeType};

/// [`Tree`] is a generic hierarchical tree data structure.
///
/// It stores a collection of nodes connected in a parent-child
/// relationship. The tree can be constructed either from the top
/// down (root first) or bottom up (leaves first).
///
/// # Type parameters
/// - `T`: The type of data stored in each node.
/// - `N`: The node type, which must implement [`NodeType<T>`].
/// - `Ix`: The index type used to address nodes in the tree.
pub struct Tree<T, N: NodeType<Ix>, Ix: IndexType = DefaultIx> {
    /// The index of the root node, if any.
    ///
    /// This is `None` if the tree is empty or is being built from leaves.
    root: Option<NodeIndex<Ix>>,

    /// Collection of all nodes in the tree.
    ///
    /// Each node is addressed by its [`NodeIndex`].
    pub(crate) nodes: Vec<N>,

    /// Marker for the generic type `T`.
    _phantom: PhantomData<T>,
}

impl<T, N: NodeType<Ix>, Ix: IndexType> Tree<T, N, Ix> {
    /// Creates an empty tree with no nodes.
    #[inline]
    pub(crate) fn new() -> Self {
        Self {
            root: None,
            nodes: Vec::new(),
            _phantom: PhantomData,
        }
    }

    /// Creates an empty tree with pre-allocated capacity for nodes.
    ///
    /// # Parameters
    /// - `capacity`: The initial number of nodes to allocate space for.
    #[inline]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            root: None,
            nodes: Vec::with_capacity(capacity),
            _phantom: PhantomData,
        }
    }

    /// Returns the number of nodes currently in the tree.
    #[inline]
    pub fn length(&self) -> usize {
        self.nodes.len()
    }

    /// Adds a new node with the given `value` to the tree.
    ///
    /// # Returns
    /// The [`NodeIndex`] of the newly inserted node.
    ///
    /// # Panics
    /// If the tree is at its maximum number of nodes for the chosen index type.
    #[inline]
    #[must_use]
    pub fn add_node(&mut self, value: T) -> NodeIndex<Ix> {
        self.try_add_node(value).unwrap()
    }

    /// Attempts to add a new node with the given `value` to the tree.
    ///
    /// # Returns
    /// - `Ok(NodeIndex)` with the index of the new node.
    /// - `Err(TreeError)` if the node cannot be added.
    #[must_use]
    pub fn try_add_node(&mut self, value: T) -> Result<NodeIndex<Ix>, TreeError<Ix>> {
        todo!()
    }

    /// Attaches multiple children under a specified parent node.
    ///
    /// # Parameters
    /// - `parent`: The index of the parent node.
    /// - `children`: A vector of child node indices.
    ///
    /// # Returns
    /// - `Ok(())` on success.
    /// - `Err(TreeError)` if the operation fails (e.g., invalid indices).
    fn join_node_index(
        &mut self,
        parent: NodeIndex<Ix>,
        children: Vec<NodeIndex<Ix>>,
    ) -> Result<(), TreeError<Ix>> {
        Ok(())
    }

    /// Creates a new parent node for two existing nodes.
    ///
    /// # Parameters
    /// - `value`: The data to store in the parent node.
    /// - `lhs`: Index of the left child.
    /// - `rhs`: Index of the right child.
    ///
    /// # Returns
    /// The [`NodeIndex`] of the newly created parent node.
    pub fn join(&mut self, value: T, lhs: NodeIndex<Ix>, rhs: NodeIndex<Ix>) -> NodeIndex<Ix> {
        todo!()
    }

    /// Attempts to create a parent node from a value.
    ///
    /// # Returns
    /// - `Ok(NodeIndex)` with the index of the new node.
    /// - `Err(TreeError)` if the operation fails.
    pub fn try_join(&mut self, value: T) -> Result<NodeIndex<Ix>, TreeError<Ix>> {
        todo!()
    }

    /// Returns a reference to the root node.
    ///
    /// # Panics
    /// If the tree does not have a root.
    pub fn root(&self) -> &N {
        self.try_root().unwrap()
    }

    /// Attempts to return a reference to the root node.
    ///
    /// # Returns
    /// - `Ok(&N)` if a root exists.
    /// - `Err(TreeError::MissingRoot)` if the tree has no root.
    pub fn try_root(&self) -> Result<&N, TreeError<Ix>> {
        if let Some(idx) = self.root {
            Ok(&self.nodes[idx.index()])
        } else {
            Err(TreeError::MissingRoot)
        }
    }
}
