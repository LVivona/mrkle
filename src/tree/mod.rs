#[path = "view.rs"]
mod borrow;
mod node;

use crate::error::TreeError;
use crate::prelude::*;
pub use borrow::TreeView;
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
    pub(crate) root: Option<NodeIndex<Ix>>,

    /// Collection of all nodes in the tree.
    ///
    /// Each node is addressed by its [`NodeIndex`].
    pub(crate) nodes: Vec<N>,

    /// Marker for the generic type `T`.
    phantom: PhantomData<T>,
}

impl<T, N: NodeType<Ix>, Ix: IndexType> Tree<T, N, Ix> {
    /// Creates an empty tree with no nodes.
    #[inline]
    pub(crate) fn new() -> Self {
        Self {
            root: None,
            nodes: Vec::new(),
            phantom: PhantomData,
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
            phantom: PhantomData,
        }
    }

    /// Returns the number of nodes currently in the tree.
    #[inline]
    pub fn length(&self) -> usize {
        self.nodes.len()
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
            // NOTE: The only occurance of this would likely happen
            // if programmer had straight access to the Tree data
            // structure in construction.
            Err(TreeError::MissingRoot)
        }
    }

    ///Return root [`TreeView`] of the [`Tree`]
    pub fn view(&self) -> TreeView<'_, T, N, Ix> {
        TreeView::from(self)
    }

    /// Returns `true` if the tree contains no nodes.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.length() == 0
    }
}

impl<T, N: NodeType<Ix>, Ix: IndexType> Default for Tree<T, N, Ix> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod test {

    use crate::{DefaultIx, prelude::*};
    use crate::{IndexType, NodeType, Tree, tree::NodeIndex};

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(crate) struct Node<T, Ix: IndexType = DefaultIx>
    where
        T: Clone,
    {
        pub(crate) value: T,
        pub(crate) parent: Option<NodeIndex<Ix>>,
        pub(crate) children: Vec<NodeIndex<Ix>>,
    }

    impl<T, Ix: IndexType> Node<T, Ix>
    where
        T: Clone,
    {
        pub(crate) fn new(value: T) -> Self {
            Self {
                value,
                parent: None,
                children: Vec::new(),
            }
        }
    }

    impl<T, Ix: IndexType> NodeType<Ix> for Node<T, Ix>
    where
        T: Clone,
    {
        fn is_leaf(&self) -> bool {
            self.children.len() == 0
        }
        fn children(&self) -> Vec<NodeIndex<Ix>> {
            self.children.clone()
        }

        fn contains(&self, node: &NodeIndex<Ix>) -> bool {
            self.children.contains(node)
        }

        fn parent(&self) -> Option<NodeIndex<Ix>> {
            self.parent
        }
    }

    #[test]
    fn test_empty_tree_construction() {
        let tree: Tree<u8, Node<u8>> = Tree::new();
        assert!(tree.is_empty())
    }
}
