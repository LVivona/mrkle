#[path = "view.rs"]
mod borrow;
mod iter;
mod node;

use crate::error::TreeError;
use crate::prelude::*;
pub use borrow::TreeView;
pub use iter::Iter;
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

    /// Returns Iterator pattern [`Iter`].
    pub fn iter(&self) -> Iter<'_, T, N, Ix> {
        Iter::new(&self)
    }

    /// Create a [`TreeView`] from a specific node as root.
    pub fn subtree_view(&self, root: NodeIndex<Ix>) -> Option<TreeView<T, N, Ix>> {
        // Check if the node exists
        if root.index() >= self.nodes.len() {
            return None;
        }

        let root_node = &self.nodes[root.index()];
        let mut nodes: Vec<(NodeIndex<Ix>, &N)> = vec![(root, root_node)];

        // BFS to collect all nodes in the subtree
        let mut queue: VecDeque<NodeIndex<Ix>> = VecDeque::from(vec![root]);

        while let Some(current_idx) = queue.pop_front() {
            let current_node = &self.nodes[current_idx.index()];

            for child_idx in current_node.children() {
                if child_idx.index() < self.nodes.len() {
                    let child_node = &self.nodes[child_idx.index()];
                    nodes.push((child_idx, child_node));
                    queue.push_back(child_idx);
                }
            }
        }

        Some(TreeView::new(root, nodes))
    }

    /// Create a [`TreeView`] from a node reference.
    pub fn subtree_from_node(&self, target: &N) -> Option<TreeView<T, N, Ix>>
    where
        N: PartialEq,
    {
        // Find the index of the target node
        for (idx, node) in self.nodes.iter().enumerate() {
            if node == target {
                return self.subtree_view(NodeIndex::new(idx));
            }
        }
        None
    }
}

impl<T, N: NodeType<Ix>, Ix: IndexType> Default for Tree<T, N, Ix> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a, T, N: NodeType<Ix>, Ix: IndexType> IntoIterator for &'a Tree<T, N, Ix> {
    type IntoIter = Iter<'a, T, N, Ix>;
    type Item = &'a N;

    fn into_iter(self) -> Self::IntoIter {
        Iter::new(self)
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

    #[test]
    fn test_tree_iter() {
        let mut root: Node<String> = Node::new("hello".to_string());
        root.children = vec![NodeIndex::new(1), NodeIndex::new(2)];
        let mut tree: Tree<String, Node<String>> = Tree::new();
        tree.root = Some(NodeIndex::new(0));
        tree.nodes.push(root);
        tree.nodes.push(Node::new("world".to_string()));
        tree.nodes.push(Node::new("!".to_string()));

        let mut tree_iter = tree.into_iter();

        // Test that we get the root first
        let root_ref = tree_iter.next().unwrap();
        assert_eq!(root_ref.value, "hello");

        // Test that we get the children in breadth-first order
        let child1 = tree_iter.next().unwrap();
        assert_eq!(child1.value, "world");

        let child2 = tree_iter.next().unwrap();
        assert_eq!(child2.value, "!");

        // Test that iterator is exhausted
        assert!(tree_iter.next().is_none());
    }

    #[test]
    fn test_tree_subtree() {
        let mut root: Node<String> = Node::new("hello".to_string());
        root.children = vec![NodeIndex::new(1), NodeIndex::new(2)];
        let mut tree: Tree<String, Node<String>> = Tree::new();
        tree.root = Some(NodeIndex::new(0));
        tree.nodes.push(root);
        tree.nodes.push(Node::new("world".to_string()));
        tree.nodes.push(Node::new("!".to_string()));

        let subtree = tree.subtree_view(NodeIndex::new(1)).unwrap();
        assert!(subtree.len() == 1);
        assert!(subtree.root() == &tree.nodes[1]);
    }
}
