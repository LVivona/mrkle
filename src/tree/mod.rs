#[path = "view.rs"]
mod borrow;
mod iter;
mod node;

use crate::TreeError;
use crate::prelude::*;

pub use borrow::TreeView;
pub use iter::{Iter, IterIdx};
pub use node::{BasicNode, IndexType, Node, NodeIndex};

pub(crate) use node::DefaultIx;

/// A generic hierarchical tree data structure.
///
/// It stores a collection of [`Node`] connected in a parent-child
/// relationship. The tree can be constructed either from the top
/// down (root first) or bottom up (leaves first).
///
/// # Type parameters
/// - `T`: The type of data stored in each node.
/// - `N`: The node type, which must implement [`Node<T>`].
/// - `Ix`: The index type used to address nodes in the tree.
pub struct Tree<T, N = BasicNode<T>, Ix: IndexType = DefaultIx> {
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

impl<T, N: Node<Ix>, Ix: IndexType> Tree<T, N, Ix> {
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
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Returns a reference to the root node.
    ///
    /// # Panics
    /// If the tree does not have a root.
    #[inline]
    pub fn root(&self) -> &N {
        self.try_root().unwrap()
    }

    /// Attempts to return a reference to the root node.
    ///
    /// # Returns
    /// - `Ok(&N)` if a root exists.
    /// - `Err(TreeError::MissingRoot)` if the tree has no root.
    pub fn try_root(&self) -> Result<&N, TreeError> {
        if let Some(idx) = self.root {
            Ok(&self.nodes[idx.index()])
        } else {
            // NOTE: The only occurance of this would likely happen
            // if programmer had straight access to the Tree data
            // structure in construction.
            Err(TreeError::MissingRoot)
        }
    }

    /// Returns a reference to an element [`Node`] or subslice depending on the type of index.
    pub fn get<I>(&self, idx: I) -> Option<&<I as SliceIndex<[N]>>::Output>
    where
        I: SliceIndex<[N]>,
    {
        self.nodes.get(idx)
    }

    /// Returns a mut reference to an element [`Node`] or subslice depending on the type of index.
    pub fn get_mut<I>(&mut self, idx: I) -> Option<&mut <I as SliceIndex<[N]>>::Output>
    where
        I: SliceIndex<[N]>,
    {
        self.nodes.get_mut(idx)
    }

    /// Push nodes onto [`Tree`] node list without connection.
    ///
    /// Return there [`NodeIndex`] within the tree
    pub fn push(&mut self, node: N) -> NodeIndex<Ix> {
        self.nodes.push(node);
        NodeIndex::new(self.nodes.len() - 1)
    }

    /// Inserts an [`Node`] at position index within the vector, shifting all elements after it to the right.
    pub fn insert(&mut self, index: NodeIndex<Ix>, node: N) {
        self.nodes.insert(index.index(), node);
    }

    ///Return root [`TreeView`] of the [`Tree`]
    pub fn view(&self) -> TreeView<'_, T, N, Ix> {
        TreeView::from(self)
    }

    /// Returns `true` if the tree contains no nodes.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns Iterator pattern [`Iter`] which returns a
    /// unmutable Node reference.
    #[inline]
    pub fn iter(&self) -> Iter<'_, T, N, Ix> {
        self.view().iter()
    }

    /// Returns Iterator pattern [`IterIdx`] which returns a
    /// [`NodeIndex<Ix>`] of the node.
    #[inline]
    pub fn iter_idx(&self) -> IterIdx<'_, T, N, Ix> {
        self.view().iter_idx()
    }

    /// Create a [`TreeView`] from a specific node as root.
    pub fn subtree_view(&self, root: NodeIndex<Ix>) -> Option<TreeView<'_, T, N, Ix>> {
        // Check if the node exists
        if root.index() >= self.nodes.len() {
            return None;
        }

        let node = &self.nodes[root.index()];
        let mut nodes: Vec<(NodeIndex<Ix>, &N)> = vec![(root, node)];

        // Breath-First-Search (BFS) to collect all nodes in the subtree.
        // to add it into [`TreeView`].
        let mut queue: VecDeque<NodeIndex<Ix>> = VecDeque::from(vec![root]);

        while let Some(current_idx) = queue.pop_front() {
            let current_node = &self.nodes[current_idx.index()];

            for child_idx in current_node.children() {
                if child_idx.index() < self.nodes.len() {
                    let child_node = &self.nodes[child_idx.index()];
                    nodes.push((*child_idx, child_node));
                    queue.push_back(*child_idx);
                }
            }
        }

        Some(TreeView::new(root, nodes))
    }

    /// Create a [`TreeView`] from a node reference if found,
    /// else return None.
    pub fn subtree_from_node(&self, target: &N) -> Option<TreeView<'_, T, N, Ix>>
    where
        N: PartialEq + Eq,
    {
        // Find the index of the target node
        for idx in IterIdx::new(self.view()) {
            if &self.nodes[idx.index()] == target {
                return self.subtree_view(idx);
            }
        }
        None
    }
}

impl<T, N: Node<Ix>, Ix: IndexType> Default for Tree<T, N, Ix> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a, T, N: Node<Ix>, Ix: IndexType> IntoIterator for &'a Tree<T, N, Ix> {
    type IntoIter = Iter<'a, T, N, Ix>;
    type Item = &'a N;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

#[cfg(test)]
mod test {

    use super::BasicNode as Node;
    use crate::prelude::*;
    use crate::{NodeIndex, Tree};

    #[test]
    fn test_empty_tree_construction() {
        let tree: Tree<u8> = Tree::new();
        assert!(tree.is_empty())
    }

    #[test]
    fn test_tree_iter() {
        let mut root: Node<String> = Node::new("hello".to_string());
        root.children = vec![NodeIndex::new(1), NodeIndex::new(2)];
        let mut tree: Tree<String> = Tree::new();
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
    fn test_tree_get() {
        let mut root: Node<String> = Node::new("hello".to_string());
        root.children = vec![NodeIndex::new(1), NodeIndex::new(2)];
        let mut tree: Tree<String> = Tree::new();
        let n1 = Node::new("world".to_string());
        let n2 = Node::new("!".to_string());
        tree.root = Some(NodeIndex::new(0));
        tree.nodes.push(root.clone());
        tree.nodes.push(n1.clone());
        tree.nodes.push(n2.clone());

        if let Some(output) = tree.get(..) {
            assert_eq!(root, output[0]);
            assert_eq!(n1, output[1]);
            assert_eq!(n2, output[2]);
        }
    }

    #[test]
    fn test_tree_subtree() {
        let mut root: Node<String> = Node::new("hello".to_string());
        root.children = vec![NodeIndex::new(1), NodeIndex::new(2)];
        let mut tree: Tree<String> = Tree::new();
        tree.root = Some(NodeIndex::new(0));
        tree.nodes.push(root);
        tree.nodes.push(Node::new("world".to_string()));
        tree.nodes.push(Node::new("!".to_string()));

        let subtree = tree.subtree_view(NodeIndex::new(1)).unwrap();
        assert!(subtree.len() == 1);
        assert!(subtree.root() == &tree.nodes[1]);
    }

    #[test]
    fn test_tree_subtree_unordered() {
        let mut root: Node<String> = Node::new("hello".to_string());
        root.children = vec![NodeIndex::new(0), NodeIndex::new(1)];
        let mut tree: Tree<String> = Tree::new();
        let n1 = Node::new("world".to_string());
        let n2 = Node::new("!".to_string());
        tree.root = Some(NodeIndex::new(2));
        tree.nodes.push(n1.clone());
        tree.nodes.push(n2);
        tree.nodes.push(root);

        let subtree = tree.subtree_from_node(&n1);
        assert!(subtree.is_some());
        if let Some(s) = subtree {
            assert!(s.len() == 1);
            assert!(s.root() == &tree.nodes[0]);
        }
    }
}
