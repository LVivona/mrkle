#[path = "view.rs"]
mod borrow;
mod iter;
mod node;

use crate::TreeError;
use crate::prelude::*;

pub use borrow::TreeView;
pub use iter::{IndexIter, Iter};
pub use node::{IndexType, MutNode, Node, NodeIndex};

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
pub struct Tree<N: Node<Ix>, Ix: IndexType = DefaultIx> {
    /// The index of the root node, if any.
    ///
    /// This is `None` if the tree is empty or is being built from leaves.
    pub(crate) root: Option<NodeIndex<Ix>>,

    /// Collection of all nodes in the tree.
    ///
    /// Each node is addressed by its [`NodeIndex`].
    pub(crate) nodes: Vec<N>,
}

impl<N: Node<Ix>, Ix: IndexType> Tree<N, Ix> {
    /// Creates an empty tree with no nodes.
    #[inline]
    pub fn new() -> Self {
        Self {
            root: None,
            nodes: Vec::new(),
        }
    }

    /// Creates an empty tree with pre-allocated capacity for nodes.
    ///
    /// # Arguments
    /// * `capacity` - The initial number of nodes to allocate space for.
    #[inline]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            root: None,
            nodes: Vec::with_capacity(capacity),
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

    /// Returns a mutable reference to the root node.
    ///
    /// # Panics
    /// If the tree does not have a root.
    #[inline]
    pub fn root_mut(&mut self) -> &mut N
    where
        N: MutNode<Ix>,
    {
        self.try_root_mut().unwrap()
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

    /// Attempts to return a mutable reference to the root node.
    ///
    /// # Returns
    /// - `Ok(&N)` if a root exists.
    /// - `Err(TreeError::MissingRoot)` if the tree has no root.
    pub fn try_root_mut(&mut self) -> Result<&mut N, TreeError>
    where
        N: MutNode<Ix>,
    {
        if let Some(idx) = self.root {
            Ok(&mut self.nodes[idx.index()])
        } else {
            // NOTE: The only occurance of this would likely happen
            // if programmer had straight access to the Tree data
            // structure in construction.
            Err(TreeError::MissingRoot)
        }
    }

    /// Returns a reference to an element [`Node`] or subslice depending on the type of index.
    pub fn get<I>(&self, idx: I) -> Option<&I::Output>
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

    /// Return a vector of  [`NodeIndex<Ix>`], location were the leaves can be index.
    pub fn leaves(&self) -> Vec<NodeIndex<Ix>> {
        self.iter_idx()
            .filter(|&idx| {
                self.get(idx.index())
                    .filter(|&node| node.is_leaf())
                    .is_some()
            })
            .collect()
    }

    /// Return a vector of  [`Node`] references.
    pub fn leaves_ref(&self) -> Vec<&N> {
        self.iter_idx()
            .filter_map(|idx| self.get(idx.index()).filter(|node| node.is_leaf()))
            .collect()
    }

    /// Inserts an [`Node`] at position index within the vector, shifting all elements after it to the right.
    pub fn insert(&mut self, index: NodeIndex<Ix>, node: N) {
        self.nodes.insert(index.index(), node);
    }

    ///Return root [`TreeView`] of the [`Tree`]
    pub fn view(&self) -> TreeView<'_, N, Ix> {
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
    pub fn iter(&self) -> Iter<'_, N, Ix> {
        Iter::new(self)
    }

    /// Returns Iterator pattern [`IterIdx`] which returns a
    /// [`NodeIndex<Ix>`] of the node.
    #[inline]
    pub fn iter_idx(&self) -> IndexIter<'_, N, Ix> {
        IndexIter::new(self)
    }

    /// Create a [`TreeView`] from a specific node as root.
    pub fn subtree_view(&self, root: NodeIndex<Ix>) -> Option<TreeView<'_, N, Ix>> {
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
                    nodes.push((child_idx, child_node));
                    queue.push_back(child_idx);
                }
            }
        }

        Some(TreeView::new(root, nodes))
    }

    /// Create a [`TreeView`] from a node reference if found,
    /// else return None.
    pub fn subtree_from_node(&self, target: &N) -> Option<TreeView<'_, N, Ix>>
    where
        N: PartialEq + Eq,
    {
        // Find the index of the target node
        for idx in IndexIter::<_, _>::new(self) {
            if &self.nodes[idx.index()] == target {
                return self.subtree_view(idx);
            }
        }
        None
    }
}

impl<N: Node<Ix> + Display, Ix: IndexType> Tree<N, Ix> {
    /// NOTE:
    /// Power of 10 rules for developing safety-critical code
    /// [Rule 2](https://en.wikipedia.org/wiki/The_Power_of_10:_Rules_for_Developing_Safety-Critical_Code): All loops must have fixed bounds. This prevents runaway code.
    /// - In safety-critical systems (like avionics), recursion can lead to unbounded
    ///   stack growth, making timing and memory usage unpredictable.
    /// - Static analyzers also have a hard time proving termination and memory bounds for recursive functions.
    /// - Iterative loops are much easier to analyze, bound, and test for worst-case execution.
    fn ascii_tree(&self, node: &N) -> text_trees::TreeNode<String> {
        let mut display = text_trees::TreeNode::new(format!("{}", node));

        for index in node.children() {
            if let Some(child) = self.get(index.index()) {
                let d = self.ascii_tree(child);
                display.push_node(d);
            }
        }

        display
    }
}

impl<N: Node<Ix> + Display, Ix: IndexType> core::fmt::Display for Tree<N, Ix> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.ascii_tree(self.root()))
    }
}

impl<N: Node<Ix> + Display, Ix: IndexType> core::fmt::Debug for Tree<N, Ix> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.ascii_tree(self.root()))
    }
}

impl<N: Node<Ix>, Ix: IndexType> Default for Tree<N, Ix> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a, N: Node<Ix>, Ix: IndexType> IntoIterator for &'a Tree<N, Ix> {
    type IntoIter = Iter<'a, N, Ix>;
    type Item = &'a N;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

#[cfg(feature = "serde")]
impl<N, Ix> serde::Serialize for Tree<N, Ix>
where
    N: Node<Ix> + serde::Serialize,
    Ix: IndexType + serde::Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("TreeCore", 2)?;

        state.serialize_field("root", &self.root)?;
        state.serialize_field("nodes", &self.nodes)?;
        state.end()
    }
}

#[cfg(feature = "serde")]
impl<'de, N: Node<Ix>, Ix: IndexType> serde::Deserialize<'de> for Tree<N, Ix>
where
    N: serde::Deserialize<'de>,
    Ix: serde::Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        #[serde(field_identifier, rename_all = "lowercase")]
        enum Field {
            Root,
            Nodes,
        }

        struct TreeVisitor<N, Ix> {
            _marker: PhantomData<(N, Ix)>,
        }

        impl<'de, N: Node<Ix>, Ix: IndexType> serde::de::Visitor<'de> for TreeVisitor<N, Ix>
        where
            N: serde::Deserialize<'de>,
            Ix: serde::Deserialize<'de>,
        {
            type Value = Tree<N, Ix>;
            fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
                formatter.write_str("struct Tree")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let root: Option<NodeIndex<Ix>> = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;

                let nodes: Vec<N> = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(1, &self))?;

                Ok(Tree { root, nodes })
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                let mut root: Option<Option<NodeIndex<Ix>>> = None;
                let mut nodes: Option<Vec<N>> = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Root => {
                            if root.is_some() {
                                return Err(serde::de::Error::duplicate_field("root"));
                            }
                            root = Some(map.next_value()?);
                        }
                        Field::Nodes => {
                            if nodes.is_some() {
                                return Err(serde::de::Error::duplicate_field("nodes"));
                            }
                            nodes = Some(map.next_value()?);
                        }
                    }
                }
                let root = root.ok_or_else(|| serde::de::Error::missing_field("root"))?;
                let nodes = nodes.ok_or_else(|| serde::de::Error::missing_field("nodes"))?;

                Ok(Tree { root, nodes })
            }
        }

        const FEILDS: &[&str] = &["root", "nodes"];
        deserializer.deserialize_struct(
            "TreeCore",
            FEILDS,
            TreeVisitor {
                _marker: PhantomData,
            },
        )
    }
}

#[cfg(test)]
mod test {

    use super::node::BasicNode as Node;
    use crate::prelude::*;
    use crate::{NodeIndex, Tree};

    #[test]
    fn test_empty_tree_construction() {
        let tree: Tree<Node<u8>> = Tree::new();
        assert!(tree.is_empty())
    }

    #[test]
    fn test_tree_iter() {
        let mut root: Node<String> = Node::new("hello".to_string());
        root.children = vec![NodeIndex::new(1), NodeIndex::new(2)];
        let mut tree: Tree<Node<String>> = Tree::new();
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
        let mut tree: Tree<Node<String>> = Tree::new();
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
        let mut tree: Tree<Node<String>> = Tree::new();
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
        let mut tree: Tree<Node<String>> = Tree::new();
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
