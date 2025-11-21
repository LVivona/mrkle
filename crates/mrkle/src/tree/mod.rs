#[path = "view.rs"]
mod borrow;
mod iter;
mod node;

use crate::NodeError;
use crate::TreeError;
use crate::prelude::*;

pub use borrow::TreeView;
pub use iter::{Fifo, IndexIter, Iter, Lifo, TraversalOrder, ViewIndexIter, ViewIter};
pub use node::{DefaultNode, IndexType, MutNode, Node, NodeIndex};

pub(crate) use node::DefaultIx;

/// A generic hierarchical tree data structure.
///
/// This structure stores a collection of nodes implementing [`Node<Ix>`] in a [`Vec`],
/// where hierarchical relationships are maintained through parent and child indices
/// stored within each node.
///
/// The tree structure is not enforced at the data structure level; validation and
/// enforcement should be handled at the abstraction layer during node insertion.
///
/// # Type Parameters
/// * `N` - The node type, which must implement [`Node<Ix>`]
/// * `Ix` - The index type used to address nodes in the tree (defaults to [`DefaultIx`])
///
/// # Examples
/// ```
/// use mrkle::tree::{Tree, DefaultNode};
///
/// let mut tree: Tree<DefaultNode<u8>> = Tree::new();
/// let root = tree.push(DefaultNode::default());
/// ```
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

impl<N: Node<Ix> + Clone, Ix: IndexType> Clone for Tree<N, Ix> {
    fn clone(&self) -> Self {
        Self {
            root: self.root,
            nodes: self.nodes.clone(),
        }
    }
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

    /// Returns the total number of nodes the can hold without reallocating.
    #[inline]
    pub fn capacity(&self) -> usize {
        self.nodes.capacity()
    }

    /// Unchecked setting of the root index of the tree.
    pub fn set_root(&mut self, root: Option<NodeIndex<Ix>>) {
        self.root = root;
    }

    /// Returns the root index of the tree.
    ///
    /// # Returns
    /// * `Some(NodeIndex<Ix>)` - The index of the root node if the tree is non-empty
    /// * `None` - If the tree is empty or has no designated root
    ///
    /// # Examples
    /// ```
    /// use mrkle::tree::{Tree, DefaultNode};
    ///
    /// let mut tree = Tree::new();
    /// let _ = tree.push(DefaultNode::<u8>::default());
    /// assert_eq!(tree.start().unwrap().index(), 0);
    /// ```
    #[inline]
    pub fn start(&self) -> Option<NodeIndex<Ix>> {
        self.root
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
    /// * `Ok(&N)` - A reference to the root node if one exists
    /// * `Err(TreeError::MissingRoot)` - If the tree has no root node
    ///
    /// # Examples
    /// ```
    /// use mrkle::tree::{Tree, DefaultNode};
    ///
    /// // Empty tree returns an error
    /// let tree: Tree<DefaultNode<u8>> = Tree::new();
    /// assert!(tree.try_root().is_err());
    ///
    /// // Non-empty tree returns the root
    /// let mut tree: Tree<DefaultNode<u8>> = Tree::new();
    /// let _ = tree.push(DefaultNode::default());
    /// assert!(tree.try_root().is_ok());
    /// ```
    #[inline]
    pub fn try_root(&self) -> Result<&N, TreeError> {
        if let Some(idx) = self.root {
            Ok(&self[idx])
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
    #[inline]
    pub fn try_root_mut(&mut self) -> Result<&mut N, TreeError>
    where
        N: MutNode<Ix>,
    {
        if let Some(idx) = self.root {
            Ok(&mut self[idx.index()])
        } else {
            // NOTE: The only occurance of this would likely happen
            // if programmer had straight access to the Tree data
            // structure in construction.
            Err(TreeError::MissingRoot)
        }
    }

    /// Returns the child nodes of the specified node as immutable references.
    ///
    /// # Arguments
    /// * `index` - The index of the parent node
    ///
    /// # Returns
    /// A vector of references to child nodes. Returns an empty vector if the node
    /// does not exist or has no children.
    #[inline]
    pub fn get_children(&self, index: Ix) -> Vec<&N> {
        self.get(index.index()).map_or(Vec::new(), |node| {
            node.children()
                .iter()
                .map(|&idx| self.get(idx.index()).unwrap())
                .collect()
        })
    }

    /// Returns the child indices of the specified node.
    ///
    /// # Arguments
    /// * `index` - The index of the parent node
    ///
    /// # Returns
    /// A vector of [`NodeIndex<Ix>`] values representing the children. Returns an
    /// empty vector if the node does not exist or has no children.
    #[inline]
    pub fn get_children_indices(&self, index: Ix) -> Vec<NodeIndex<Ix>> {
        self.get(index.index())
            .map(|node| node.children())
            .unwrap_or_default()
    }

    /// Returns a reference to an element or subslice depending on the index type.
    ///
    /// # Type Parameters
    /// * `I` - A type that can index into a slice of nodes
    ///
    /// # Arguments
    /// * `idx` - The index or range to access
    ///
    /// # Returns
    /// * `Some(&I::Output)` - A reference to the requested element(s)
    /// * `None` - If the index is out of bounds
    #[inline]
    pub fn get<I>(&self, idx: I) -> Option<&I::Output>
    where
        I: SliceIndex<[N]>,
    {
        self.nodes.get(idx)
    }

    /// Returns a mutable reference to an element or subslice depending on the index type.
    ///
    /// # Type Parameters
    /// * `I` - A type that can index into a slice of nodes
    ///
    /// # Arguments
    /// * `idx` - The index or range to access
    ///
    /// # Returns
    /// * `Some(&mut I::Output)` - A mutable reference to the requested element(s)
    /// * `None` - If the index is out of bounds
    #[inline]
    pub fn get_mut<I>(&mut self, idx: I) -> Option<&mut I::Output>
    where
        N: MutNode<Ix>,
        I: SliceIndex<[N]> + IndexType,
    {
        self.nodes.get_mut(idx)
    }

    /// Pushes a node onto the tree.
    ///
    /// If the tree is empty and the node is marked as a root node, it will automatically
    /// be set as the tree's root. For nodes implementing only [`Node`] (not [`MutNode`]),
    /// all node connections must be established prior to insertion.
    ///
    /// # Arguments
    /// * `node` - The node to insert into the tree
    ///
    /// # Returns
    /// The [`NodeIndex`] of the newly inserted node within the tree
    ///
    /// # Panics
    /// Panics if attempting to push a root node with pre-existing children, as their
    /// positions in the tree cannot be inferred.
    ///
    /// # Examples
    /// ```
    /// use mrkle::tree::{Tree, DefaultNode};
    ///
    /// let mut tree = Tree::<DefaultNode<u8>>::new();
    /// let root_idx = tree.push(DefaultNode::default());
    /// ```
    #[inline]
    pub fn push(&mut self, node: N) -> NodeIndex<Ix> {
        // NOTE: Easily allow individuals to insert a
        // root node within the tree.
        if self.is_empty() && node.is_root() {
            assert!(
                node.child_count() == 0,
                "Children not allocated to could not infer children's location in the tree."
            );
            self.set_root(Some(NodeIndex::new(0)));
        }
        self.nodes.push(node);
        NodeIndex::new(self.nodes.len() - 1)
    }

    /// Clears the vector, removing all values.
    ///
    /// Note that this method has no effect on the allocated capacity of the vector.
    #[inline]
    fn clear(&mut self) {
        self.nodes.clear();
        self.root = None;
    }

    /// Removes a node and all its descendants from the tree.
    ///
    /// This method performs a breadth-first traversal starting from the specified node,
    /// collecting all descendants, and then removing them from the tree. All remaining
    /// node indices are adjusted accordingly.
    ///
    /// # Arguments
    /// * `index` - The index of the node to prune
    ///
    /// # Returns
    /// * `Ok(())` - If the operation succeeds
    /// * `Err(TreeError::IndexOutOfBounds)` - If the index is invalid
    ///
    /// # Performance
    /// The implementation automatically detects whether the nodes to be removed form
    /// a sequential range and applies an optimized removal strategy when possible.
    #[inline]
    pub fn prune<I: Into<NodeIndex<Ix>>>(&mut self, index: I) -> Result<(), TreeError>
    where
        N: MutNode<Ix>,
    {
        // To be able to prune there must exist a root node.
        if self.root.is_none() {
            return Err(TreeError::MissingRoot);
        }

        let index = index.into();

        // Base Case: the index we are pruning is the root
        // we can just clear the whole buffer, and set the root
        // to None.
        if index == self.start().unwrap() {
            self.clear();
            return Ok(());
        }

        let mut remove = BTreeSet::new();
        let mut queue = VecDeque::from([index]);

        // Get nodes to prune from the tree.
        while let Some(idx) = queue.pop_front() {
            if let Some(node) = self.get(idx.index()) {
                remove.insert(idx);
                queue.extend(node.children());
            } else {
                return Err(TreeError::IndexOutOfBounds {
                    index: idx.index(),
                    len: self.len(),
                });
            }
        }

        // Convert to ordered indices for sequential check.
        let mut indices = remove.iter().map(|idx| idx.index()).collect::<Vec<usize>>();
        indices.sort();

        // Check if indices are sequential
        if self.is_sequential(&indices) {
            self.prune_sequential(indices)
        } else {
            self.prune_non_sequential(remove)
        }
    }

    /// Check if a sorted vector of indices is sequential.
    ///
    /// Internal function that allows use to make assumtion on
    /// prunning a branch from the [`Tree`].
    fn is_sequential(&self, indices: &[usize]) -> bool {
        if indices.is_empty() {
            return true;
        }

        for window in indices.windows(2) {
            if window[1] != window[0] + 1 {
                return false;
            }
        }
        true
    }

    /// Performs optimized removal for sequential index ranges.
    ///
    /// This method avoids unnecessary computation by recognizing that nodes between
    /// the start and end of the removed range do not require index updates.
    ///
    /// # Arguments
    /// * `indices_to_remove` - A sorted vector of sequential indices to remove
    ///
    /// # Returns
    /// * `Ok(())` - If the operation succeeds
    /// * `Err(TreeError)` - If a node error occurs during the update process
    fn prune_sequential(&mut self, indices_to_remove: Vec<usize>) -> Result<(), TreeError>
    where
        N: MutNode<Ix>,
    {
        if indices_to_remove.is_empty() {
            return Ok(());
        }

        let start_idx = indices_to_remove[0];
        let end_idx = indices_to_remove[indices_to_remove.len() - 1];
        let remove_count = indices_to_remove.len();

        // Update references in nodes that will remain
        for (current_idx, node) in self.nodes.iter_mut().enumerate() {
            // Skip nodes that will be removed
            if current_idx >= start_idx && current_idx <= end_idx {
                continue;
            }

            // Update children references
            let updated_children: Vec<NodeIndex<Ix>> = node
                .children()
                .iter()
                .filter_map(|&child_idx| {
                    let child_usize = child_idx.index();

                    if child_usize >= start_idx && child_usize <= end_idx {
                        // Child will be removed
                        None
                    } else if child_usize > end_idx {
                        // Child index needs to be shifted down
                        Some(NodeIndex::new(child_usize - remove_count))
                    } else {
                        // Child index stays the same (before removed range)
                        Some(child_idx)
                    }
                })
                .collect();

            // Clear out nodes from mutable node reference.
            node.clear();

            // Push new index into nodes.
            for child in updated_children {
                if node.contains(&child) {
                    return Err(NodeError::Duplicate {
                        child: child.index(),
                    }
                    .into());
                } else {
                    node.push(child);
                }
            }

            // Update parent reference if node has one
            if let Some(parent_idx) = node.parent() {
                let index = parent_idx.index();

                if index >= start_idx && index <= end_idx {
                    // Parent will be removed
                    node.take_parent();
                } else if index > end_idx {
                    // Parent index needs to be shifted down
                    node.set_parent(NodeIndex::new(index - remove_count));
                }
            }
        }

        // Update root if necessary
        if let Some(root_idx) = self.root {
            let index = root_idx.index();

            if index >= start_idx && index <= end_idx {
                // Root will be removed
                self.root = None;
            } else if index > end_idx {
                // Root index needs to be shifted down
                self.root = Some(NodeIndex::new(index - remove_count));
            }
        }

        // Remove the sequential range in one operation
        self.nodes.drain(start_idx..=end_idx);

        Ok(())
    }

    /// Performs general removal for non-sequential indices.
    ///
    /// This method builds a complete index mapping and updates all node references
    /// before performing the removal operation.
    ///
    /// # Arguments
    /// * `remove` - A set of node indices to remove from the tree
    ///
    /// # Returns
    /// * `Ok(())` - If the operation succeeds
    /// * `Err(TreeError)` - If a node error occurs during the update process
    fn prune_non_sequential(&mut self, remove: BTreeSet<NodeIndex<Ix>>) -> Result<(), TreeError>
    where
        N: MutNode<Ix>,
    {
        // Build index mapping before any modifications
        let mut index_mapping = HashMap::new();
        let mut new_index = 0;

        for index in 0..self.nodes.len() {
            if !remove.contains(&NodeIndex::new(index)) {
                index_mapping.insert(index, new_index);
                new_index += 1;
            }
        }

        // Update all references in remaining nodes
        for (old_idx, node) in self.nodes.iter_mut().enumerate() {
            if !remove.contains(&NodeIndex::new(old_idx)) {
                // Update children
                let updated_children: Vec<NodeIndex<Ix>> = node
                    .children()
                    .iter()
                    .filter_map(|&child_idx| {
                        index_mapping
                            .get(&child_idx.index())
                            .map(|&new_idx| NodeIndex::new(new_idx))
                    })
                    .collect();

                node.clear();
                for child in updated_children {
                    if node.contains(&child) {
                        return Err(NodeError::Duplicate {
                            child: child.index(),
                        }
                        .into());
                    } else {
                        node.push(child);
                    }
                }

                // Update parent if exists
                if let Some(parent_idx) = node.parent() {
                    if let Some(&new_parent_idx) = index_mapping.get(&parent_idx.index()) {
                        node.set_parent(NodeIndex::new(new_parent_idx));
                    } else {
                        node.take_parent(); // Parent was removed
                    }
                }
            }
        }

        // Update root
        if let Some(index) = self.root {
            if let Some(&new_index) = index_mapping.get(&index.index()) {
                self.root = Some(NodeIndex::new(new_index));
            } else {
                self.root = None;
            }
        }

        let mut current_index = 0;
        self.nodes.retain(|_| {
            let should_keep = !remove.contains(&NodeIndex::new(current_index));
            current_index += 1;
            should_keep
        });

        Ok(())
    }

    /// Returns a vector of [`NodeIndex<Ix>`] for all leaf nodes in the tree.
    pub fn leaf_indices(&self) -> Vec<NodeIndex<Ix>> {
        self.iter_idx()
            .filter(|&idx| self.get(idx.index()).is_some_and(|node| node.is_leaf()))
            .collect()
    }

    /// Returns a vector of references to all leaf nodes in the tree.
    pub fn leaves(&self) -> Vec<&N> {
        self.iter_idx()
            .filter_map(|idx| self.get(idx.index()).filter(|node| node.is_leaf()))
            .collect()
    }

    /// Returns a [`Vec`] of mutable references to all leaf nodes in the tree.
    pub fn leaves_mut(&mut self) -> Vec<&mut N>
    where
        N: MutNode<Ix>,
    {
        let mut leaves = Vec::new();
        for node in &mut self.nodes {
            if node.is_leaf() {
                leaves.push(node);
            }
        }
        leaves
    }

    /// Creates a [`TreeView`] from a node reference if found in the tree.
    ///
    /// # Arguments
    /// * `target` - A reference to the node to search for
    ///
    /// # Returns
    /// * `Some(TreeView)` - A view of the subtree rooted at the found node
    /// * `None` - If the node is not found in the tree
    pub fn view(&self) -> TreeView<'_, N, Ix> {
        TreeView::from(self)
    }

    /// Searches for a node by checking its claimed parent-child relationship.
    /// Returns the node's index if found and properly connected.
    #[inline]
    pub fn find(&self, node: &N) -> Option<NodeIndex<Ix>>
    where
        N: PartialEq,
    {
        if let Some(parent_idx) = node.parent() {
            // Node claims to have a parent, check if parent lists it as a child
            let parent = self.get(parent_idx.index())?;
            parent
                .children()
                .iter()
                .find(|&&idx| &self[idx] == node)
                .copied()
        } else {
            // Node claims to be a possilbe root, check if it matches the tree root
            self.root
                .and_then(|idx| self.get(idx.index()))
                .filter(|&root| root == node)
                .and(self.root)
        }
    }

    /// Finds the first node that satisfies the given predicate.
    #[inline]
    pub fn find_by<F>(&self, predicate: F) -> Option<NodeIndex<Ix>>
    where
        F: Fn(&N) -> bool,
    {
        self.iter()
            .enumerate()
            .find(|(_, node)| predicate(node))
            .map(|(idx, _)| NodeIndex::new(idx))
    }

    /// Finds all nodes that satisfy the given predicate.
    #[inline]
    pub fn find_all<F>(&self, predicate: F) -> Vec<NodeIndex<Ix>>
    where
        F: Fn(&N) -> bool,
    {
        self.iter()
            .enumerate()
            .filter(|(_, node)| predicate(node))
            .map(|(idx, _)| NodeIndex::new(idx))
            .collect()
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

    /// Returns Iterator pattern [`IndexIter`] which returns a
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

            for idx in current_node.children() {
                if idx.index() < self.nodes.len() {
                    let child_node = &self[idx];
                    nodes.push((idx, child_node));
                    queue.push_back(idx);
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

impl<N: Node<Ix>, Ix: IndexType> core::ops::Index<usize> for Tree<N, Ix> {
    type Output = N;

    fn index(&self, index: usize) -> &Self::Output {
        &self.nodes[index]
    }
}

impl<N: MutNode<Ix>, Ix: IndexType> core::ops::IndexMut<usize> for Tree<N, Ix> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.nodes[index]
    }
}

impl<N: Node<Ix>, Ix: IndexType> core::ops::Index<NodeIndex<Ix>> for Tree<N, Ix> {
    type Output = N;

    fn index(&self, index: NodeIndex<Ix>) -> &Self::Output {
        &self.nodes[index.index()]
    }
}

impl<N: Node<Ix>, Ix: IndexType> core::ops::IndexMut<NodeIndex<Ix>> for Tree<N, Ix> {
    fn index_mut(&mut self, index: NodeIndex<Ix>) -> &mut Self::Output {
        &mut self.nodes[index.index()]
    }
}

impl<N: Node<Ix> + Display, Ix: IndexType> Tree<N, Ix> {
    /// Generates an ASCII art representation of the tree structure.
    ///
    /// # Arguments
    /// * `node` - The node to use as the root of the ASCII tree
    ///
    /// # Returns
    /// A [`text_trees::TreeNode`] structure representing the tree hierarchy
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

    use super::node::DefaultNode as Node;
    use crate::prelude::*;
    use crate::{MutNode, NodeIndex, Tree};

    #[test]
    fn test_empty_tree_construction() {
        let tree: Tree<Node<u8>> = Tree::new();
        assert!(tree.is_empty())
    }

    #[test]
    fn test_tree_iter() {
        let mut tree: Tree<Node<&str>> = Tree::new();

        let parent = tree.push(Node::new("hello"));
        let child = tree.push(Node::new_with_parent_index("world", parent));
        let l1 = tree.push(Node::new_with_parent_index("!", child));
        let l2 = tree.push(Node::new_with_parent_index("?", child));

        let root = tree.get_mut(parent.index()).unwrap();
        root.push(child);

        let child = tree.get_mut(parent.index()).unwrap();
        child.push(l1);
        child.push(l2);

        let mut tree_iter = tree.into_iter();

        // Test that we get the root first
        let root_ref = tree_iter.next().unwrap();
        assert_eq!(root_ref.value(), &"hello");

        // Test that we get the children in breadth-first order
        let child = tree_iter.next().unwrap();
        assert_eq!(child.value(), &"world");

        let l1 = tree_iter.next().unwrap();
        assert_eq!(l1.value(), &"!");

        let l2 = tree_iter.next().unwrap();
        // Test that iterator is exhausted
        assert_eq!(l2.value(), &"?");
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

    #[test]
    fn test_tree_prune_node_root() {
        let mut root: Node<String> = Node::new("hello".to_string());
        root.children = vec![NodeIndex::new(0), NodeIndex::new(1)];
        let mut tree: Tree<Node<String>> = Tree::new();
        let n1 = Node::new("world".to_string());
        let n2 = Node::new("!".to_string());
        tree.root = Some(NodeIndex::new(2));
        tree.nodes.push(n1.clone());
        tree.nodes.push(n2);
        tree.nodes.push(root);

        tree.prune(NodeIndex::new(2)).unwrap();
        assert!(tree.is_empty());
    }

    #[test]
    fn test_tree_prune_node_leaf_non_seq() {
        let mut root: Node<String> = Node::new("hello".to_string());
        root.children = vec![NodeIndex::new(0), NodeIndex::new(1)];
        let mut tree: Tree<Node<String>> = Tree::new();
        let n1 = Node::new("world".to_string());
        let mut n2 = Node::new("!".to_string());
        let mut n3: Node<String> = Node::new("!!".to_string());

        n2.push(NodeIndex::new(3));

        tree.root = Some(NodeIndex::new(2));
        tree.push(n1);
        let index = tree.push(n2);
        n3.set_parent(index);
        tree.push(root);
        tree.push(n3);

        tree.prune(index).unwrap();
        let expect = ["hello", "world"];
        assert!(
            tree.iter()
                .all(|node| expect.contains(&node.value.as_str()))
        )
    }

    #[test]
    fn test_tree_prune_node_leaf_seq() {
        // construct tree
        let mut tree: Tree<Node<String>> = Tree::new();

        let root = tree.push(Node::new(String::from("hello")));

        // construct children
        let lhs = tree.push(Node::new_with_parent_index(String::from("world"), root));
        let rhs = tree.push(Node::new_with_parent_index(String::from("!"), root));
        let _ = tree.push(Node::new_with_parent_index(String::from("!!"), rhs));

        let root = tree.root_mut();

        root.push(lhs);
        root.push(rhs);

        // remove !, and !!
        tree.prune(rhs).unwrap();

        let expect = ["hello", "world"];
        assert!(
            tree.iter()
                .all(|node| expect.contains(&node.value.as_str()))
        )
    }
}
