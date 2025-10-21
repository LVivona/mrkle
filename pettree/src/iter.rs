use crate::prelude::*;

use super::Tree;
use crate::{IndexType, Node, NodeIndex, TreeView};

/// Trait defining traversal order behavior for tree iteration
pub trait TraversalOrder<Ix: IndexType> {
    /// The storage type used for this traversal order
    type Storage: Default;

    /// Add a single node to storage
    fn push(storage: &mut Self::Storage, child: NodeIndex<Ix>);

    /// Add children nodes to storage
    fn extend(storage: &mut Self::Storage, children: impl IntoIterator<Item = NodeIndex<Ix>>);

    /// Remove and return the next node from storage
    fn pop(storage: &mut Self::Storage) -> Option<NodeIndex<Ix>>;

    /// Check if storage is empty
    fn is_empty(storage: &Self::Storage) -> bool;
}

/// Breadth-First Search traversal order (Fifo)
pub struct Fifo;

impl<Ix: IndexType> TraversalOrder<Ix> for Fifo {
    type Storage = VecDeque<NodeIndex<Ix>>;

    #[inline]
    fn push(storage: &mut Self::Storage, value: NodeIndex<Ix>) {
        storage.push_back(value);
    }

    #[inline]
    fn extend(storage: &mut Self::Storage, children: impl IntoIterator<Item = NodeIndex<Ix>>) {
        storage.extend(children);
    }

    #[inline]
    fn pop(storage: &mut Self::Storage) -> Option<NodeIndex<Ix>> {
        storage.pop_front()
    }

    #[inline]
    fn is_empty(storage: &Self::Storage) -> bool {
        storage.is_empty()
    }
}

/// Depth-First Search traversal order (Lifo)
pub struct Lifo;

impl<Ix: IndexType> TraversalOrder<Ix> for Lifo {
    type Storage = Vec<NodeIndex<Ix>>;

    #[inline]
    fn push(storage: &mut Self::Storage, value: NodeIndex<Ix>) {
        storage.push(value);
    }

    #[inline]
    fn extend(storage: &mut Self::Storage, children: impl IntoIterator<Item = NodeIndex<Ix>>) {
        let children: Vec<_> = children.into_iter().collect();
        storage.extend(children.into_iter().rev());
    }

    #[inline]
    fn pop(storage: &mut Self::Storage) -> Option<NodeIndex<Ix>> {
        storage.pop()
    }

    #[inline]
    fn is_empty(storage: &Self::Storage) -> bool {
        storage.is_empty()
    }
}

struct IterState<Storage> {
    storage: Storage,
    started: bool,
}

impl<Storage: Default> IterState<Storage> {
    #[inline]
    fn new() -> Self {
        Self {
            storage: Storage::default(),
            started: false,
        }
    }

    #[inline]
    fn is_started(&self) -> bool {
        self.started
    }

    #[inline]
    fn start(&mut self) {
        self.started = true;
    }
}

/// Iterator over tree nodes in a specific traversal order
pub struct Iter<'a, N, Ix, O = Fifo>
where
    N: Node<Ix>,
    Ix: IndexType,
    O: TraversalOrder<Ix>,
{
    state: IterState<O::Storage>,
    tree: &'a Tree<N, Ix>,
}

impl<'a, N, Ix, O> Iter<'a, N, Ix, O>
where
    N: Node<Ix>,
    Ix: IndexType,
    O: TraversalOrder<Ix>,
{
    /// Creates a new iterator over the tree with the specified traversal order
    #[inline]
    pub fn new(tree: &'a Tree<N, Ix>) -> Self {
        Self {
            state: IterState::new(),
            tree,
        }
    }

    /// Returns the remaining number of nodes in the iterator (lower bound)
    #[inline]
    pub fn remaining_hint(&self) -> (usize, Option<usize>) {
        if !self.state.is_started() {
            (0, Some(self.tree.len()))
        } else {
            (0, None)
        }
    }
}

impl<'a, N, Ix, O> Iterator for Iter<'a, N, Ix, O>
where
    N: Node<Ix>,
    Ix: IndexType,
    O: TraversalOrder<Ix>,
{
    type Item = &'a N;

    fn next(&mut self) -> Option<Self::Item> {
        if !self.state.is_started() {
            if self.tree.is_empty() {
                return None;
            }

            if let Some(root) = self.tree.root {
                O::push(&mut self.state.storage, root);
                self.state.start();
            } else {
                return None;
            }
        }

        let index = O::pop(&mut self.state.storage)?;
        let node = &self.tree[index];

        // Add children to storage if not a leaf
        if !node.is_leaf() {
            O::extend(&mut self.state.storage, node.children().iter().copied());
        }

        Some(node)
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.remaining_hint()
    }
}

impl<N, Ix, O> core::iter::FusedIterator for Iter<'_, N, Ix, O>
where
    N: Node<Ix>,
    Ix: IndexType,
    O: TraversalOrder<Ix>,
{
}

/// Iterator over tree node indices in a specific traversal order
pub struct IndexIter<'a, N, Ix, O = Fifo>
where
    N: Node<Ix>,
    Ix: IndexType,
    O: TraversalOrder<Ix>,
{
    state: IterState<O::Storage>,
    tree: &'a Tree<N, Ix>,
}

impl<'a, N, Ix, O> IndexIter<'a, N, Ix, O>
where
    N: Node<Ix>,
    Ix: IndexType,
    O: TraversalOrder<Ix>,
{
    /// Creates a new index iterator over the tree with the specified traversal order
    #[inline]
    pub fn new(tree: &'a Tree<N, Ix>) -> Self {
        Self {
            state: IterState::new(),
            tree,
        }
    }
}

impl<N, Ix, O> Iterator for IndexIter<'_, N, Ix, O>
where
    N: Node<Ix>,
    Ix: IndexType,
    O: TraversalOrder<Ix>,
{
    type Item = NodeIndex<Ix>;

    fn next(&mut self) -> Option<Self::Item> {
        if !self.state.is_started() {
            if self.tree.is_empty() {
                return None;
            }

            if let Some(root) = self.tree.root {
                O::push(&mut self.state.storage, root);
                self.state.start();
            } else {
                return None;
            }
        }

        let index = O::pop(&mut self.state.storage)?;

        self.tree
            .get(index.index())
            .filter(|&node| !node.is_leaf())
            .inspect(|&node| O::extend(&mut self.state.storage, node.children().iter().copied()));

        Some(index)
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        if !self.state.is_started() {
            (0, Some(self.tree.len()))
        } else {
            (0, None)
        }
    }
}

impl<N, Ix, O> core::iter::FusedIterator for IndexIter<'_, N, Ix, O>
where
    N: Node<Ix>,
    Ix: IndexType,
    O: TraversalOrder<Ix>,
{
}

/// An iterator that moves Node references out of a [`TreeView`] in a specific traversal order
pub struct ViewIter<'a, N, Ix, O = Fifo>
where
    N: Node<Ix>,
    Ix: IndexType,
    O: TraversalOrder<Ix>,
{
    state: IterState<O::Storage>,
    tree: TreeView<'a, N, Ix>,
}

impl<'a, N, Ix, O> ViewIter<'a, N, Ix, O>
where
    N: Node<Ix>,
    Ix: IndexType,
    O: TraversalOrder<Ix>,
{
    /// Creates a new iterator over the tree view with the specified traversal order
    #[inline]
    pub(crate) fn new(tree: TreeView<'a, N, Ix>) -> Self {
        Self {
            state: IterState::new(),
            tree,
        }
    }
}

impl<'a, N, Ix, O> Iterator for ViewIter<'a, N, Ix, O>
where
    N: Node<Ix>,
    Ix: IndexType,
    O: TraversalOrder<Ix>,
{
    type Item = &'a N;

    fn next(&mut self) -> Option<Self::Item> {
        if !self.state.is_started() {
            if self.tree.is_empty() {
                return None;
            }
            O::push(&mut self.state.storage, self.tree.root);
            self.state.start();
        }

        let index = O::pop(&mut self.state.storage)?;
        let node = self.tree.get(&index)?;

        if !node.is_leaf() {
            O::extend(&mut self.state.storage, node.children().iter().copied());
        }

        Some(node)
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        if !self.state.is_started() {
            (0, Some(self.tree.len()))
        } else {
            (0, None)
        }
    }
}

impl<N, Ix, O> core::iter::FusedIterator for ViewIter<'_, N, Ix, O>
where
    N: Node<Ix>,
    Ix: IndexType,
    O: TraversalOrder<Ix>,
{
}

/// An iterator that moves Node indices out of a [`TreeView`] in a specific traversal order
pub struct ViewIndexIter<'a, N, Ix, O = Fifo>
where
    N: Node<Ix>,
    Ix: IndexType,
    O: TraversalOrder<Ix>,
{
    state: IterState<O::Storage>,
    tree: TreeView<'a, N, Ix>,
}

impl<'a, N, Ix, O> ViewIndexIter<'a, N, Ix, O>
where
    N: Node<Ix>,
    Ix: IndexType,
    O: TraversalOrder<Ix>,
{
    /// Creates a new index iterator over the tree view with the specified traversal order
    #[inline]
    pub(crate) fn new(tree: TreeView<'a, N, Ix>) -> Self {
        Self {
            state: IterState::new(),
            tree,
        }
    }
}

impl<N, Ix, O> Iterator for ViewIndexIter<'_, N, Ix, O>
where
    N: Node<Ix>,
    Ix: IndexType,
    O: TraversalOrder<Ix>,
{
    type Item = NodeIndex<Ix>;

    fn next(&mut self) -> Option<Self::Item> {
        if !self.state.is_started() {
            if self.tree.is_empty() {
                return None;
            }
            let root_index = self.tree.root;
            O::push(&mut self.state.storage, root_index);
            self.state.start();
        }

        let index = O::pop(&mut self.state.storage)?;

        self.tree
            .get(&index)
            .filter(|&node| !node.is_leaf())
            .inspect(|&node| O::extend(&mut self.state.storage, node.children().iter().copied()));

        Some(index)
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        if !self.state.is_started() {
            (0, Some(self.tree.len()))
        } else {
            (0, None)
        }
    }
}

impl<N, Ix, O> core::iter::FusedIterator for ViewIndexIter<'_, N, Ix, O>
where
    N: Node<Ix>,
    Ix: IndexType,
    O: TraversalOrder<Ix>,
{
}
