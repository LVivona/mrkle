use crate::prelude::*;
use core::iter::Iterator;

use crate::{IndexType, NodeIndex, NodeType, TreeView};

/*
 * TODO:
 * It might be better to create an iterator trait that
 * preforms diffrent types of searchs within the tree
 * allowing for maybe universal tree traversal.
 *
 */

/// An iterator that moves Nodes references out of a [`TreeView`].
///
/// This `struct` is created by the `into_iter` method on [`TreeView`]
/// (provided by the [`IntoIterator`] trait).
pub struct Iter<'a, T, N: NodeType<T, Ix>, Ix: IndexType> {
    /// internal queue for node reterival.
    queue: VecDeque<NodeIndex<Ix>>,
    /// [`Tree`] reference.
    inner: TreeView<'a, T, N, Ix>,
    /// stopping flag initiated after root has been
    /// allocated to the queue.
    stop: bool,
}

impl<'a, T, N: NodeType<T, Ix>, Ix: IndexType> Iter<'a, T, N, Ix> {
    pub(crate) fn new(tree: TreeView<'a, T, N, Ix>) -> Self {
        Self {
            queue: VecDeque::from([]),
            inner: tree,
            stop: false,
        }
    }
}

impl<'a, T, N: NodeType<T, Ix>, Ix: IndexType> Iterator for Iter<'a, T, N, Ix> {
    type Item = &'a N;
    fn next(&mut self) -> Option<Self::Item> {
        if let Some(index) = &self.queue.pop_front() {
            let node = self.inner.get(&index)?;
            if !node.is_leaf() {
                self.queue.extend(node.children());
            }
            return Some(node);
        } else {
            if self.inner.is_empty() || self.stop {
                return None;
            } else {
                let root = self.inner.root();
                self.queue.extend(root.children());
                self.stop = true;
                return Some(root);
            }
        }
    }
}

/// An iterator that moves Nodes Index out of a [`TreeView`].
pub struct IterIdx<'a, T, N: NodeType<T, Ix>, Ix: IndexType> {
    queue: VecDeque<NodeIndex<Ix>>,
    inner: TreeView<'a, T, N, Ix>,
    stop: bool,
}

impl<'a, T, N: NodeType<T, Ix>, Ix: IndexType> IterIdx<'a, T, N, Ix> {
    pub(crate) fn new(tree: TreeView<'a, T, N, Ix>) -> Self {
        Self {
            queue: VecDeque::from([]),
            inner: tree,
            stop: false,
        }
    }
}

impl<'a, T, N: NodeType<T, Ix>, Ix: IndexType> Iterator for IterIdx<'a, T, N, Ix> {
    type Item = NodeIndex<Ix>;
    fn next(&mut self) -> Option<Self::Item> {
        if let Some(index) = &self.queue.pop_front() {
            let node = self.inner.get(&index)?;
            if !node.is_leaf() {
                self.queue.extend(node.children());
            }
            return Some(*index);
        } else {
            // Possible stop cases where Iterator ends.
            if self.inner.is_empty() || self.stop {
                return None;
            } else {
                let root = self.inner.root();
                self.queue.extend(root.children());
                self.stop = true;
                return Some(self.inner.root);
            }
        }
    }
}
