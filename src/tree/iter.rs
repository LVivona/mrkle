use crate::prelude::*;
use core::iter::Iterator;

use crate::{
    IndexType, NodeType,
    tree::{NodeIndex, Tree},
};

/// TODO:
/// It might be better to create an iterator trait that
/// preforms diffrent types of searchs within the tree
/// allowing for maybe universal tree traversal.
pub struct Iter<'a, T, N: NodeType<Ix>, Ix: IndexType> {
    queue: VecDeque<NodeIndex<Ix>>,
    inner: &'a Tree<T, N, Ix>,
    stop: bool,
}

impl<'a, T, N: NodeType<Ix>, Ix: IndexType> Iter<'a, T, N, Ix> {
    pub(crate) fn new(tree: &'a Tree<T, N, Ix>) -> Self {
        Self {
            queue: VecDeque::from([]),
            inner: tree,
            stop: false,
        }
    }
}

impl<'a, T, N: NodeType<Ix>, Ix: IndexType> Iterator for Iter<'a, T, N, Ix> {
    type Item = &'a N;
    fn next(&mut self) -> Option<Self::Item> {
        if let Some(index) = &self.queue.pop_front() {
            if let Some(node) = self.inner.nodes.get(index.index()) {
                if !node.is_leaf() {
                    self.queue.extend(node.children());
                }
                return Some(node);
            } else {
                return None;
            }
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
