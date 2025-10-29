#![allow(dead_code)]
use crate::prelude::*;

use crate::{DefaultIx, DefaultNode, IndexType, MutNode, NodeIndex, Tree};
use crate::{NodeError, TreeBuilderError, TreeError};

use core::ops::Range;

type Result<T> = std::result::Result<T, TreeBuilderError>;

/// Allow for Join operation to be applied to [`MutNode<Ix>`].
///
/// To be able construct the tree from the bottom up we need
/// to construct a join operation that allows us to preform [`Node<Ix>`]
/// some sort of arbitrary creation of internal parent from our leaves.
pub trait NodeJoin<Ix: IndexType>: MutNode<Ix> + Sized {
    /// Returns an internal node from two nodes with no parent.
    fn join(lhs: &Self, rhs: &Self) -> std::result::Result<Self, NodeError>;
    /// Returns an internal node from more than 1 child, with no parent.
    fn multi_join(nodes: &[Self]) -> std::result::Result<Self, NodeError>;

    /// Returns an internal node from two nodes with no parent (taking ownership).
    ///
    /// This is useful when you want to consume the nodes rather than borrow them.
    fn join_owned(lhs: Self, rhs: Self) -> std::result::Result<Self, NodeError> {
        Self::join(&lhs, &rhs)
    }

    /// Returns an internal node from more than 1 child (taking ownership).
    fn multi_join_owned(nodes: Vec<Self>) -> std::result::Result<Self, NodeError> {
        Self::multi_join(&nodes)
    }
}

impl<T, Ix: IndexType> NodeJoin<Ix> for DefaultNode<T, Ix>
where
    T: Default,
{
    fn join(_lhs: &Self, _rhs: &Self) -> std::result::Result<Self, NodeError> {
        Ok(DefaultNode::default())
    }

    fn multi_join(_nodes: &[Self]) -> std::result::Result<Self, NodeError> {
        Ok(DefaultNode::default())
    }
}

/// A builder for constructing trees from the bottom up.
///
/// # Examples
/// ```
/// use pettree::{TreeBuilder, DefaultNode as Node};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let tree = TreeBuilder::<Node<u8>>::new()
///     .push(Node::default())
///     .push(Node::default())
///     .join(0..2)?
///     .finish()?;
/// # Ok(())
/// # }
/// ```

pub struct TreeBuilder<N: NodeJoin<Ix>, Ix: IndexType = DefaultIx> {
    // Internal tree structure we want to return at the end
    // of the tree builder is finished.
    inner: Tree<N, Ix>,
    // Internal level buffer.
    //
    // Buffer holds the current layer nodes we want
    // to add in our tree.
    buffer: Vec<N>,
}

impl<N: NodeJoin<Ix>, Ix: IndexType> Default for TreeBuilder<N, Ix> {
    fn default() -> Self {
        Self::new()
    }
}

impl<N: NodeJoin<Ix>, Ix: IndexType> TreeBuilder<N, Ix> {
    /// Construct a new TreeBuilder that allows us to construct from the bottom up.
    ///
    ///
    pub fn new() -> Self {
        Self {
            inner: Tree::new(),
            buffer: Vec::new(),
        }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            inner: Tree::new(),
            buffer: Vec::with_capacity(capacity),
        }
    }

    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    #[inline]
    pub fn push(mut self, node: N) -> Self {
        self.buffer.push(node);
        self
    }

    /// Join a range of nodes within pushed buffer.
    ///
    /// Within the buffer take a range of the nodes
    /// and create a parent from those nodes.
    ///
    /// # Example
    /// ```
    /// use pettree::{TreeBuilder, DefaultNode as Node};
    ///
    ///# fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let tree = TreeBuilder::<Node<u8>>::new()
    ///     .push(Node::default())
    ///     .push(Node::default())
    ///     .join(0..2)?
    ///     .finish()?;
    /// #  Ok(())
    /// #  }
    ///
    /// ```
    pub fn join(mut self, range: Range<usize>) -> Result<Self> {
        let range: Range<usize> = range.into();
        // Check if the node exceeds the buffer
        if range.end > self.buffer.len() || range.start >= range.end {
            return Err(TreeBuilderError::InvalidRange);
        }
        // Maximum range should be greater than 2 nodes.
        if range.len() < 2 {
            return Err(TreeBuilderError::InsufficientNodes);
        }
        // Drain out the buffer of nodes we want to join.
        let nodes: Vec<N> = self.buffer.drain(range.clone()).collect();
        let parent_index: NodeIndex<Ix> = NodeIndex::new(self.inner.len() + range.end);

        let mut parent = N::multi_join(&nodes).map_err(TreeError::from)?;

        // borrow mutable node to set the parent of the nodes
        for mut node in nodes {
            node.set_parent(parent_index);
            let child = self.inner.push(node);
            parent.push(child);
        }

        self.buffer.insert(range.start, parent);
        Ok(self)
    }

    /// Join all remaining nodes in the buffer into a single tree.
    /// This is called automatically by `finish()` if there are nodes left in the buffer.
    fn join_all(mut self) -> Result<Self> {
        // assuming the buffer is greater then 1. then take the rest of the buffer
        // and join the full range.
        while self.buffer.len() > 1 {
            // Join all nodes in the buffer
            let range = 0..self.buffer.len();

            let nodes: Vec<N> = self.buffer.drain(range.clone()).collect();
            let parent_index: NodeIndex<Ix> = NodeIndex::new(self.inner.len() + range.end);

            let mut parent = N::multi_join(&nodes).map_err(TreeError::from)?;

            // borrow mutable node to set the parent of the nodes
            for mut node in nodes {
                node.set_parent(parent_index);
                let child = self.inner.push(node);
                parent.push(child);
            }

            self.buffer.insert(range.start, parent);
        }

        // Push the final root node to the tree
        if let Some(root) = self.buffer.pop() {
            self.inner.push(root);
        }

        Ok(self)
    }

    /// Finish building the tree and return it.
    pub fn finish(mut self) -> Result<Tree<N, Ix>> {
        // Auto-join remaining nodes
        if self.buffer.len() > 1 {
            self = self.join_all()?;
        }

        // Push final node and set root
        if let Some(root) = self.buffer.pop() {
            let root_idx = self.inner.push(root);
            self.inner.set_root(Some(root_idx));
        } else if !self.inner.is_empty() {
            self.inner
                .set_root(Some(NodeIndex::new(self.inner.len() - 1)));
        }

        Ok(self.inner)
    }
}

impl<N: NodeJoin<Ix> + Display, Ix: IndexType> core::fmt::Display for TreeBuilder<N, Ix> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.inner)
    }
}

#[cfg(test)]
mod test {
    use crate::builder::TreeBuilder;
    use crate::{DefaultNode, Tree};

    #[test]
    fn test_basic_binary_tree() {
        let tree: Tree<DefaultNode<u8>> = TreeBuilder::new()
            .push(DefaultNode::new(1))
            .push(DefaultNode::new(2))
            .join(0..2)
            .unwrap()
            .finish()
            .unwrap();

        assert_eq!(tree.len(), 3);
    }

    #[test]
    fn test_basic_single_leaf() {
        let tree: Tree<DefaultNode<u8>> = TreeBuilder::new()
            .push(DefaultNode::new(1))
            .join_all()
            .unwrap()
            .finish()
            .unwrap();

        println!("{tree}");
        assert_eq!(tree.len(), 1);
    }

    #[test]
    fn test_basic_n_leaf() {
        let mut builder: TreeBuilder<DefaultNode<i32>> = TreeBuilder::new();
        for i in 1..11 {
            builder = builder.push(DefaultNode::new(i));
        }

        let tree: Tree<DefaultNode<i32, _>, _> = builder.join_all().unwrap().finish().unwrap();

        println!("{tree}");
        assert_eq!(tree.len(), 11);
    }
}
