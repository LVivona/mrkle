use crate::NodeError;
use crate::prelude::*;

/// Default index type for tree nodes
///
/// **Refrence**: https://crates.io/crates/petgraph
pub type DefaultIx = u32;

/// Trait for the unsigned integer type used for node and edge indices.
///
/// # Safety
///
/// Marked `unsafe` because: the trait must faithfully preserve
/// and convert index values.
///
/// **Refrence**: https://crates.io/crates/petgraph
pub unsafe trait IndexType:
    Copy + Default + core::cmp::Ord + core::cmp::PartialOrd + core::fmt::Debug + 'static
{
    /// Construct new `IndexType` from usize.
    fn new(x: usize) -> Self;
    /// Return `IndexType` current index value.
    fn index(&self) -> usize;
    /// Return max value.
    fn max() -> Self;
}

unsafe impl IndexType for usize {
    #[inline]
    fn new(x: usize) -> Self {
        x
    }

    #[inline]
    fn index(&self) -> usize {
        *self
    }

    #[inline]
    fn max() -> Self {
        usize::MAX
    }
}

unsafe impl IndexType for u64 {
    #[inline]
    fn new(x: usize) -> Self {
        x as u64
    }

    #[inline]
    fn index(&self) -> usize {
        *self as usize
    }

    #[inline]
    fn max() -> Self {
        u64::MAX
    }
}

unsafe impl IndexType for u32 {
    #[inline]
    fn new(x: usize) -> Self {
        x as u32
    }

    #[inline]
    fn index(&self) -> usize {
        *self as usize
    }

    #[inline]
    fn max() -> Self {
        u32::MAX
    }
}

unsafe impl IndexType for u16 {
    #[inline(always)]
    fn new(x: usize) -> Self {
        x as u16
    }

    #[inline(always)]
    fn index(&self) -> usize {
        *self as usize
    }

    #[inline(always)]
    fn max() -> Self {
        u16::MAX
    }
}

unsafe impl IndexType for u8 {
    #[inline(always)]
    fn new(x: usize) -> Self {
        x as u8
    }

    #[inline(always)]
    fn index(&self) -> usize {
        *self as usize
    }

    #[inline(always)]
    fn max() -> Self {
        u8::MAX
    }
}

impl<Ix: core::fmt::Debug + IndexType> core::fmt::Debug for NodeIndex<Ix> {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "NodeIndex({:?})", self.index())
    }
}

impl<Ix: core::fmt::Debug + IndexType> core::fmt::Display for NodeIndex<Ix> {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "{:?}", self.index())
    }
}

/// The node identifier for tree nodes.
///
/// Cheap indexing data type that allows for fast clone or copy.
///
/// **Refrence**: https://crates.io/crates/petgraph
#[derive(Copy, Clone, Default, PartialEq, Eq, Hash)]
pub struct NodeIndex<Ix: IndexType>(Ix);

impl<Ix: IndexType> NodeIndex<Ix> {
    /// Construct new `IndexType` from usize.
    #[inline]
    pub fn new(x: usize) -> Self {
        NodeIndex(IndexType::new(x))
    }

    /// Return `IndexType` current index value.
    #[inline]
    pub fn index(self) -> usize {
        self.0.index()
    }

    /// Return max value.
    #[inline]
    pub fn end() -> Self {
        NodeIndex(IndexType::max())
    }
}

impl<Ix: IndexType> Ord for NodeIndex<Ix> {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.index().cmp(&other.index())
    }
}

impl<Ix: IndexType> PartialOrd for NodeIndex<Ix> {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<Ix: IndexType> PartialOrd<usize> for NodeIndex<Ix> {
    fn partial_cmp(&self, other: &usize) -> Option<core::cmp::Ordering> {
        self.index().partial_cmp(other)
    }

    fn lt(&self, other: &usize) -> bool {
        self.index() < *other
    }

    fn le(&self, other: &usize) -> bool {
        self.index() <= *other
    }

    fn gt(&self, other: &usize) -> bool {
        self.index() > *other
    }

    fn ge(&self, other: &usize) -> bool {
        self.index() >= *other
    }
}

impl<Ix: IndexType> PartialEq<usize> for NodeIndex<Ix> {
    fn eq(&self, other: &usize) -> bool {
        self.index() == *other
    }
}

unsafe impl<Ix: IndexType> IndexType for NodeIndex<Ix> {
    fn index(&self) -> usize {
        self.0.index()
    }

    fn new(x: usize) -> Self {
        NodeIndex::new(x)
    }

    fn max() -> Self {
        NodeIndex(<Ix as IndexType>::max())
    }
}

impl From<usize> for NodeIndex<usize> {
    fn from(val: usize) -> Self {
        NodeIndex::new(val)
    }
}

impl From<u64> for NodeIndex<u64> {
    fn from(val: u64) -> Self {
        NodeIndex::new(val as usize)
    }
}

impl From<u32> for NodeIndex<u32> {
    fn from(val: u32) -> Self {
        NodeIndex::new(val as usize)
    }
}

impl From<u16> for NodeIndex<u16> {
    fn from(val: u16) -> Self {
        NodeIndex::new(val as usize)
    }
}

impl From<u8> for NodeIndex<u8> {
    fn from(val: u8) -> Self {
        NodeIndex::new(val as usize)
    }
}

/// Trait for generic Node data type.
pub trait NodeType<T, Ix: IndexType = DefaultIx> {
    /// Return the value of the node.
    fn value(&self) -> &T;

    /// Returns if the current node is a leaf (has no children).
    fn is_leaf(&self) -> bool;

    /// Returns if the current node is a root (has no parent).
    fn is_root(&self) -> bool;

    /// Return the number of children.
    fn child_count(&self) -> usize;

    /// Return parent if there exists one.
    fn parent(&self) -> Option<NodeIndex<Ix>>;

    /// Return set of children within `Node`.
    fn children(&self) -> &[NodeIndex<Ix>];

    /// Return if Node contains connection to other node through `NodeIndex<Ix>`.
    fn contains(&self, node: &NodeIndex<Ix>) -> bool;

    /// Return child at the specified position.
    fn child_at(&self, index: usize) -> Option<NodeIndex<Ix>>;

    /// Set the parent node to [`NodeType`].
    fn set_parent(&mut self, parent: Option<NodeIndex<Ix>>);

    /// Remove parent from [`NodeType`].
    fn remove_parent(&mut self) -> Option<NodeIndex<Ix>>;

    /// Remove child from node children.
    fn remove(&mut self, index: NodeIndex<Ix>);

    /// Push [`NodeIndex`] to [`NodeType`].
    fn push(&mut self, index: NodeIndex<Ix>);

    /// Try to push [`NodeIndex`] to [`NodeType`].
    fn try_push(&mut self, index: NodeIndex<Ix>) -> Result<(), NodeError<Ix>>;

    /// Remove all children and return children indcies [`NodeIndex`].
    fn clear(&mut self) -> Vec<NodeIndex<Ix>>;

    /// Convert leaf [`NodeType`] into parent.
    fn into_parent(&mut self) -> Result<(), NodeError<Ix>> {
        unimplemented!("no possible way to turn a child into a parnet.")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node<T, Ix: IndexType = DefaultIx> {
    pub value: T,
    pub(crate) parent: Option<NodeIndex<Ix>>,
    pub(crate) children: Vec<NodeIndex<Ix>>,
}

impl<T, Ix: IndexType> Node<T, Ix> {
    pub(crate) fn new(value: T) -> Self {
        Self {
            value,
            parent: None,
            children: Vec::new(),
        }
    }
}

impl<T, Ix: IndexType> NodeType<T, Ix> for Node<T, Ix> {
    fn value(&self) -> &T {
        &self.value
    }

    fn is_root(&self) -> bool {
        self.parent.is_none()
    }

    #[inline]
    fn is_leaf(&self) -> bool {
        self.children.len() == 0
    }

    #[inline]
    fn parent(&self) -> Option<NodeIndex<Ix>> {
        self.parent
    }

    #[inline]
    fn children(&self) -> &[NodeIndex<Ix>] {
        &self.children
    }

    #[inline]
    fn child_count(&self) -> usize {
        self.children.len()
    }

    fn child_at(&self, index: usize) -> Option<NodeIndex<Ix>> {
        if let Some(&child) = self.children.get(index) {
            return Some(child);
        } else {
            return None;
        }
    }

    #[inline]
    fn contains(&self, node: &NodeIndex<Ix>) -> bool {
        self.children.contains(node)
    }

    #[inline(always)]
    fn push(&mut self, index: NodeIndex<Ix>) {
        self.try_push(index).unwrap()
    }

    #[inline]
    fn remove(&mut self, index: NodeIndex<Ix>) {
        if let Some(idx) = self.children.iter().position(|idx| idx == &index) {
            self.children.swap_remove(idx);
        }
    }

    fn set_parent(&mut self, parent: Option<NodeIndex<Ix>>) {
        self.parent = parent;
    }

    fn remove_parent(&mut self) -> Option<NodeIndex<Ix>> {
        self.parent.take()
    }

    fn try_push(&mut self, index: NodeIndex<Ix>) -> Result<(), NodeError<Ix>> {
        if self.contains(&index) {
            return Err(NodeError::Duplicate { child: index });
        }
        self.children.push(index);
        return Ok(());
    }

    fn clear(&mut self) -> Vec<NodeIndex<Ix>> {
        self.children.drain(..).collect()
    }
}

#[cfg(test)]
mod test {}
