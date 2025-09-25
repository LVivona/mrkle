#![allow(dead_code)]
use crate::NodeError;
use crate::prelude::*;

/// Default index type for tree nodes
///
/// **Refrence**: <https://crates.io/crates/petgraph>
pub type DefaultIx = u32;

/// Trait for the unsigned integer type used for node and edge indices.
///
/// # Safety
///
/// Marked `unsafe` because: the trait must faithfully preserve
/// and convert index values.
///
/// **Refrence**: <https://crates.io/crates/petgraph>
pub unsafe trait IndexType:
    Copy
    + Default
    + core::cmp::Ord
    + core::cmp::PartialOrd
    + core::fmt::Debug
    + 'static
    + Send
    + Sync
    + Hash
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
/// **Refrence**: <https://crates.io/crates/petgraph>
#[repr(transparent)]
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

#[cfg(feature = "serde")]
impl<Ix: IndexType> serde::Serialize for NodeIndex<Ix>
where
    Ix: serde::Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de, Ix: IndexType> serde::Deserialize<'de> for NodeIndex<Ix>
where
    Ix: serde::Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let inner = Ix::deserialize(deserializer)?;
        Ok(NodeIndex(inner))
    }
}

impl<Ix: IndexType> From<NodeIndex<Ix>> for usize {
    fn from(value: NodeIndex<Ix>) -> usize {
        value.index()
    }
}

/// Trait for mutable operations on Node data types.
///
/// This trait provides methods for modifying node structure, complementing
/// the read-only operations provided by the [`Node`] trait.
pub trait MutNode<Ix: IndexType = DefaultIx>: Node<Ix> {
    /// Sets the parent index within in node.
    fn set_parent(&mut self, parent: NodeIndex<Ix>);

    /// Removes and returns the parent within the node; if any.
    fn take_parent(&mut self) -> Option<NodeIndex<Ix>>;

    /// Adds a child node index within tree to the end of the children list.
    ///
    /// # Panics
    /// Panics if [`Node`] already exsit within list.
    fn push(&mut self, child: NodeIndex<Ix>);

    /// Tries to add a child, returning an error if the operation is invalid.
    fn try_push(&mut self, child: NodeIndex<Ix>) -> Result<(), NodeError>;

    /// Removes and returns the last child, if any.
    fn pop(&mut self) -> Option<NodeIndex<Ix>>;

    /// Inserts a child at the specified position.
    ///
    /// # Panics
    /// Panics if `index > len`.
    fn insert(&mut self, index: usize, child: NodeIndex<Ix>);

    /// Removes and returns the child at the specified position.
    ///
    /// # Panics
    /// Panics if `index >= len`.
    fn remove(&mut self, index: usize) -> NodeIndex<Ix>;

    /// Removes the first occurrence of the specified child.
    /// Returns `true` if the child was found and removed.
    fn remove_item(&mut self, child: NodeIndex<Ix>) -> bool;

    /// Removes all children and returns them as a vector.
    fn clear(&mut self) -> Vec<NodeIndex<Ix>>;

    /// Retains only the children specified by the predicate.
    fn retain<F>(&mut self, f: F)
    where
        F: FnMut(&NodeIndex<Ix>) -> bool;

    /// Swaps two children at the given indices.
    ///
    /// # Panics
    /// Panics if either index is out of bounds.
    fn swap(&mut self, a: usize, b: usize);

    /// Returns the current capacity for children storage.
    fn capacity(&self) -> usize {
        // Default: capacity equals current length
        self.child_count()
    }
}

/// Trait for generic Node data type.
pub trait Node<Ix: IndexType = DefaultIx> {
    /// Returns if the current node is a leaf (has no children).
    #[inline(always)]
    fn is_leaf(&self) -> bool {
        self.child_count() == 0
    }

    /// Returns if the current node is a root (has no parent).
    #[inline(always)]
    fn is_root(&self) -> bool {
        self.parent().is_none()
    }

    /// Return the number of children.
    #[inline(always)]
    fn child_count(&self) -> usize {
        self.children().len()
    }

    /// Return if Node contains connection to other node through `NodeIndex<Ix>`.
    #[inline(always)]
    fn contains(&self, node: &NodeIndex<Ix>) -> bool {
        self.children().contains(node)
    }

    /// Return child at the specified position.
    #[inline(always)]
    fn child_at(&self, index: usize) -> Option<NodeIndex<Ix>> {
        let children = self.children();
        if children.len() <= index {
            return None;
        }
        Some(children[index])
    }

    /// Return parent if there exists one.
    fn parent(&self) -> Option<NodeIndex<Ix>>;

    /// Return set of children within `Node`.
    fn children(&self) -> Vec<NodeIndex<Ix>>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BasicNode<T, Ix: IndexType = DefaultIx> {
    pub(crate) value: T,
    pub(crate) parent: Option<NodeIndex<Ix>>,
    pub(crate) children: Vec<NodeIndex<Ix>>,
}

impl<T, Ix: IndexType> BasicNode<T, Ix> {
    pub(crate) fn new(value: T) -> Self {
        Self {
            value,
            parent: None,
            children: Vec::new(),
        }
    }
}

impl<T, Ix: IndexType> Node<Ix> for BasicNode<T, Ix> {
    fn is_root(&self) -> bool {
        self.parent.is_none()
    }

    #[inline]
    fn is_leaf(&self) -> bool {
        self.children.is_empty()
    }

    #[inline]
    fn parent(&self) -> Option<NodeIndex<Ix>> {
        self.parent
    }

    #[inline]
    fn children(&self) -> Vec<NodeIndex<Ix>> {
        self.children.clone()
    }

    #[inline]
    fn child_count(&self) -> usize {
        self.children.len()
    }

    fn child_at(&self, index: usize) -> Option<NodeIndex<Ix>> {
        if let Some(&child) = self.children.get(index) {
            return Some(child);
        }
        None
    }

    #[inline]
    fn contains(&self, node: &NodeIndex<Ix>) -> bool {
        self.children.contains(node)
    }
}

impl<T, Ix: IndexType> MutNode<Ix> for BasicNode<T, Ix> {
    #[inline(always)]
    fn push(&mut self, index: NodeIndex<Ix>) {
        self.try_push(index).unwrap()
    }

    #[inline]
    fn insert(&mut self, index: usize, child: NodeIndex<Ix>) {
        self.children.insert(index, child);
    }

    #[inline]
    fn pop(&mut self) -> Option<NodeIndex<Ix>> {
        self.children.pop()
    }

    #[inline]
    fn swap(&mut self, a: usize, b: usize) {
        self.children.swap(a, b);
    }

    #[inline]
    fn retain<F>(&mut self, f: F)
    where
        F: FnMut(&NodeIndex<Ix>) -> bool,
    {
        self.children.retain(f);
    }

    #[inline]
    fn remove(&mut self, index: usize) -> NodeIndex<Ix> {
        self.children.remove(index)
    }

    #[inline]
    fn remove_item(&mut self, child: NodeIndex<Ix>) -> bool {
        if let Some(index) = self.children.iter().position(|&idx| idx == child) {
            self.children.swap_remove(index);
            true
        } else {
            false
        }
    }

    fn set_parent(&mut self, parent: NodeIndex<Ix>) {
        self.parent = Some(parent);
    }

    fn take_parent(&mut self) -> Option<NodeIndex<Ix>> {
        self.parent.take()
    }

    fn try_push(&mut self, index: NodeIndex<Ix>) -> Result<(), NodeError> {
        if self.contains(&index) {
            return Err(NodeError::Duplicate {
                child: index.index(),
            });
        }
        self.children.push(index);
        Ok(())
    }

    fn clear(&mut self) -> Vec<NodeIndex<Ix>> {
        self.children.drain(..).collect()
    }
}

impl<T: Display + Debug, Ix: IndexType> Display for BasicNode<T, Ix> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:?}", self.value)
    }
}

#[cfg(test)]
mod test {}
