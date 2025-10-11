#![allow(dead_code)]
#![allow(unused_variables)]
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
    /// Sets the parent index within the node.
    fn set_parent(&mut self, _parent: NodeIndex<Ix>) {}

    /// Removes and returns the parent within the node, if any.
    fn take_parent(&mut self) -> Option<NodeIndex<Ix>> {
        unimplemented!("take_parent has not been implemented.")
    }

    /// Adds a child node index to the end of the children list.
    ///
    /// # Panics
    /// Panics if the child already exists within the list
    /// or any other [`NodeError`] occurs.
    fn push(&mut self, _child: NodeIndex<Ix>) {}

    /// Tries to add a child, returning an error if the operation is invalid.
    fn try_push(&mut self, _child: NodeIndex<Ix>) -> Result<(), NodeError> {
        unimplemented!("try_push has not been implemented.")
    }

    /// Removes and returns the last child within the list, if any.
    fn pop(&mut self) -> Option<NodeIndex<Ix>> {
        unimplemented!("pop has not been implemented.")
    }

    /// Inserts a child at the specified position.
    ///
    /// # Panics
    /// Panics if `index > len`.
    fn insert(&mut self, _index: usize, _child: NodeIndex<Ix>) {}

    /// Removes and returns the child at the specified position.
    ///
    /// # Panics
    /// Panics if `index >= len`.
    fn remove(&mut self, _index: usize) -> NodeIndex<Ix> {
        unimplemented!("remove has not been implemented.")
    }

    /// Removes the first occurrence of the specified child.
    ///
    /// Returns `true` if the child was found and removed.
    fn remove_item(&mut self, _child: NodeIndex<Ix>) -> bool {
        unimplemented!("remove_item has not been implemented.")
    }

    /// Removes all children and returns them as a vector.
    fn clear(&mut self) -> Vec<NodeIndex<Ix>> {
        unimplemented!("clear has not been implemented.")
    }

    /// Retains only the children specified by the predicate.
    fn retain<F>(&mut self, _f: F)
    where
        F: FnMut(&NodeIndex<Ix>) -> bool,
    {
        unimplemented!("retain has not been implemented.")
    }

    /// Swaps two children at the given indices.
    ///
    /// # Panics
    /// Panics if either index is out of bounds.
    fn swap(&mut self, _a: usize, _b: usize) {
        unimplemented!("swap has not been implemented.")
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
pub(crate) struct DefaultNode<T, Ix: IndexType = DefaultIx> {
    /// Internal value should be
    pub(crate) value: T,
    /// Each Node should contain a possible index to its parent.
    pub(crate) parent: Option<NodeIndex<Ix>>,
    /// list of possible children.
    pub(crate) children: Vec<NodeIndex<Ix>>,
}

impl<T, Ix: IndexType> Default for DefaultNode<T, Ix>
where
    T: Default,
{
    fn default() -> Self {
        Self {
            value: T::default(),
            children: Vec::new(),
            parent: None,
        }
    }
}

impl<T, Ix: IndexType> DefaultNode<T, Ix> {
    pub(crate) fn new(value: T) -> Self {
        Self {
            value,
            parent: None,
            children: Vec::new(),
        }
    }

    fn value_mut(&mut self) -> &mut T {
        &mut self.value
    }

    fn value(&self) -> &T {
        &self.value
    }
}

impl<T, Ix: IndexType> Node<Ix> for DefaultNode<T, Ix> {
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

impl<T, Ix: IndexType> MutNode<Ix> for DefaultNode<T, Ix> {
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

impl<T: Display + Debug, Ix: IndexType> Display for DefaultNode<T, Ix> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:?}", self.value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_construction() {
        let n0: DefaultNode<i32> = DefaultNode::default();
        let n1: DefaultNode<i32> = DefaultNode::default();

        assert!(n0.value() == n1.value())
    }

    #[test]
    fn test_new_with_value() {
        let n0: DefaultNode<i32> = DefaultNode::new(42);
        assert_eq!(*n0.value(), 42);
        assert!(n0.is_root());
        assert!(n0.is_leaf());
    }

    #[test]
    fn test_basic_is_empty_children() {
        let n0: DefaultNode<i32> = DefaultNode::default();
        assert!(n0.children().is_empty())
    }

    #[test]
    fn test_basic_empty_parent() {
        let n0: DefaultNode<i32> = DefaultNode::default();
        assert!(n0.parent().is_none())
    }

    #[test]
    fn test_link_nodes() {
        let mut stack: Vec<DefaultNode<i32>> = Vec::with_capacity(2);
        let n0: DefaultNode<i32> = DefaultNode::default();
        let n1: DefaultNode<i32> = DefaultNode::default();

        stack.push(n0);
        stack.push(n1);

        stack[0].push(NodeIndex::new(1));
        stack[1].set_parent(NodeIndex::new(0));

        assert!(stack[0].is_root());
        assert!(stack[1].is_leaf());

        if let Some(parent) = stack[1].parent() {
            assert!(stack[parent.index()].is_root())
        } else {
            panic!("Parent should exist.")
        }
    }

    #[test]
    fn test_push_multiple_children() {
        let mut node: DefaultNode<i32> = DefaultNode::new(1);
        node.push(NodeIndex::new(2));
        node.push(NodeIndex::new(3));
        node.push(NodeIndex::new(4));

        assert_eq!(node.child_count(), 3);
        assert!(!node.is_leaf());
        assert!(node.contains(&NodeIndex::new(2)));
        assert!(node.contains(&NodeIndex::new(3)));
        assert!(node.contains(&NodeIndex::new(4)));
    }

    #[test]
    #[should_panic]
    fn test_push_duplicate_child_panics() {
        let mut node: DefaultNode<i32> = DefaultNode::new(1);
        node.push(NodeIndex::new(2));
        node.push(NodeIndex::new(2)); // Should panic
    }

    #[test]
    fn test_try_push_duplicate_returns_error() {
        let mut node: DefaultNode<i32> = DefaultNode::new(1);
        assert!(node.try_push(NodeIndex::new(2)).is_ok());

        let result = node.try_push(NodeIndex::new(2));
        assert!(result.is_err());

        if let Err(NodeError::Duplicate { child }) = result {
            assert_eq!(child, 2);
        } else {
            panic!("Expected Duplicate error");
        }
    }

    #[test]
    fn test_pop_child() {
        let mut node: DefaultNode<i32> = DefaultNode::new(1);
        node.push(NodeIndex::new(2));
        node.push(NodeIndex::new(3));

        assert_eq!(node.pop(), Some(NodeIndex::new(3)));
        assert_eq!(node.child_count(), 1);
        assert_eq!(node.pop(), Some(NodeIndex::new(2)));
        assert_eq!(node.child_count(), 0);
        assert_eq!(node.pop(), None);
    }

    #[test]
    fn test_insert_child() {
        let mut node: DefaultNode<i32> = DefaultNode::new(1);
        node.push(NodeIndex::new(2));
        node.push(NodeIndex::new(4));

        node.insert(1, NodeIndex::new(3));

        assert_eq!(node.child_count(), 3);
        assert_eq!(node.child_at(0), Some(NodeIndex::new(2)));
        assert_eq!(node.child_at(1), Some(NodeIndex::new(3)));
        assert_eq!(node.child_at(2), Some(NodeIndex::new(4)));
    }

    #[test]
    fn test_remove_child() {
        let mut node: DefaultNode<i32> = DefaultNode::new(1);
        node.push(NodeIndex::new(2));
        node.push(NodeIndex::new(3));
        node.push(NodeIndex::new(4));

        let removed: NodeIndex<u32> = node.remove(1);
        assert_eq!(removed, NodeIndex::new(3));
        assert_eq!(node.child_count(), 2);
        assert_eq!(node.child_at(0), Some(NodeIndex::new(2)));
        assert_eq!(node.child_at(1), Some(NodeIndex::new(4)));
    }

    #[test]
    fn test_remove_item() {
        let mut node: DefaultNode<i32> = DefaultNode::new(1);
        node.push(NodeIndex::new(2));
        node.push(NodeIndex::new(3));
        node.push(NodeIndex::new(4));

        assert!(node.remove_item(NodeIndex::new(3)));
        assert_eq!(node.child_count(), 2);
        assert!(!node.contains(&NodeIndex::new(3)));

        // Removing non-existent child returns false
        assert!(!node.remove_item(NodeIndex::new(10)));
    }

    #[test]
    fn test_swap_children() {
        let mut node: DefaultNode<i32> = DefaultNode::new(1);
        node.push(NodeIndex::new(2));
        node.push(NodeIndex::new(3));
        node.push(NodeIndex::new(4));

        node.swap(0, 2);

        assert_eq!(node.child_at(0), Some(NodeIndex::new(4)));
        assert_eq!(node.child_at(1), Some(NodeIndex::new(3)));
        assert_eq!(node.child_at(2), Some(NodeIndex::new(2)));
    }

    #[test]
    fn test_clear_children() {
        let mut node: DefaultNode<i32> = DefaultNode::new(1);
        node.push(NodeIndex::new(2));
        node.push(NodeIndex::new(3));
        node.push(NodeIndex::new(4));

        let cleared = node.clear();

        assert_eq!(cleared.len(), 3);
        assert_eq!(node.child_count(), 0);
        assert!(node.is_leaf());
        assert!(cleared.contains(&NodeIndex::new(2)));
        assert!(cleared.contains(&NodeIndex::new(3)));
        assert!(cleared.contains(&NodeIndex::new(4)));
    }

    #[test]
    fn test_retain_children() {
        let mut node: DefaultNode<i32> = DefaultNode::new(1);
        node.push(NodeIndex::new(2));
        node.push(NodeIndex::new(3));
        node.push(NodeIndex::new(4));
        node.push(NodeIndex::new(5));

        // Keep only even indices
        node.retain(|idx| idx.index() % 2 == 0);

        assert_eq!(node.child_count(), 2);
        assert!(node.contains(&NodeIndex::new(2)));
        assert!(node.contains(&NodeIndex::new(4)));
        assert!(!node.contains(&NodeIndex::new(3)));
        assert!(!node.contains(&NodeIndex::new(5)));
    }

    #[test]
    fn test_set_and_take_parent() {
        let mut node: DefaultNode<i32> = DefaultNode::new(1);
        assert!(node.is_root());

        node.set_parent(NodeIndex::new(0));
        assert!(!node.is_root());
        assert_eq!(node.parent(), Some(NodeIndex::new(0)));

        let taken = node.take_parent();
        assert_eq!(taken, Some(NodeIndex::new(0)));
        assert!(node.is_root());
        assert_eq!(node.parent(), None);
    }

    #[test]
    fn test_child_at_out_of_bounds() {
        let mut node: DefaultNode<i32> = DefaultNode::new(1);
        node.push(NodeIndex::new(2));

        assert_eq!(node.child_at(0), Some(NodeIndex::new(2)));
        assert_eq!(node.child_at(1), None);
        assert_eq!(node.child_at(100), None);
    }

    #[test]
    fn test_value_access() {
        let mut node: DefaultNode<i32> = DefaultNode::new(42);
        assert_eq!(*node.value(), 42);

        *node.value_mut() = 100;
        assert_eq!(*node.value(), 100);
    }

    #[test]
    fn test_display_implementation() {
        let node: DefaultNode<&str> = DefaultNode::new("test");
        let display_str = format!("{}", node);
        assert!(display_str.contains("test"));
    }

    #[test]
    fn test_clone_node() {
        let mut node: DefaultNode<i32> = DefaultNode::new(1);
        node.push(NodeIndex::new(2));
        node.set_parent(NodeIndex::new(0));

        let cloned = node.clone();

        assert_eq!(node, cloned);
        assert_eq!(cloned.child_count(), 1);
        assert_eq!(cloned.parent(), Some(NodeIndex::new(0)));
    }

    #[test]
    fn test_is_leaf_is_root_combinations() {
        let mut node: DefaultNode<i32> = DefaultNode::new(1);

        // Initially: root and leaf
        assert!(node.is_root());
        assert!(node.is_leaf());

        // Add child: root but not leaf
        node.push(NodeIndex::new(2));
        assert!(node.is_root());
        assert!(!node.is_leaf());

        // Set parent: not root, not leaf
        node.set_parent(NodeIndex::new(0));
        assert!(!node.is_root());
        assert!(!node.is_leaf());

        // Remove child: not root, but is leaf
        node.pop();
        assert!(!node.is_root());
        assert!(node.is_leaf());
    }

    #[test]
    fn test_children_returns_clone() {
        let mut node: DefaultNode<i32> = DefaultNode::new(1);
        node.push(NodeIndex::new(2));
        node.push(NodeIndex::new(3));

        let children1 = node.children();
        let children2 = node.children();

        // Should be equal but different instances
        assert_eq!(children1, children2);
        assert_eq!(children1.len(), 2);
    }

    #[test]
    fn test_multiple_operations_sequence() {
        let mut node: DefaultNode<i32> = DefaultNode::new(1);

        // Build tree structure
        node.push(NodeIndex::new(2));
        node.push(NodeIndex::new(3));
        node.push(NodeIndex::new(4));
        assert_eq!(node.child_count(), 3);

        // Remove middle child
        let removed = node.remove(1);
        assert_eq!(removed, NodeIndex::new(3));
        assert_eq!(node.child_count(), 2);

        // Insert new child at beginning
        node.insert(0, NodeIndex::new(5));
        assert_eq!(node.child_count(), 3);
        assert_eq!(node.child_at(0), Some(NodeIndex::new(5)));

        // Swap first and last
        node.swap(0, 2);
        assert_eq!(node.child_at(0), Some(NodeIndex::new(4)));
        assert_eq!(node.child_at(2), Some(NodeIndex::new(5)));

        // Clear all
        let cleared = node.clear();
        assert_eq!(cleared.len(), 3);
        assert!(node.is_leaf());
    }
}
