use crate::prelude::*;
use crypto::digest::Digest;

use crate::{Hasher, MrkleHasher, hasher::GenericArray};

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
    Copy + Default + core::cmp::Ord + core::fmt::Debug + 'static
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

impl<Ix: core::fmt::Debug> core::fmt::Debug for NodeIndex<Ix> {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "NodeIndex({:?})", self.0)
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

/// The node identifier for tree nodes.
///
/// Cheap indexing data type that allows for fast clone or copy.
///
/// **Refrence**: https://crates.io/crates/petgraph
#[derive(Copy, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NodeIndex<Ix = DefaultIx>(Ix);

impl<Ix: IndexType> NodeIndex<Ix> {
    #[inline]
    pub fn new(x: usize) -> Self {
        NodeIndex(IndexType::new(x))
    }

    #[inline]
    pub fn index(self) -> usize {
        self.0.index()
    }

    #[inline]
    pub fn end() -> Self {
        NodeIndex(IndexType::max())
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

impl<Ix: IndexType> From<usize> for NodeIndex<Ix> {
    fn from(val: usize) -> Self {
        NodeIndex::new(val)
    }
}

impl<Ix: IndexType> From<u32> for NodeIndex<Ix> {
    fn from(val: u32) -> Self {
        NodeIndex::new(val as usize)
    }
}

/// Trait for generic Node data type.
pub trait NodeType<Ix: IndexType>: Clone {
    /// Returns if the the current node is a leaf.
    #[inline(always)]
    fn is_leaf(&self) -> bool {
        self.parent().is_some() && self.children().len() == 0
    }

    /// Return parent if there exist one.
    fn parent(&self) -> Option<NodeIndex<Ix>>;

    /// Return set of children within `Node`
    fn children(&self) -> Vec<NodeIndex<Ix>>;

    /// Return if Node contain connection to other node though `NodeIndex<Ix>`.
    fn contains(&self, node: &NodeIndex<Ix>) -> bool;
}

/// A generic node in a Merkle Tree.
///
/// [`MekrleNode`] is a our default for our [`Tree`]. It implments The
/// [`NodeType`] trait and stores both the structural relationship
/// and the cryptographic hash value that repersents its subtree.
///
/// # Example
/// ```
/// use mrkle::MrkleNode;
/// use sha1::Sha1;
///
/// let packet = [0u8; 10];
/// let node = MrkleNode::<_, Sha1>::leaf(packet);
/// ```
#[derive(Debug)]
pub struct MrkleNode<T, D: Digest, Ix: IndexType = DefaultIx> {
    /// The internal data of the node.
    ///
    ///
    payload: Payload<T>,
    /// The parents of this node, if any.
    ///
    ///
    parent: Option<NodeIndex<Ix>>,
    /// The children of this node.
    ///
    /// Dependent on the [`Tree`] if the node contains children.
    /// The [`NodeIndex`] points to a location in [`Tree`]
    /// buffer.
    children: Vec<NodeIndex<Ix>>,
    /// The cryptographic hash of this node's contents
    ///
    /// Produced by the [`Hasher`] trait. Leaves are derived from the
    /// Inner data; for internal nodes, it is derived from the
    /// hash of the children.
    pub(crate) hash: GenericArray<D>,
}

impl<T, D: Digest, Ix: IndexType> MrkleNode<T, D, Ix>
where
    T: AsRef<[u8]> + Copy,
{
    /// Build mekrle node with `Digest` trait.
    #[inline]
    pub fn leaf(payload: T) -> Self {
        let block = Payload::Leaf(payload);
        Self {
            payload: block,
            parent: None,
            children: Vec::new(),
            hash: D::digest(*block),
        }
    }

    /// Build merkle node with [`MrkleHasher`].
    #[inline]
    pub fn from_hasher(payload: T, hasher: &MrkleHasher<D>) -> Self {
        let block = Payload::Leaf(payload);
        Self {
            payload: block,
            parent: None,
            children: Vec::new(),
            hash: hasher.hash(*block),
        }
    }
}

impl<T, D: Digest, Ix: IndexType> MrkleNode<T, D, Ix> {
    /// Create mekrle internal node from children.
    pub fn internal(children: Vec<NodeIndex<Ix>>, hash: GenericArray<D>) -> Self {
        Self {
            payload: Payload::Internal,
            parent: None,
            children,
            hash,
        }
    }
}

/// Represents the contents of a node in a Merkle tree.
///
/// A node can either be:
/// - [`Payload::Leaf`] — containing the original data payload (e.g. a block, record, or chunk of bytes),
///   which is hashed directly to form the leaf hash.
/// - [`Payload::Internal`] — representing an internal (non-leaf) node, which does not
///   store data directly but derives its hash from its child nodes.
///
/// This distinction is important for Merkle tree construction, since leaves anchor the
/// tree with actual data, while internal nodes serve as structural parents combining
/// child hashes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Payload<T> {
    /// A leaf node containing a payload value.
    ///
    /// The payload is typically application data (e.g. a byte buffer) that is hashed
    /// directly to form this node’s digest.
    Leaf(T),

    /// An internal node with no direct payload.
    ///
    /// Its hash is derived from the hashes of its child nodes.
    Internal,
}

impl<T> Payload<T> {
    /// Internal Node check if Node is leaf node.
    pub fn is_leaf(&self) -> bool {
        match self {
            Self::Leaf(_) => true,
            _ => false,
        }
    }
}

impl<T> core::ops::Deref for Payload<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        match self {
            Self::Leaf(value) => value,
            _ => panic!("Can not deref a internal node."),
        }
    }
}

impl<T, D: Digest, Ix: IndexType> Clone for MrkleNode<T, D, Ix>
where
    T: Clone,
{
    fn clone(&self) -> Self {
        Self {
            payload: self.payload.clone(),
            parent: self.parent,
            children: self.children.clone(),
            hash: self.hash.clone(),
        }
    }
}

impl<T, D: Digest, Ix: IndexType> NodeType<Ix> for MrkleNode<T, D, Ix>
where
    T: Clone,
{
    fn is_leaf(&self) -> bool {
        self.payload.is_leaf() && self.children.len() == 0
    }
    /// Return if `MrkelNode` has children.
    #[inline]
    fn children(&self) -> Vec<NodeIndex<Ix>> {
        self.children.clone()
    }

    /// Return parent index.
    #[inline]
    fn parent(&self) -> Option<NodeIndex<Ix>> {
        self.parent
    }

    /// Return true if the node contains the child index.
    #[inline]
    fn contains(&self, node: &NodeIndex<Ix>) -> bool {
        self.children.contains(node)
    }
}

#[cfg(test)]
mod test {
    use sha1::Digest;

    use crate::{
        Hasher, MrkleHasher,
        prelude::*,
        tree::{MrkleNode, NodeIndex, NodeType},
    };

    const DATA_PAYLOAD: [u8; 32] = [0u8; 32];

    #[test]
    fn test_is_leaf_logic() {
        let leaf = MrkleNode::<_, sha1::Sha1>::leaf(DATA_PAYLOAD);
        assert!(leaf.is_leaf());

        let hash = MrkleHasher::<sha1::Sha1>::digest(&leaf.hash);
        let internal = MrkleNode::<[u8; 32], sha1::Sha1>::internal(vec![NodeIndex::new(1)], hash);
        assert!(!internal.is_leaf())
    }

    #[test]
    fn test_default_mrkle_node() {
        let node = MrkleNode::<_, sha1::Sha1, usize>::leaf(DATA_PAYLOAD);

        let expected = sha1::Sha1::digest(DATA_PAYLOAD);
        assert_eq!(node.hash, expected)
    }

    #[test]
    fn test_build_with_mrkel() {
        let hasher = MrkleHasher::<sha1::Sha1>::new();
        let node = MrkleNode::<_, sha1::Sha1, usize>::from_hasher(DATA_PAYLOAD, &hasher);

        assert_eq!(node.hash, sha1::Sha1::digest(DATA_PAYLOAD))
    }

    #[test]
    fn test_build_internal_mrkel_node() {
        let hasher = MrkleHasher::<sha1::Sha1>::new();
        let node1 = MrkleNode::<_, sha1::Sha1, usize>::from_hasher(DATA_PAYLOAD, &hasher);
        let node2 = MrkleNode::<_, sha1::Sha1, usize>::from_hasher(DATA_PAYLOAD, &hasher);

        let children: Vec<NodeIndex<usize>> = vec![NodeIndex::new(0), NodeIndex::new(1)];

        let hash = hasher.concat_slice(&[node1.hash, node2.hash]);

        let parent: MrkleNode<[u8; 32], sha1::Sha1, usize> = MrkleNode::internal(children, hash);

        // The expected hash should be just concat the two child
        // using the same digest.
        let expected = {
            let mut hasher = sha1::Sha1::new();
            hasher.update(node1.hash);
            hasher.update(node2.hash);
            hasher.finalize()
        };

        assert_eq!(parent.hash, expected);
    }

    #[test]
    fn test_internal_contains_node_index() {
        let hasher = MrkleHasher::<sha1::Sha1>::new();
        let node1 = MrkleNode::<_, sha1::Sha1, usize>::from_hasher(DATA_PAYLOAD, &hasher);
        let node2 = MrkleNode::<_, sha1::Sha1, usize>::from_hasher(DATA_PAYLOAD, &hasher);

        let children: Vec<NodeIndex<usize>> = vec![NodeIndex::new(0), NodeIndex::new(1)];

        let hash = hasher.concat_slice(&[node1.hash, node2.hash]);

        let parent: MrkleNode<[u8; 32], sha1::Sha1, usize> = MrkleNode::internal(children, hash);

        assert!(parent.contains(&NodeIndex::new(0)));
    }
}
