#![deny(missing_docs)]
#![doc = include_str!("../README.md")]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
#[macro_use]
extern crate alloc;

#[cfg(all(feature = "std", feature = "alloc"))]
compile_error!("must choose either the `std` or `alloc` feature, but not both.");
#[cfg(all(not(feature = "std"), not(feature = "alloc")))]
compile_error!("must choose either the `std` or `alloc` feature");

#[path = "entry.rs"]
mod borrowed;

/// Cryptographic hash utilities and traits used in Merkle trees.
pub mod hasher;

/// Core tree structures and nodes for the Merkle tree implementation.
///
/// This module contains [`MrkleNode`], [`Tree`], and the [`NodeType`] trait.
pub(crate) mod tree;

/// Error types for the Merkle tree crate.
///
/// Includes errors for tree construction, hashing, and I/O operations.
pub mod error;

pub(crate) use crate::error::{EntryError, NodeError, TreeError};
pub(crate) use crate::tree::DefaultIx;

pub use crate::hasher::{GenericArray, Hasher, MrkleHasher};
pub use crate::tree::{IndexType, NodeIndex, NodeType, Tree, TreeView};
pub use borrowed::*;

use crypto::digest::Digest;

#[allow(unused_imports, reason = "future proofing for tree features.")]
pub(crate) mod prelude {
    #[cfg(not(feature = "std"))]
    mod no_stds {
        pub use alloc::borrow::{Borrow, Cow, ToOwned};
        pub use alloc::collections::{BTreeMap, VecDeque};
        pub use alloc::str;
        pub use alloc::string::{String, ToString};
        pub use alloc::vec::Vec;
    }

    #[cfg(feature = "std")]
    mod stds {
        pub use std::borrow::{Borrow, Cow, ToOwned};
        pub use std::collections::{BTreeMap, VecDeque};
        pub use std::str;
        pub use std::string::{String, ToString};
        pub use std::vec::Vec;
    }

    pub use core::marker::{Copy, PhantomData};
    #[cfg(not(feature = "std"))]
    pub use no_stds::*;
    #[cfg(feature = "std")]
    pub use stds::*;
}

use prelude::*;

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

impl<T, D: Digest, Ix: IndexType> NodeType<T, Ix> for MrkleNode<T, D, Ix> {
    fn value(&self) -> &T {
        &self.payload
    }

    fn is_root(&self) -> bool {
        self.parent.is_none()
    }

    #[inline]
    fn is_leaf(&self) -> bool {
        self.payload.is_leaf() && self.children.len() == 0
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
            return Err(error::NodeError::Duplicate { child: index });
        }
        self.children.push(index);
        return Ok(());
    }

    fn clear(&mut self) -> Vec<NodeIndex<Ix>> {
        self.children.drain(..).collect()
    }
}

impl<T, D: Digest, Ix: IndexType> AsRef<entry> for MrkleNode<T, D, Ix> {
    fn as_ref(&self) -> &entry {
        entry::from_bytes_unchecked(&self.hash)
    }
}

impl<T, D: Digest> core::borrow::Borrow<entry> for MrkleNode<T, D> {
    fn borrow(&self) -> &entry {
        self.as_ref()
    }
}

/// A wrapper around the [`Tree`] data structure.
/// [`MrkleTree`] (short for *Merkle Tree*) is a cryptographic immutable hash tree
/// used as the foundation for data validation.
///
/// Merkle Trees enable efficient verification of data integrity, ensuring
/// that each `T` (data block) can be confirmed as received without
/// corruption or tampering.
pub struct MrkleTree<T, D: Digest, Ix: IndexType = DefaultIx> {
    /// The underlying tree storing nodes
    core: Tree<T, MrkleNode<T, D, Ix>, Ix>,
}

impl<T, D: Digest> Default for MrkleTree<T, D> {
    /// Build a default `MrkleTree` with an empty tree and a new hasher.
    fn default() -> Self {
        Self { core: Tree::new() }
    }
}

impl<T, D: Digest> MrkleTree<T, D> {
    /// Returns `true` if the tree contains no nodes.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.core.is_empty()
    }
}

#[cfg(test)]
mod test {

    use crate::{Hasher, MrkleHasher, MrkleNode, MrkleTree, NodeIndex, NodeType, prelude::*};
    use sha1::Digest;

    const DATA_PAYLOAD: [u8; 32] = [0u8; 32];

    #[test]
    fn test_merkle_tree_default_build() {
        let tree: MrkleTree<[u8; 32], _> = MrkleTree::<[u8; 32], sha1::Sha1>::default();

        assert!(tree.is_empty())
    }

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
