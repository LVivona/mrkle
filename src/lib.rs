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

pub use crate::hasher::{GenericArray, Hasher, MrkleHasher};
pub use crate::tree::{DefaultIx, IndexType, MrkleNode, NodeIndex, NodeType, Tree, TreeView};
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
/// [`MrkleTree`] (short for *Merkle Tree*) is a cryptographic hash tree
/// used as the foundation for data validation.
///
/// Merkle Trees enable efficient verification of data integrity, ensuring
/// that each `T` (data block) can be confirmed as received without
/// corruption or tampering.
pub struct MrkleTree<T, D: Digest, Ix: IndexType = DefaultIx>
where
    T: Clone,
{
    /// The underlying tree storing nodes
    core: Tree<T, MrkleNode<T, D, Ix>, Ix>,
    /// The hasher used for digesting nodes
    hasher: MrkleHasher<D>,
}

impl<T, D: Digest> Default for MrkleTree<T, D>
where
    T: Clone,
{
    /// Build a default `MrkleTree` with an empty tree and a new hasher.
    fn default() -> Self {
        Self {
            core: Tree::new(),
            hasher: MrkleHasher::new(),
        }
    }
}

impl<T, D: Digest> MrkleTree<T, D>
where
    T: Clone,
{
    /// Returns `true` if the tree contains no nodes.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.core.is_empty()
    }
}

#[cfg(test)]
mod test {
    use crate::MrkleTree;

    #[test]
    fn test_merkle_tree_default_build() {
        let tree: MrkleTree<[u8; 32], _> = MrkleTree::<[u8; 32], sha1::Sha1>::default();

        assert!(tree.is_empty())
    }
}
