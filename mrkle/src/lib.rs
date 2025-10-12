#![deny(missing_docs)]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/LVivona/mrkle/refs/heads/main/.github/assets/logo.png"
)]
#![doc = include_str!("../DOC_README.md")]
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
mod builder;
mod proof;

/// Cryptographic hash utilities and traits used in Merkle trees.
pub mod hasher;

/// Core tree structures and nodes for the Merkle tree implementation.
///
/// This module contains [`MrkleNode`], [`Tree`], and the [`Node`] trait.
pub mod tree;

/// Error types for the Merkle tree crate.
///
/// Includes errors for tree construction, hashing, and I/O operations.
pub mod error;

use crate::error::MrkleError;
pub(crate) use crate::error::{EntryError, NodeError, ProofError, TreeError};
pub(crate) use crate::tree::DefaultIx;

pub use crate::builder::MrkleDefaultBuilder;
pub use crate::hasher::{GenericArray, Hasher, MrkleHasher};
pub use crate::proof::{MrkleProof, ProofLevel, ProofPath};
pub use crate::tree::{IndexIter, IndexType, Iter, MutNode, Node, NodeIndex, Tree, TreeView};
pub use borrowed::*;

#[allow(unused_imports, reason = "future proofing for tree features.")]
pub(crate) mod prelude {
    #[cfg(not(feature = "std"))]
    mod no_stds {
        pub use alloc::borrow::{Borrow, Cow, ToOwned};
        pub use alloc::boxed::Box;
        pub use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
        pub use alloc::str;
        pub use alloc::string::{String, ToString};
        pub use alloc::vec::Vec;
        pub use hashbrown::{HashMap, HashSet};
    }

    #[cfg(feature = "std")]
    mod stds {
        pub use std::borrow::{Borrow, Cow, ToOwned};
        pub use std::boxed::Box;
        pub use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
        pub use std::str;
        pub use std::string::{String, ToString};
        pub use std::vec::Vec;
    }

    pub use core::fmt::{Debug, Display};
    pub use core::hash::Hash;
    pub use core::marker::{Copy, PhantomData};
    pub use core::slice::SliceIndex;
    pub(crate) use crypto::digest::Digest;
    #[cfg(not(feature = "std"))]
    pub use no_stds::*;
    #[cfg(feature = "std")]
    pub use stds::*;
}

use prelude::*;

/// A generic immutable node in a Merkle Tree.
///
/// [`MrkleNode`] is a our default for our [`Tree`]. It implments The
/// [`Node`] trait and stores both the structural relationship
/// and the cryptographic hash value that repersents its subtree.
///
/// # Example
/// ```
/// use mrkle::MrkleNode;
/// use sha1::Sha1;
///
/// // data packet payload
/// let packet = [0u8; 10];
/// let node = MrkleNode::<_, Sha1>::leaf(packet);
/// ```
pub struct MrkleNode<T, D: Digest, Ix: IndexType = DefaultIx> {
    /// The internal data of the node.
    payload: Payload<T>,
    /// The parents of this node, if any.
    pub parent: Option<NodeIndex<Ix>>,
    /// The children of this node.
    ///
    /// Dependent on the [`Tree`] if the node contains children.
    /// The [`NodeIndex`] points to a location in [`Tree`]
    /// buffer.
    pub(crate) children: Vec<NodeIndex<Ix>>,
    /// The cryptographic hash of this node's contents
    ///
    /// Produced by the [`Hasher`] trait. Leaves are derived from the
    /// Inner data; for internal nodes, it is derived from the
    /// hash of the children.
    pub(crate) hash: GenericArray<D>,
}

impl<T, D: Digest, Ix: IndexType> Eq for MrkleNode<T, D, Ix> {}

impl<T, D: Digest, Ix: IndexType> MrkleNode<T, D, Ix>
where
    T: AsRef<[u8]> + Clone,
{
    /// Creates a new leaf node with the given payload.
    ///
    /// This method constructs a leaf node by computing the cryptographic hash
    /// of the payload using the digest algorithm `D`. The resulting node has
    /// no parent or children and represents a terminal node in the Merkle tree.
    ///
    /// # Arguments
    ///
    /// * `payload` - The data to store in this leaf node. Must implement [`AsRef<[u8]>`]
    ///   to allow hashing of the underlying bytes.
    ///
    /// # Returns
    ///
    /// A new [`MrkleNode`] configured as a leaf node with the computed hash.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use mrkle::{MrkleNode, Node};
    /// use sha2::Sha256;
    ///
    /// let data = b"Hello, world!";
    /// let leaf = MrkleNode::<_, Sha256>::leaf(*data);
    /// assert!(leaf.is_leaf());
    /// ```
    ///
    /// # Performance
    ///
    /// This method performs one hash computation using the specified digest algorithm.
    #[inline]
    pub fn leaf(payload: T) -> Self {
        let hash = D::digest(&payload);
        let payload = Payload::Leaf(payload);
        Self {
            payload,
            hash,
            parent: None,
            children: Vec::with_capacity(0),
        }
    }

    /// Creates a new leaf node with a pre-computed hash.
    ///
    /// This method allows creation of a leaf node when the hash has already been
    /// computed externally. The method verifies that the provided hash matches
    /// the hash of the payload data to ensure integrity.
    ///
    /// # Arguments
    ///
    /// * `payload` - The data to store in this leaf node
    /// * `hash` - The pre-computed cryptographic hash of the payload
    ///
    /// # Returns
    ///
    /// A new [`MrkleNode`] configured as a leaf node with the provided hash.
    ///
    /// # Panics
    ///
    /// Panics if the provided `hash` does not match the digest of the `payload`.
    /// This verification ensures the integrity of the Merkle tree structure.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use mrkle::{MrkleNode, Node};
    /// use sha2::{Sha256, Digest};
    ///
    /// let data = b"Hello, world!";
    /// let hash = Sha256::digest(data);
    /// let leaf = MrkleNode::<_, Sha256>::leaf_with_hash(*data, hash);
    /// assert!(leaf.is_leaf());
    /// ```
    ///
    /// ```rust,should_panic
    /// use mrkle::MrkleNode;
    /// use sha2::{Sha256, Digest};
    ///
    /// let data = b"Hello, world!";
    /// let wrong_hash = Sha256::digest(b"Different data");
    /// // This will panic due to hash mismatch
    /// let leaf = MrkleNode::<_, Sha256>::leaf_with_hash(*data, wrong_hash);
    /// ```
    ///
    /// # Security Considerations
    ///
    /// This method performs hash verification to prevent malicious or accidental
    /// corruption of the tree structure. Always ensure the hash is computed from
    /// the exact same payload data.
    pub fn leaf_with_hash(payload: T, hash: GenericArray<D>) -> Self {
        /// Helper function to provide better panic messages for hash mismatches.
        ///
        /// This function is marked with `#[cold]` to optimize for the common case
        /// where hashes match correctly.
        #[cold]
        #[inline(never)]
        fn assert_hash_digest<D: Digest>(value: &GenericArray<D>) {
            panic!(
                "Hash verification failed: provided hash {value:?} does not match \
                     the computed digest of the payload data. This indicates either \
                     corrupted data or an incorrect hash value."
            );
        }

        if D::digest(&payload) != hash {
            assert_hash_digest::<D>(&hash);
        }

        let payload = Payload::Leaf(payload);
        Self {
            payload,
            hash,
            parent: None,
            children: Vec::with_capacity(0),
        }
    }

    /// Creates a new leaf node using a custom hasher instance.
    ///
    /// This method allows the use of a specialized [`MrkleHasher`] that may have
    /// custom configuration or state. This is useful when you need consistent
    /// hashing behavior across multiple nodes or when using hasher-specific features.
    ///
    /// # Arguments
    ///
    /// * `payload` - The data to store in this leaf node
    /// * `hasher` - A reference to a [`MrkleHasher`] instance to compute the hash
    ///
    /// # Returns
    ///
    /// A new [`MrkleNode`] configured as a leaf node with hash computed by the hasher.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use mrkle::{MrkleNode, MrkleHasher, Node};
    /// use sha2::Sha256;
    ///
    /// let data = b"Hello, world!";
    /// let hasher = MrkleHasher::<Sha256>::new();
    /// let leaf = MrkleNode::<_, Sha256>::leaf_with_hasher(*data, &hasher);
    /// assert!(leaf.is_leaf());
    /// ```
    ///
    /// # Use Cases
    ///
    /// - Custom hash computation with specialized parameters
    /// - Consistent hashing across multiple nodes
    /// - Integration with existing hasher instances
    /// - Performance optimization through hasher reuse
    pub fn leaf_with_hasher(payload: T, hasher: &MrkleHasher<D>) -> Self {
        let hash = hasher.hash(&payload);
        let payload = Payload::Leaf(payload);
        Self {
            payload,
            hash,
            parent: None,
            children: Vec::with_capacity(0),
        }
    }
}

impl<T, D: Digest, Ix: IndexType> MrkleNode<T, D, Ix> {
    /// Creates a new internal (non-leaf) node with the specified children and tree.
    ///
    /// Internal nodes represent the structural components of the Merkle tree that
    /// combine child node hashes. They do not store application data directly
    /// but serve as cryptographic proofs of their subtree contents.
    ///
    /// # Arguments
    ///
    /// * `children` - A vector of [`NodeIndex`] references pointing to child nodes
    /// * `hash` - The cryptographic hash computed from the child node hashes
    ///
    /// # Returns
    ///
    /// A new [`MrkleNode`] configured as an internal node.
    ///
    /// # Examples
    ///
    /// ```rust ignore
    /// use mrkle::{MrkleNode, NodeIndex, Node};
    /// use sha2::Sha256;
    ///
    /// // Create child nodes first
    /// let child1 = MrkleNode::<Vec<u8>, Sha256>::leaf(b"data1".to_vec());
    /// let child2 = MrkleNode::<Vec<u8>, Sha256>::leaf(b"data2".to_vec());
    ///
    /// // Compute combined hash of children
    /// let mut hasher = Sha256::new();
    /// hasher.update(&child1.hash);
    /// hasher.update(&child2.hash);
    /// let combined_hash = hasher.finalize();
    ///
    /// let children = vec![NodeIndex::new(0), NodeIndex::new(1)];
    /// let internal = MrkleNode::<Vec<u8>, Sha256>::internal(children, combined_hash);
    /// assert!(!internal.is_leaf());
    /// ```
    ///
    /// # Security Notes
    ///
    /// - The hash should be computed from the concatenation or combination of child hashes
    /// - The order of children affects the final hash and tree structure
    /// - This method does not verify the hash against the children for performance reasons
    ///
    /// # Visibility
    ///
    /// This method is `pub(crate)` as internal node creation should typically be
    /// managed by the tree construction algorithms rather than external users.
    #[inline]
    pub fn internal(
        tree: &Tree<MrkleNode<T, D, Ix>, Ix>,
        children: Vec<NodeIndex<Ix>>,
    ) -> Result<Self, MrkleError> {
        let mut hasher = D::new();
        children
            .iter()
            .try_for_each(|&idx| {
                if let Some(node) = tree.get(idx.index()) {
                    if node.parent().is_some() {
                        return Err(TreeError::from(NodeError::ParentConflict {
                            parent: node.parent().unwrap().index(),
                            child: idx.index(),
                        }));
                    }
                    hasher.update(node.hash());
                    Ok(())
                } else {
                    Err(TreeError::from(NodeError::NodeNotFound {
                        index: idx.index(),
                    }))
                }
            })
            .map_err(MrkleError::from)?;

        let hash = hasher.finalize();

        Ok(Self {
            payload: Payload::Internal,
            parent: None,
            children,
            hash,
        })
    }

    /// Creates a new internal (non-leaf) node with the specified children and tree.
    pub fn internal_with_hash(hash: GenericArray<D>, children: Vec<NodeIndex<Ix>>) -> Self {
        Self {
            payload: Payload::Internal,
            parent: None,
            children,
            hash,
        }
    }

    /// Return reference to internal value.
    pub fn value(&self) -> Option<&T> {
        if let Payload::Leaf(value) = &self.payload {
            Some(value)
        } else {
            None
        }
    }

    /// Return Reference to [`MrkleNode`] hash.
    pub fn hash(&self) -> &GenericArray<D> {
        &self.hash
    }

    /// Return a [`HexDisplay`] of the node hash.
    pub fn to_hex(&self) -> HexDisplay<'_> {
        entry::from_bytes(&self.hash[..]).to_hex()
    }
}

/// Represents the contents of a node in a Merkle tree.
///
/// This distinction is important for Merkle tree construction, since leaves anchor the
/// tree with actual data, while internal nodes serve as structural parents combining
/// child hashes.
///
/// # Variants
/// - [`Payload::Leaf`] — containing the original data payload (e.g. a block, record, or chunk of bytes),
///   which is hashed directly to form the leaf hash.
/// - [`Payload::Internal`] — representing an internal (non-leaf) node, which does not
///   store data directly but derives its hash from its child nodes.
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
    #[inline]
    pub fn is_leaf(&self) -> bool {
        matches!(self, Self::Leaf(_))
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

#[cfg(feature = "serde")]
impl<T> serde::Serialize for Payload<T>
where
    T: serde::Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Payload::Leaf(data) => serializer.serialize_some(data),
            Payload::Internal => serializer.serialize_none(),
        }
    }
}

#[cfg(feature = "serde")]
impl<'de, T> serde::Deserialize<'de> for Payload<T>
where
    T: serde::Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let opt: Option<T> = Option::deserialize(deserializer)?;
        match opt {
            Some(data) => Ok(Payload::Leaf(data)),
            None => Ok(Payload::Internal),
        }
    }
}

/// Since the object is immutable we only need to compare the hashes.
impl<T, D: Digest, Ix: IndexType> PartialEq for MrkleNode<T, D, Ix> {
    fn eq(&self, other: &Self) -> bool {
        self.hash == other.hash
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

impl<T, D: Digest, Ix: IndexType> Node<Ix> for MrkleNode<T, D, Ix> {
    fn is_root(&self) -> bool {
        self.parent.is_none() && !self.payload.is_leaf()
    }

    #[inline]
    fn is_leaf(&self) -> bool {
        self.payload.is_leaf() && self.children.is_empty()
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

impl<T, D: Digest, Ix: IndexType> AsRef<entry> for MrkleNode<T, D, Ix> {
    fn as_ref(&self) -> &entry {
        entry::from_bytes_unchecked(&self.hash)
    }
}

impl<T, D: Digest, Ix: IndexType> AsRef<[u8]> for MrkleNode<T, D, Ix> {
    fn as_ref(&self) -> &[u8] {
        &self.hash
    }
}

impl<T, D: Digest> core::borrow::Borrow<entry> for MrkleNode<T, D> {
    fn borrow(&self) -> &entry {
        self.as_ref()
    }
}

impl<T, D: Digest, Ix: IndexType> core::fmt::Debug for MrkleNode<T, D, Ix> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut debug_struct = f.debug_struct("MrkleNode");

        debug_struct
            .field("type", &if self.is_leaf() { "leaf" } else { "internal" })
            .field("is_root", &self.is_root())
            .field("child_count", &self.child_count());

        if let Some(parent) = &self.parent {
            debug_struct.field("parent", parent);
        }

        if !self.children.is_empty() {
            debug_struct.field("children", &self.children);
        }

        let bytes = &self.hash;
        if bytes.len() > 8 {
            debug_struct.field(
                "hash",
                &format!(
                    "{:02x?}{:02x?}...{:02x?}{:02x?}",
                    bytes[0],
                    bytes[1],
                    bytes[bytes.len() - 2],
                    bytes[bytes.len() - 1]
                ),
            );
        } else {
            debug_struct.field("hash", &format!("{:02x?}", bytes));
        }

        debug_struct.finish()
    }
}

// Display implementation - user-friendly representation
impl<T, D: Digest, Ix: IndexType> Display for MrkleNode<T, D, Ix> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let hash_bytes = self.hash.as_slice();
        let hash_preview = if hash_bytes.len() >= 4 {
            format!(
                "{:02x}{:02x}...{:02x}{:02x}",
                hash_bytes[0],
                hash_bytes[1],
                hash_bytes[hash_bytes.len() - 2],
                hash_bytes[hash_bytes.len() - 1]
            )
        } else {
            format!("{:02x?}", hash_bytes)
        };

        write!(f, "{}", hash_preview)
    }
}

#[cfg(feature = "serde")]
impl<T, D: Digest, Ix: IndexType> serde::Serialize for MrkleNode<T, D, Ix>
where
    T: serde::Serialize,
    Ix: serde::Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("MrkleNode", 4)?;

        state.serialize_field("hash", &self.hash[..])?;
        state.serialize_field("parent", &self.parent)?;
        state.serialize_field("children", &self.children)?;
        state.serialize_field("payload", &self.payload)?;

        state.end()
    }
}

#[cfg(feature = "serde")]
impl<'de, T, D: Digest, Ix: IndexType> serde::Deserialize<'de> for MrkleNode<T, D, Ix>
where
    T: serde::Deserialize<'de>,
    Ix: serde::Deserialize<'de>,
{
    fn deserialize<_D>(deserializer: _D) -> Result<Self, _D::Error>
    where
        _D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        #[serde(field_identifier, rename_all = "lowercase")]
        enum Field {
            Payload,
            Parent,
            Children,
            Hash,
        }

        struct MrkleNodeVisitor<T, D: Digest, Ix: IndexType> {
            marker: PhantomData<(T, D, Ix)>,
        }
        impl<'de, T, D: Digest, Ix: IndexType> serde::de::Visitor<'de> for MrkleNodeVisitor<T, D, Ix>
        where
            T: serde::Deserialize<'de>,
            Ix: serde::Deserialize<'de>,
        {
            type Value = MrkleNode<T, D, Ix>;

            fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
                formatter.write_str("struct MrkleNode")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let hash_layout: Vec<u8> = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;

                let parent: Option<NodeIndex<Ix>> = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(1, &self))?;

                let children: Vec<NodeIndex<Ix>> = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(2, &self))?;

                let payload: Payload<T> = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(3, &self))?;

                let hash: GenericArray<D> =
                    crypto::digest::generic_array::GenericArray::clone_from_slice(&hash_layout);

                Ok(MrkleNode {
                    payload,
                    parent,
                    children,
                    hash,
                })
            }

            fn visit_map<V>(self, mut map: V) -> Result<MrkleNode<T, D, Ix>, V::Error>
            where
                V: serde::de::MapAccess<'de>,
            {
                let mut payload = None;
                let mut parent = None;
                let mut children = None;
                let mut hash_bytes: Option<Vec<u8>> = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Payload => {
                            if payload.is_some() {
                                return Err(serde::de::Error::duplicate_field("payload"));
                            }
                            payload = Some(map.next_value()?);
                        }
                        Field::Parent => {
                            if parent.is_some() {
                                return Err(serde::de::Error::duplicate_field("parent"));
                            }
                            parent = Some(map.next_value()?);
                        }
                        Field::Children => {
                            if children.is_some() {
                                return Err(serde::de::Error::duplicate_field("children"));
                            }
                            children = Some(map.next_value()?);
                        }
                        Field::Hash => {
                            if hash_bytes.is_some() {
                                return Err(serde::de::Error::duplicate_field("hash"));
                            }
                            hash_bytes = Some(map.next_value()?);
                        }
                    }
                }

                let payload = payload.ok_or_else(|| serde::de::Error::missing_field("payload"))?;
                let parent = parent.ok_or_else(|| serde::de::Error::missing_field("parent"))?;
                let children =
                    children.ok_or_else(|| serde::de::Error::missing_field("children"))?;
                let hash_bytes =
                    hash_bytes.ok_or_else(|| serde::de::Error::missing_field("hash"))?;

                let hash: GenericArray<D> =
                    crypto::digest::generic_array::GenericArray::clone_from_slice(&hash_bytes);

                Ok(MrkleNode {
                    payload,
                    parent,
                    children,
                    hash,
                })
            }
        }

        const FIELDS: &[&str] = &["hash", "parent", "children", "payload"];
        deserializer.deserialize_struct(
            "MrkleNode",
            FIELDS,
            MrkleNodeVisitor {
                marker: PhantomData,
            },
        )
    }
}

unsafe impl<T: Send, D: Digest, Ix: IndexType> Send for MrkleNode<T, D, Ix> {}
unsafe impl<T: Sync, D: Digest, Ix: IndexType> Sync for MrkleNode<T, D, Ix> {}

/// A cryptographic hash tree data structure.
///
/// A `MrkleNode` is a generic tree data structure where each leaf node represents a data block and each
/// internal node contains a cryptographic hash of its children. This structure enables
/// efficient and secure verification of large data structures.
///
/// The tree provides verification of any element's inclusion and integrity
/// without requiring the entire dataset. This makes Merkle trees particularly useful
/// for distributed systems, blockchain technologies, and data integrity verification.
///
///
/// # Type Parameters
///
/// * `T` - The type of data stored in leaf nodes
/// * `D` - The digest algorithm implementing [`Digest`] trait (e.g., SHA-256)
/// * `Ix` - The index type for node references, defaults to `DefaultIx`
///
///
/// # Example
///
/// ```
/// use mrkle::MrkleTree;
/// use sha1::Sha1;
///
/// // build basic binary merkle tree.
/// let tree = MrkleTree::<&str, Sha1>::from(vec![
///     "A",
///     "B",
///     "C",
///     "D",
///     "E",
/// ]);
/// ```
///
/// # Security Considerations
///
/// The security of a `MrkleTree` depends entirely on the cryptographic strength
/// of the chosen digest algorithm `D`. Using weak or broken hash functions
/// compromises the tree's integrity guarantees.
///
#[must_use]
pub struct MrkleTree<T, D: Digest, Ix: IndexType = DefaultIx> {
    /// The underlying tree data structure.
    ///
    /// This field is private to maintain invariants about the tree structure
    /// and ensure all modifications go through the proper cryptographic
    /// verification process.
    core: Tree<MrkleNode<T, D, Ix>, Ix>,
}

impl<T, D: Digest, Ix: IndexType> Default for MrkleTree<T, D, Ix> {
    /// Construct a new default `MrkleTree`.
    ///
    /// The tree will not allocate until tree has been build. since the object
    /// is immutable when construction we can not push nodeds onto the tree.
    ///
    /// #  Examples
    ///
    /// ```
    /// use mrkle::MrkleTree;
    /// use sha1::Sha1;
    ///
    /// let tree: MrkleTree<u8, Sha1> = MrkleTree::default();
    /// ```
    fn default() -> Self {
        Self {
            core: Tree::<_, Ix>::new(),
        }
    }
}

impl<T, D: Digest, Ix: IndexType> MrkleTree<T, D, Ix> {
    pub(crate) fn new(tree: Tree<MrkleNode<T, D, Ix>, Ix>) -> Self {
        Self { core: tree }
    }
}

impl<T, D: Digest, Ix: IndexType> MrkleTree<T, D, Ix>
where
    T: AsRef<[u8]> + Clone,
{
    /// Constructs a `MrkleTree` from leaf nodes.
    ///
    /// # Arguments
    /// * `leaves` - Vector of `T` nodes to build the tree from
    ///
    /// # Returns
    /// A generic binary [`MrkleTree`]
    ///
    /// # Example
    /// ```
    /// use mrkle::MrkleTree;
    /// use sha1::Sha1;
    /// let leaves : Vec<&str> = vec![
    ///     "A",
    ///     "B",
    ///     "C",
    ///     "D",
    /// ];
    ///
    /// let tree = MrkleTree::<&str, Sha1>::from_leaves(leaves);
    /// ```
    pub fn from_leaves(leaves: Vec<T>) -> Result<MrkleTree<T, D, Ix>, MrkleError> {
        MrkleDefaultBuilder::build_from_data(leaves)
    }
}

impl<T, D: Digest, Ix: IndexType> MrkleTree<T, D, Ix> {
    /// Return [`Tree`] root node [`MrkleNode`] refrecne.
    pub fn root(&self) -> &MrkleNode<T, D, Ix> {
        self.core.root()
    }

    /// Return reference to root [`GenericArray<D>`].
    pub fn root_hash(&self) -> &GenericArray<D> {
        &self.core.root().hash
    }

    /// Return reference to root [`HexDisplay<'_>`].
    pub fn root_hex(&self) -> HexDisplay<'_> {
        self.core.root().to_hex()
    }

    /// Returns `true` if the tree contains no nodes.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.core.is_empty()
    }

    /// Return the length of the [`Tree`] i.e # of nodes
    #[inline]
    pub fn len(&self) -> usize {
        self.core.len()
    }

    /// Returns the total number of nodes the vector can hold without reallocating.
    #[inline]
    pub fn capacity(&self) -> usize {
        self.core.capacity()
    }

    /// Return children Nodes as immutable references of the given index.
    #[inline]
    pub fn get_children(&self, index: NodeIndex<Ix>) -> Vec<&MrkleNode<T, D, Ix>> {
        self.get(index.index()).map_or(Vec::new(), |node| {
            node.children()
                .iter()
                .map(|&idx| self.get(idx.index()).unwrap())
                .collect()
        })
    }

    /// Return a childen of the indexed node as a vector of [`NodeIndex<Ix>`].
    #[inline]
    pub fn get_children_indices(&self, index: NodeIndex<Ix>) -> Vec<NodeIndex<Ix>> {
        self.get(index.index())
            .map(|node| node.children())
            .unwrap_or_default()
    }

    /// Returns a reference to an element [`MrkleNode<T, D, Ix>`].
    pub fn get<I>(&self, index: I) -> Option<&I::Output>
    where
        I: SliceIndex<[MrkleNode<T, D, Ix>]>,
    {
        self.core.get(index)
    }

    /// Return root [`TreeView`] of the [`MrkleTree`]
    #[inline]
    pub fn view(&self) -> TreeView<'_, MrkleNode<T, D, Ix>, Ix> {
        self.core.view()
    }

    /// Return a vector of  [`NodeIndex<Ix>`].
    #[inline]
    pub fn leaf_indices(&self) -> Vec<NodeIndex<Ix>> {
        self.core.leaf_indices()
    }

    /// Return a vector of  [`Node`] references.
    #[inline]
    pub fn leaves(&self) -> Vec<&MrkleNode<T, D, Ix>> {
        self.core.leaves()
    }

    /// Searches for a node by checking its claimed parent-child relationship.
    ///
    /// Returns the node’s index if found and properly connected.
    pub fn find(&self, node: &MrkleNode<T, D, Ix>) -> Option<NodeIndex<Ix>> {
        self.core.find(node)
    }

    /// Create a [`TreeView`] of the Merkle tree
    /// from a node reference as root if found, else return None.
    #[inline]
    pub fn subtree_view(
        &self,
        root: NodeIndex<Ix>,
    ) -> Option<TreeView<'_, MrkleNode<T, D, Ix>, Ix>> {
        self.core.subtree_view(root)
    }

    /// Returns Iterator pattern [`Iter`] which returns a unmutable Node reference.
    pub fn iter(&self) -> Iter<'_, MrkleNode<T, D, Ix>, Ix> {
        self.core.iter()
    }

    ///Returns Iterator pattern [`IndexIter`] which returns a [`NodeIndex<Ix>`] of the node.
    pub fn iter_idx(&self) -> IndexIter<'_, MrkleNode<T, D, Ix>, Ix> {
        self.core.iter_idx()
    }

    /// Generate [`MrkleProof`] from a leaf index within the [`MrkleTree`]
    pub fn generate_proof(&self, index: Vec<NodeIndex<Ix>>) -> MrkleProof<D>
where {
        MrkleProof::generate_basic(self, &index).unwrap()
    }

    /// Verify if leaves belong to [`MrkleProof`].
    pub fn verify(proof: &MrkleProof<D>, data: Vec<T>) -> Result<bool, ProofError>
    where
        T: AsRef<[u8]>,
    {
        let leaves = data
            .iter()
            .map(|item| D::digest(item))
            .collect::<Vec<GenericArray<D>>>();

        proof.verify(leaves)
    }
}

impl<T, D: Digest, Ix: IndexType> MrkleTree<T, D, Ix>
where
    T: Eq + PartialEq,
{
    /// Create a [`TreeView`] from a node reference if found, else return None.
    pub fn subtree_from_node(
        &self,
        target: &MrkleNode<T, D, Ix>,
    ) -> Option<TreeView<'_, MrkleNode<T, D, Ix>, Ix>> {
        self.core.subtree_from_node(target)
    }
}

impl<'a, T, D: Digest, Ix: IndexType> IntoIterator for &'a MrkleTree<T, D, Ix> {
    type IntoIter = Iter<'a, MrkleNode<T, D, Ix>, Ix>;
    type Item = &'a MrkleNode<T, D, Ix>;
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<T, D: Digest, Ix: IndexType> From<Vec<T>> for MrkleTree<T, D, Ix>
where
    T: AsRef<[u8]> + Clone,
{
    fn from(value: Vec<T>) -> Self {
        MrkleTree::from_leaves(value).unwrap()
    }
}

impl<T, D: Digest, Ix: IndexType, const N: usize> From<&[T; N]> for MrkleTree<T, D, Ix>
where
    T: AsRef<[u8]> + Clone,
{
    fn from(value: &[T; N]) -> Self {
        MrkleTree::from_leaves(value.to_vec()).unwrap()
    }
}

impl<T, D: Digest, Ix: IndexType> From<VecDeque<T>> for MrkleTree<T, D, Ix>
where
    T: AsRef<[u8]> + Clone,
{
    fn from(value: VecDeque<T>) -> Self {
        MrkleTree::from_leaves(value.into()).unwrap()
    }
}

impl<T, D: Digest, Ix: IndexType> From<Box<[T]>> for MrkleTree<T, D, Ix>
where
    T: AsRef<[u8]> + Clone,
{
    fn from(value: Box<[T]>) -> Self {
        MrkleTree::from_leaves(value.into_vec()).unwrap()
    }
}

impl<T, D: Digest, Ix: IndexType> Display for MrkleTree<T, D, Ix> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.core)
    }
}

impl<T, D: Digest, Ix: IndexType> Debug for MrkleTree<T, D, Ix> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.core)
    }
}

impl<T, D: Digest, Ix: IndexType> PartialEq for MrkleTree<T, D, Ix> {
    fn eq(&self, other: &Self) -> bool {
        if self.root() != other.root() {
            return false;
        }

        self.len() == other.len() && self.iter().eq(other.iter())
    }
}
impl<T, D: Digest, Ix: IndexType> Eq for MrkleTree<T, D, Ix> {}

unsafe impl<T: Send, D: Digest, Ix: IndexType> Send for MrkleTree<T, D, Ix> {}
unsafe impl<T: Sync, D: Digest, Ix: IndexType> Sync for MrkleTree<T, D, Ix> {}

impl<T, D: Digest, Ix: IndexType> core::ops::Index<usize> for MrkleTree<T, D, Ix> {
    type Output = MrkleNode<T, D, Ix>;

    fn index(&self, index: usize) -> &Self::Output {
        &self.core[index]
    }
}

impl<T, D: Digest, Ix: IndexType> core::ops::Index<NodeIndex<Ix>> for MrkleTree<T, D, Ix> {
    type Output = MrkleNode<T, D, Ix>;

    fn index(&self, index: NodeIndex<Ix>) -> &Self::Output {
        &self.core[index.index()]
    }
}

#[cfg(feature = "serde")]
impl<T, D: Digest, Ix: IndexType> serde::Serialize for MrkleTree<T, D, Ix>
where
    T: serde::Serialize,
    Ix: serde::Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.core.serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de, T, D, Ix> serde::Deserialize<'de> for MrkleTree<T, D, Ix>
where
    T: AsRef<[u8]> + serde::Deserialize<'de>,
    D: Digest + Default,
    Ix: IndexType + serde::Deserialize<'de>,
{
    fn deserialize<De>(deserializer: De) -> Result<Self, De::Error>
    where
        De: serde::Deserializer<'de>,
    {
        // First, deserialize the underlying core tree structure
        let core = Tree::<MrkleNode<T, D, Ix>, Ix>::deserialize(deserializer)?;

        // Verify all nodes (leaf and internal) match their expected hashes
        for node in core.iter() {
            let mut digest = D::new();

            if node.is_leaf() {
                let value = node.value().ok_or_else(|| {
                    serde::de::Error::custom("Leaf node missing value during deserialization")
                })?;

                digest.update(value.as_ref());
                let computed = digest.finalize();

                if computed.as_slice() != node.hash().as_slice() {
                    return Err(serde::de::Error::custom("Merkle tree leaf hash mismatch"));
                }
            } else {
                if node.child_count() == 0 {
                    return Err(serde::de::Error::custom(
                        "Internal node should never have no children.",
                    ));
                }

                for child in node.children() {
                    let child_node = core.get(child.index()).ok_or_else(|| {
                        serde::de::Error::custom("Missing child node during deserialization")
                    })?;
                    digest.update(child_node.hash());
                }

                let computed = digest.finalize();
                if &computed != node.hash() {
                    return Err(serde::de::Error::custom(
                        "Merkle tree internal hash mismatch",
                    ));
                }
            }
        }

        Ok(MrkleTree { core })
    }
}

#[cfg(test)]
mod test {

    use crate::{MrkleHasher, MrkleNode, MrkleTree, Node, prelude::*};
    use sha1::Digest;

    const DATA_PAYLOAD: [u8; 32] = [0u8; 32];

    #[test]
    fn test_merkle_tree_default_build() {
        let tree: MrkleTree<[u8; 32], _> = MrkleTree::<[u8; 32], sha1::Sha1>::default();

        assert!(tree.is_empty())
    }

    #[test]
    fn test_default_mrkle_node() {
        let node = MrkleNode::<_, sha1::Sha1, usize>::leaf(DATA_PAYLOAD);
        let expected = sha1::Sha1::digest(DATA_PAYLOAD);
        assert_eq!(node.hash, expected)
    }

    #[test]
    fn test_build_with_mrkle() {
        let hasher = MrkleHasher::<sha1::Sha1>::new();
        let node = MrkleNode::<_, sha1::Sha1, usize>::leaf_with_hasher(DATA_PAYLOAD, &hasher);

        assert_eq!(node.hash, sha1::Sha1::digest(DATA_PAYLOAD))
    }

    #[test]
    fn test_building_binary_tree_base_case() {
        let leaves: Vec<&str> = vec!["A"];
        let tree = MrkleTree::<&str, sha1::Sha1>::from(leaves);
        assert!(tree.len() == 2);
        assert!(tree.leaves().len() == 1);
    }

    #[test]
    fn test_building_binary_tree() {
        let leaves: Vec<&str> = vec!["A", "B", "C", "D", "E"];
        let tree = MrkleTree::<&str, sha1::Sha1>::from(leaves.clone());
        assert_eq!(tree.len(), 11);
        for node in &tree {
            if node.is_leaf() {
                if let Some(value) = node.value() {
                    assert!(leaves.contains(value));
                } else {
                    panic!("Failed Test.")
                }
            }
        }
    }

    #[test]
    #[cfg(feature = "std")]
    fn test_building_binary_tree_display() {
        let leaves: Vec<&str> = vec!["A", "B", "C", "D", "E"];
        let tree = MrkleTree::<&str, sha1::Sha1>::from(leaves.clone());
        println!("{tree}");
    }

    #[test]
    #[allow(clippy::clone_on_copy)]
    fn test_building_binary_tree_proof() {
        let leaves: Vec<&str> = vec!["A", "B", "C", "D", "E"];
        let tree = MrkleTree::<&str, sha1::Sha1>::from(leaves.clone());
        let proof = tree.generate_proof(vec![0.into()]);

        let result = MrkleTree::<&str, sha1::Sha1>::verify(&proof, vec!["A"]);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_mrkle_node_serde() {
        let expected = MrkleNode::<[u8; 32], sha1::Sha1>::leaf(DATA_PAYLOAD);
        let output = bincode::serde::encode_to_vec(&expected, bincode::config::standard()).unwrap();

        let (node, _): (MrkleNode<[u8; 32], sha1::Sha1>, usize) =
            bincode::serde::decode_from_slice(&output[..], bincode::config::standard()).unwrap();

        assert_eq!(node, expected)
    }

    #[test]
    #[allow(clippy::clone_on_copy)]
    #[cfg(feature = "serde")]
    fn test_building_binary_tree_serde() {
        let nodes: Vec<&str> = Vec::from(["a", "b", "c", "d", "e", "f"]);
        let expected = MrkleTree::<String, sha1::Sha1>::from(
            nodes
                .iter()
                .map(|&node| String::from(node))
                .collect::<Vec<String>>(),
        );

        let buffer = bincode::serde::encode_to_vec(&expected, bincode::config::standard()).unwrap();
        let (tree, _): (MrkleTree<String, sha1::Sha1>, usize) =
            bincode::serde::decode_from_slice(&buffer[..], bincode::config::standard()).unwrap();

        assert_eq!(expected, tree);
    }
}
