#![allow(dead_code)]
#![allow(clippy::needless_return)]
#![allow(clippy::collapsible_if)]
use crate::prelude::*;

use crate::{
    DefaultIx, Digest, GenericArray, Hasher, IndexType, MrkleHasher, MrkleNode, MrkleTree, MutNode,
    Node, NodeError, NodeIndex, ProofError, Tree, entry,
};

/// A node in a Merkle proof path used for cryptographic verification.
///
/// A `MrkleProofNode` represents a single node along the path from a leaf to the root
/// in a Merkle tree during proof verification. It contains the minimal information
/// needed to reconstruct and verify the cryptographic hash chain without requiring
/// the entire tree structure.
///
/// Proof nodes are typically collected during tree traversal and used to verify
/// that a specific piece of data exists in the tree and has not been tampered with.
/// The verification process involves recomputing hashes along the path and comparing
/// the result with the known root hash.
///
/// # Type Parameters
///
/// * `D` - The digest algorithm implementing [`Digest`] trait used for hashing
/// * `Ix` - The index type for node references, must implement [`IndexType`]
///
/// # Fields
///
/// The struct contains three main components:
/// - `parent`: Optional reference to the parent node for path reconstruction
/// - `children`: Vector of child node references for internal nodes
/// - `hash`: Optional cryptographic hash that may be computed during verification
///
/// # Examples
///
/// ```rust
/// use mrkle::{MrkleTree, NodeIndex};
/// use sha2::{Sha256, Digest};
///
/// let leaves: Vec<&str> = vec!["A", "B", "C", "D", "E"];
/// let tree = MrkleTree::<&str, Sha256>::from(leaves);
///
/// // obtain proof for leaf.
/// let mut proof = tree.generate_proof(vec![NodeIndex::new(0)]);
///
/// // Obtain mut referecne to leaf \w in proof.
/// proof.update_leaf_hash(0, Sha256::digest("A")).unwrap();
/// assert!(proof.try_validate_basic().unwrap());
/// ```
///
/// # Security Considerations
///
/// The integrity of proof verification depends on:
/// - The cryptographic strength of the digest algorithm `D`
/// - Proper validation of the hash chain during verification
/// - Ensuring all nodes in the proof path are authentic
///
/// # See Also
///
/// * [`MrkleTree`](crate::MrkleTree) - The main tree structure that generates proof nodes
/// * [`MrkleNode`] - Full nodes containing payload data
/// * [`Digest`] - Trait for cryptographic hash functions
#[derive(Debug, Clone)]
pub struct MrkleProofNode<D: Digest, Ix: IndexType> {
    /// The parents of this node, if any.
    parent: Option<NodeIndex<Ix>>,
    /// The children of this node.
    ///
    /// Dependent on the [`Tree`] if the node contains children.
    /// The [`NodeIndex`] points to a location in [`Tree`]
    /// buffer.
    children: Vec<NodeIndex<Ix>>,
    /// The cryptographic hash of this node's contents
    ///
    /// Produced by the [`Hasher`] trait or `Digest` from RustCrypto library. Leaves are derived from the
    /// Inner data; for internal nodes, it is derived from the
    /// hash of the children.
    hash: Option<GenericArray<D>>,
}

impl<D: Digest, Ix: IndexType> MrkleProofNode<D, Ix> {
    /// Return constructed [`MrkleProofNode`]
    pub fn new(
        parent: Option<NodeIndex<Ix>>,
        children: Vec<NodeIndex<Ix>>,
        hash: Option<GenericArray<D>>,
    ) -> Self {
        Self {
            parent,
            children,
            hash,
        }
    }

    /// Update internal hash with new [`GenericArray`].
    pub fn update(&mut self, hash: GenericArray<D>) {
        self.hash = Some(hash);
    }

    /// Reset the node to nothing
    #[inline(always)]
    pub(crate) fn reset(&mut self) {
        if self.hash.is_some() {
            self.hash = None;
        }
    }

    ///Constructs a new, empty [`MrkleProofNode`] with at least the specified capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            parent: None,
            children: Vec::with_capacity(capacity),
            hash: None,
        }
    }

    /// Return cloned hash of the [`MrkleProofNode`]
    pub fn hash(&self) -> Option<GenericArray<D>> {
        self.hash.clone()
    }
}

impl<D: Digest, Ix: IndexType> MutNode<Ix> for MrkleProofNode<D, Ix> {
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

impl<D: Digest, Ix: IndexType> Node<Ix> for MrkleProofNode<D, Ix> {
    fn parent(&self) -> Option<NodeIndex<Ix>> {
        self.parent
    }

    fn children(&self) -> Vec<NodeIndex<Ix>> {
        self.children.clone()
    }
}

impl<D: Digest, Ix: IndexType> PartialEq for MrkleProofNode<D, Ix> {
    fn eq(&self, other: &Self) -> bool {
        self.hash == other.hash && self.children == other.children && self.parent == other.parent
    }
}
impl<D: Digest, Ix: IndexType> Eq for MrkleProofNode<D, Ix> {}

impl<T, D: Digest, Ix: IndexType> From<MrkleNode<T, D, Ix>> for MrkleProofNode<D, Ix> {
    fn from(value: MrkleNode<T, D, Ix>) -> Self {
        Self {
            parent: value.parent,
            children: value.children,
            hash: Some(value.hash),
        }
    }
}

impl<T, D: Digest, Ix: IndexType> From<&MrkleNode<T, D, Ix>> for MrkleProofNode<D, Ix> {
    fn from(value: &MrkleNode<T, D, Ix>) -> Self {
        Self {
            parent: value.parent,
            children: Vec::with_capacity(0),
            hash: Some(value.hash.clone()),
        }
    }
}

// Display implementation - user-friendly representation
impl<D: Digest, Ix: IndexType> Display for MrkleProofNode<D, Ix> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if let Some(hash) = &self.hash {
            let hash_bytes = hash.as_slice();
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
        } else {
            write!(f, "N/A")
        }
    }
}

#[cfg(feature = "serde")]
impl<D: Digest, Ix: IndexType> serde::Serialize for MrkleProofNode<D, Ix>
where
    Ix: serde::Serialize,
{
    /// Serializes the proof node into the given serializer.
    ///
    /// The node is serialized as a struct with three fields: "parent", "children", and "hash".
    /// The hash field is serialized as a byte array when present.
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;

        let mut state = serializer.serialize_struct("MrkleProofNode", 3)?;

        state.serialize_field("parent", &self.parent)?;
        state.serialize_field("children", &self.children)?;

        // Serialize hash as byte slice if present
        match &self.hash {
            Some(hash) => state.serialize_field("hash", &Some(&hash[..])),
            None => state.serialize_field("hash", &None::<&[u8]>),
        }?;

        state.end()
    }
}

#[cfg(feature = "serde")]
impl<'de, D: Digest, Ix: IndexType> serde::Deserialize<'de> for MrkleProofNode<D, Ix>
where
    Ix: serde::Deserialize<'de>,
{
    /// Deserializes a proof node from the given deserializer.
    ///
    /// Expects a struct format with "parent", "children", and "hash" fields.
    /// The hash field should be a byte array with length matching `D::OutputSize`.
    fn deserialize<_D>(deserializer: _D) -> Result<Self, _D::Error>
    where
        _D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        #[serde(field_identifier, rename_all = "lowercase")]
        enum Field {
            Parent,
            Children,
            Hash,
        }

        struct MrkleProofNodeVisitor<D: Digest, Ix: IndexType> {
            marker: PhantomData<(D, Ix)>,
        }

        impl<'de, D: Digest, Ix: IndexType> serde::de::Visitor<'de> for MrkleProofNodeVisitor<D, Ix>
        where
            Ix: serde::Deserialize<'de>,
        {
            type Value = MrkleProofNode<D, Ix>;

            fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
                formatter.write_str("struct MrkleProofNode")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let parent: Option<NodeIndex<Ix>> = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;

                let children: Vec<NodeIndex<Ix>> = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(1, &self))?;

                let hash_bytes: Option<Vec<u8>> = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(2, &self))?;

                let hash = hash_bytes.map(|bytes| GenericArray::<D>::clone_from_slice(&bytes));

                Ok(MrkleProofNode::new(parent, children, hash))
            }

            fn visit_map<V>(self, mut map: V) -> Result<MrkleProofNode<D, Ix>, V::Error>
            where
                V: serde::de::MapAccess<'de>,
            {
                let mut parent = None;
                let mut children = None;
                let mut hash_bytes: Option<Option<Vec<u8>>> = None;

                while let Some(key) = map.next_key()? {
                    match key {
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

                let parent = parent.ok_or_else(|| serde::de::Error::missing_field("parent"))?;
                let children =
                    children.ok_or_else(|| serde::de::Error::missing_field("children"))?;
                let hash_bytes =
                    hash_bytes.ok_or_else(|| serde::de::Error::missing_field("hash"))?;

                // Convert hash bytes to GenericArray if present
                let hash = hash_bytes.map(|bytes| GenericArray::<D>::clone_from_slice(&bytes));

                Ok(MrkleProofNode {
                    parent,
                    children,
                    hash,
                })
            }
        }

        const FIELDS: &[&str] = &["parent", "children", "hash"];
        deserializer.deserialize_struct(
            "MrkleProofNode",
            FIELDS,
            MrkleProofNodeVisitor {
                marker: PhantomData,
            },
        )
    }
}

/// [`MrkleProof`] is a locked data structure that verifies
/// the inclusion of one or more leaves against the root hash
/// of a Merkle tree.
///
/// # How it works
///
/// A Merkle tree is built by hashing leaves and then
/// recursively hashing pairs of nodes until a single root
/// hash is produced:
///
/// ```text
///            Root = H(AB || CD)
///             /               \
///         H(AB)                H(CD)
///        /    \               /    \
///    H(a)     H(b)        H(c)     H(d)
/// ```
///
/// To prove that `c` is included in the tree:
///
/// - The prover sends the leaf hash `H(c)`
/// - The prover also sends the sibling hashes `H(d)` and `H(AB)`
///
/// The verifier reconstructs the path:
///
/// 1. Compute `H(CD) = H( H(c) || H(d) )`
/// 2. Compute `Root' = H( H(AB) || H(CD) )`
///
/// If `Root'` equals the known root, the proof is valid and
/// `c` is guaranteed to be part of the tree.
///
///
/// For multiple leaves, a [`MrkleProof`] behaves like a
/// *dependency tree*: only the minimal set of sibling hashes
/// needed to recompute the root are included in the proof.
#[derive(Debug, Clone)]
pub struct MrkleProof<D: Digest, Ix: IndexType = DefaultIx> {
    /// Subset of the [`MrkleTree`] that must be constructed
    /// from the leaf hashes within proved to the merkle proof
    /// to find the root hash of the object.
    pub(crate) core: Tree<MrkleProofNode<D, Ix>, Ix>,
    /// Expected root hash that proves that the set of leaves
    /// are within the tree.
    pub(crate) expected: GenericArray<D>,
    /// Leaves needed index needed prove expected root
    pub(crate) leaves: Vec<NodeIndex<Ix>>,
    /// Proof already been validated.
    pub(crate) valid: Option<bool>,
}

impl<D: Digest, Ix: IndexType> MrkleProof<D, Ix> {
    /// Construct unconstructed proof from [`Tree`].
    pub fn new(proof: Tree<MrkleProofNode<D, Ix>, Ix>, expected: GenericArray<D>) -> Self {
        let leaves = proof.find_all(|node| node.hash.is_none() && node.is_leaf());

        assert!(
            !leaves.is_empty(),
            "Proof must contain at least one leaf with missing hash (hash == None). \
             Found {} total nodes but no verifiable leaves.",
            proof.len()
        );

        Self {
            core: proof,
            leaves,
            valid: None,
            expected,
        }
    }

    /// Traverse the node up the tree to the root.
    pub(crate) fn path<T>(
        tree: &MrkleTree<T, D, Ix>,
        leaf: NodeIndex<Ix>,
    ) -> Result<Vec<NodeIndex<Ix>>, ProofError> {
        let length = tree.len();
        let mut current = Some(leaf);
        let mut path = Vec::new();

        while let Some(index) = current {
            let node = tree
                .get(index.index())
                .ok_or(ProofError::out_of_bounds(length, index))?;
            current = node.parent;
            if let Some(parent) = current {
                path.push(parent);
            }
        }
        Ok(path)
    }

    pub(crate) fn lca<T>(
        tree: &MrkleTree<T, D, Ix>,
        leaves: Vec<NodeIndex<Ix>>,
    ) -> Result<HashMap<NodeIndex<Ix>, BTreeSet<usize>>, ProofError> {
        let length = tree.len();
        if length <= 1 {
            return Err(ProofError::InvalidSize);
        }

        if leaves.is_empty() {
            return Ok(HashMap::new());
        }

        // Generate paths to root node for each leaf
        let mut paths: HashMap<NodeIndex<Ix>, Vec<NodeIndex<Ix>>> = HashMap::new();
        for &leaf in &leaves {
            let path = Self::path(tree, leaf)?;
            paths.insert(leaf, path);
        }

        let mut lca_map: HashMap<NodeIndex<Ix>, BTreeSet<usize>> = HashMap::new();

        // For each possible ancestor node, find the minium which leaves have it in their path
        let mut all_ancestors: HashSet<NodeIndex<Ix>> = HashSet::new();
        for path in paths.values() {
            all_ancestors.extend(path);
        }

        // For each ancestor, determine which leaves share it
        for &ancestor in &all_ancestors {
            let mut sharing_leaves = BTreeSet::new();

            for (leaf_idx, &leaf) in leaves.iter().enumerate() {
                if let Some(path) = paths.get(&leaf) {
                    if path.contains(&ancestor) {
                        sharing_leaves.insert(leaf_idx);
                    }
                }
            }

            // Only record ancestors shared by multiple leaves
            if sharing_leaves.len() > 1 {
                lca_map.insert(ancestor, sharing_leaves);
            }
        }

        Ok(lca_map)
    }

    pub(crate) fn siblings<T>(
        tree: &MrkleTree<T, D, Ix>,
        parent: NodeIndex<Ix>,
    ) -> Vec<NodeIndex<Ix>> {
        tree.get(parent.index()).unwrap().children.clone()
    }

    /// Construct [`MrkleProof<D, Ix>`] from pre-constructed [`MrkleTree<T, D, Ix>`]
    /// and the expected public hash from a single leaf needed to
    /// reconstruct the root.
    #[inline]
    pub(crate) fn generate_proof_from_leaf<T>(
        tree: &MrkleTree<T, D, Ix>,
        leaf: NodeIndex<Ix>,
    ) -> Result<Self, ProofError> {
        let length = tree.len();
        if length <= 1 {
            return Err(ProofError::InvalidSize);
        }

        // Validate if node exists and is a leaf within the tree.
        tree.get(leaf.index())
            .filter(|&leaf| leaf.is_leaf())
            .ok_or(ProofError::ExpectedLeafHash)?;

        // Obtain the root/public hash
        let expected = tree.root_hash().clone();

        // Collect siblings from leaf to root
        let mut siblings: Vec<(Option<GenericArray<D>>, bool)> = Vec::new();
        let mut parents = 0;
        let mut current = leaf;

        while let Some(node) = tree.get(current.index()) {
            if let Some(parent_idx) = node.parent() {
                let parent = tree
                    .get(parent_idx.index())
                    .ok_or_else(|| ProofError::out_of_bounds(tree.len(), parent_idx))?;

                if parent.child_count() == 1 {
                    parents += 1;
                } else {
                    for sibling_idx in parent.children() {
                        if sibling_idx != current {
                            let sibling = tree.get(sibling_idx.index()).ok_or_else(|| {
                                ProofError::out_of_bounds(tree.len(), sibling_idx)
                            })?;
                            siblings.push((Some(sibling.hash.clone()), sibling_idx < current));
                        }
                    }
                }

                current = parent_idx;
            } else {
                break; // reached root
            }
        }

        // Build the proof tree structure
        let mut proof = Tree::new();

        // Start with the leaf proof node
        let leaf_idx = proof.push(MrkleProofNode::new(None, Vec::new(), None));
        let mut current = leaf_idx;

        for _ in 0..parents {
            let parent = MrkleProofNode::new(None, vec![current], None);
            let index = proof.push(parent);
            proof.get_mut(current.index()).unwrap().set_parent(index);
            current = index;
        }

        // Add binary parents with siblings
        for (sibling_hash, is_left) in siblings {
            let sibling_idx = proof.push(MrkleProofNode::new(None, Vec::new(), sibling_hash));

            let children = if is_left {
                vec![sibling_idx, current]
            } else {
                vec![current, sibling_idx]
            };

            let parent_idx = proof.push(MrkleProofNode::new(None, children, None));

            proof.get_mut(current.index()).unwrap().parent = Some(parent_idx);
            proof.get_mut(sibling_idx.index()).unwrap().parent = Some(parent_idx);

            current = parent_idx;
        }

        proof.root = Some(current);

        Ok(Self {
            core: proof,
            leaves: vec![leaf_idx],
            valid: None,
            expected,
        })
    }

    /// Generate a [`MrkleProof<D, Ix>`] for one or more leaves in a [`MrkleTree<T, D, Ix>`].
    ///
    /// # Arguments
    ///
    /// * `tree` - Reference to the Merkle tree from which the proof will be built.
    /// * `leaves` - A vector of leaf node indices to generate a proof for.
    ///
    /// # Returns
    ///
    /// Returns a [`MrkleProof<D, Ix>`] containing the proof structure needed to
    /// verify the inclusion of the specified leaves against the tree’s
    /// root hash.
    ///
    /// # Errors
    ///
    /// Returns a [`ProofError`] if:
    /// - The tree is too small to construct a proof.
    /// - A provided index does not exist or is not a valid leaf.
    ///
    /// # Panics
    ///
    /// Panics if `leaves` is empty.
    ///
    /// # Notes
    ///
    /// - Currently only single-leaf proofs are supported.
    /// - Multi-leaf proofs will be implemented in the future.
    ///
    /// # Examples
    ///
    /// ```
    /// use mrkle::{MrkleTree, NodeIndex};
    /// use sha1::Sha1;
    ///
    /// let tree = MrkleTree::<&str, Sha1>::from(vec!["a", "b", "c"]);
    /// let proof = tree.generate_proof(vec![NodeIndex::new(0)]);
    /// ```
    #[inline]
    pub fn generate<T>(
        tree: &MrkleTree<T, D, Ix>,
        leaves: Vec<NodeIndex<Ix>>,
    ) -> Result<MrkleProof<D, Ix>, ProofError> {
        assert!(!leaves.is_empty(), "Leaves where not provided.");

        if leaves.len() == 1 {
            Self::generate_proof_from_leaf(tree, leaves[0])
        } else {
            unimplemented!("generate multi proof...")
        }
    }
}

impl<D: Digest, Ix: IndexType> MrkleProof<D, Ix> {
    /// Returns the expected hash as bytes.
    pub fn expected(&self) -> &[u8] {
        &self.expected
    }

    /// Returns [`entry`] of the expected hashed bytes.
    #[inline(always)]
    pub fn expected_entry(&self) -> &entry {
        entry::from_bytes(&self.expected)
    }

    #[inline]
    /// Returns the number of nodes currently in the tree.
    pub fn len(&self) -> usize {
        self.core.len()
    }

    #[inline]
    /// Returns true if the tree contains no nodes.
    pub fn is_empty(&self) -> bool {
        self.core.is_empty()
    }

    /// Returns leaf [`MrkleProofNode`] within the Tree.
    pub fn leaves(&self) -> Vec<&MrkleProofNode<D, Ix>> {
        self.leaves
            .iter()
            .filter_map(|idx| self.core.get(idx.index()))
            .collect()
    }

    /// Update the hash of the `MrkleProof`.
    pub fn update_leaf_hash(
        &mut self,
        index: usize,
        hash: GenericArray<D>,
    ) -> Result<(), ProofError> {
        let index = self.leaves.get(index);
        if let Some(&idx) = index {
            if let Some(node) = self.core.get_mut(idx.index()) {
                node.update(hash);
            } else {
                return Err(ProofError::out_of_bounds(self.core.len(), idx));
            }
        }
        Ok(())
    }

    /// Returns if the tree has been validated and return if valid.
    pub fn valid(&mut self) -> bool {
        if self.valid.is_none() {
            self.valid = match self.try_validate_basic() {
                Ok(_) => Some(true),
                _ => Some(false),
            };
        }
        self.valid.unwrap()
    }

    /// Refresh the [`MrkleProof`] back to it orginal state.
    pub fn refresh(&mut self) {
        self.valid = None; // set the valid to none.
        let mut q: VecDeque<NodeIndex<Ix>> = self.leaves.clone().into();
        while let Some(idx) = q.pop_front() {
            // Obtain current node from tree.
            let node = self.core.get_mut(idx.index()).unwrap();

            node.reset(); // reset hash to all zeros.
            if let Some(parent) = node.parent {
                q.push_back(parent); // push parent
            }
        }
    }

    /// Breath First Search up the leaves and updating the parent hashes.
    pub fn try_validate_basic(&mut self) -> Result<bool, ProofError> {
        if let Some(valid) = self.valid {
            return Ok(valid);
        }

        let hasher = MrkleHasher::<D>::new();
        let mut q: VecDeque<NodeIndex<Ix>> = self.leaves.clone().into();
        while let Some(idx) = q.pop_front() {
            let node = self.core.get(idx.index()).unwrap();
            if node.is_leaf() {
                if node.hash.is_none() {
                } else {
                    // Leaves are already hashed, just queue their parents
                    if let Some(parent) = node.parent {
                        q.push_back(parent);
                    }
                }
            } else {
                // collect all the data we need (child hashes and parent)
                let mut requeue = false;
                let mut hahses = Vec::new();
                for child in node.children().iter() {
                    if let Some(child_node) = self.core.get(child.index()) {
                        if let Some(computed_hash) = &child_node.hash {
                            hahses.push(computed_hash);
                        } else {
                            requeue = true;
                            break;
                        }
                    }
                }

                // NOTE:
                // Case can exist where a branch has not fully computed all of it's hashes.
                //
                // If that where to exist a simple solution is to push it back into the queue
                // in hopes for the next time around the hashes may be fully computed.
                //
                // Ex:
                //
                // ```text
                //               Root = H(ABCD || EF)
                //              /                    \
                //           H(ABCD)                H(EF)
                //          /       \              /    \
                //     H(ABC)        H(d)       H(e)     H(f)
                //    /      \
                //  H(AB)     H(c)
                // /    \
                // H(a)  H(b)
                // ```
                //
                // Prove H(a) & H(e)
                //
                // 1. H(AB) = H(a) || H(b)
                // 2. H(EF) = H(E) || H(F)
                // 3. H(ABC) = H(AB) || H(C)
                // 4. H(ABCDEF) = H(ABCD) || H(EF) # H(ABCD) is not currently available.
                // 5. H(ABCD) = H(ABC) || H(D)
                // 6. H(ABCDEF) = H(ABCD) || H(EF)
                if requeue {
                    q.push_back(idx);
                    continue;
                }

                let parent = node.parent(); // Get parent before mutable borrow

                // compute the new hash for internal node.
                let new_hash = hasher.concat_slice(&hahses);

                // safely get mutable reference
                let node_mut = self.core.get_mut(idx.index()).unwrap();
                node_mut.update(new_hash);

                // queue parent
                if let Some(parent) = parent {
                    q.push_back(parent);
                }
            }
        }

        if let Some(root) = &self.core.root().hash {
            if root == &self.expected {
                Ok(true)
            } else {
                Err(ProofError::RootHashMissMatch {
                    expected: self.expected.to_vec(), // Also fixed: removed & and ()
                    actual: root.to_vec(),
                })
            }
        } else {
            unreachable!("By the end of traversal up the tree there should always be a root value.")
        }
    }
}

impl<D: Digest, Ix: IndexType> Display for MrkleProof<D, Ix> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.core)
    }
}

impl<D: Digest, Ix: IndexType> PartialEq for MrkleProof<D, Ix> {
    fn eq(&self, other: &Self) -> bool {
        self.core.iter().eq(other.core.iter()) && self.expected == other.expected
    }
}

#[cfg(feature = "serde")]
impl<D: Digest, Ix: IndexType> serde::Serialize for MrkleProof<D, Ix>
where
    D: Clone,
    Ix: serde::Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if self.valid.is_some() {
            return Err(serde::ser::Error::custom(
                "proof node serialization rejected: hash field must be empty for secure transmission",
            ));
        }

        // NOTE: We can reduce our write by just adding the root with the expected hash.
        let mut tree: Tree<MrkleProofNode<D, _>, _> = Tree::with_capacity(self.core.len());
        tree.root = self.core.root;
        tree.nodes.extend_from_slice(&self.core.nodes);
        tree.root_mut().update(self.expected.clone());

        tree.serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de, D: Digest, Ix: IndexType> serde::Deserialize<'de> for MrkleProof<D, Ix>
where
    Ix: serde::Deserialize<'de>,
{
    fn deserialize<_D>(deserializer: _D) -> Result<Self, _D::Error>
    where
        _D: serde::Deserializer<'de>,
    {
        let mut core: Tree<MrkleProofNode<D, Ix>, Ix> = Tree::deserialize(deserializer)?;

        let expected = core
            .root_mut()
            .hash
            .take()
            .ok_or_else(|| serde::de::Error::custom("Missing root hash"))?;

        // Less checking then using the internal `Tree` function leaves
        // in that case we would look O(N) then from a sublist we would be
        // obtaining O(L).
        //
        // Total Time Complexity: O(N + L)
        let mut leaves = Vec::new();
        for index in core.iter_idx() {
            if let Some(node) = core.get(index.index()) {
                if node.is_leaf() && node.hash.is_none() {
                    leaves.push(index);
                }
            } else {
                return Err(serde::de::Error::custom(
                    "Out of bounds could not recover node from data.",
                ));
            }
        }

        Ok(MrkleProof {
            core,
            leaves,
            expected,
            valid: None,
        })
    }
}

#[cfg(test)]
mod test {

    #[allow(unused_imports)]
    use crate::{MrkleProof, MrkleTree, NodeIndex, prelude::*};

    fn build_tree<D: Digest>() -> MrkleTree<String, D> {
        let nodes: Vec<&str> = Vec::from(["a", "b", "c", "d", "e"]);

        let tree: MrkleTree<String, D> = MrkleTree::from(
            nodes
                .iter()
                .map(|&v| String::from(v))
                .collect::<Vec<String>>(),
        );

        tree
    }

    #[test]
    #[cfg(feature = "serde")]
    fn test_serde_mrkle_proof() {
        let tree = build_tree::<sha1::Sha1>();

        let mut proof = tree.generate_proof(vec![NodeIndex::new(4)]);

        proof
            .update_leaf_hash(0, tree.get(4).unwrap().hash)
            .unwrap();

        let buffer = bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();

        let (expected, _): (MrkleProof<sha1::Sha1>, usize) =
            bincode::serde::decode_from_slice(&buffer, bincode::config::standard()).unwrap();

        assert_eq!(expected, proof);

        let valid = proof.try_validate_basic().unwrap();
        assert!(valid);
    }
}
