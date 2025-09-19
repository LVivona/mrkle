use crate::{NodeError, prelude::*};

use crate::{
    DefaultIx, Digest, GenericArray, Hasher, IndexType, MrkleHasher, MrkleNode, MutNode, Node,
    NodeIndex, ProofError, Tree, TreeError, entry,
};

///
#[derive(Debug)]
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
    /// Produced by the [`Hasher`] trait. Leaves are derived from the
    /// Inner data; for internal nodes, it is derived from the
    /// hash of the children.
    hash: Option<GenericArray<D>>,
}

impl<D: Digest, Ix: IndexType> MrkleProofNode<D, Ix> {
    /// Return constructed [`MrkleProofNode`]
    pub(crate) fn new(
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
    pub(crate) fn update(&mut self, hash: Option<GenericArray<D>>) {
        self.hash = hash;
    }

    /// Reset the node to nothing
    #[inline(always)]
    pub(crate) fn reset(&mut self) {
        if self.hash.is_some() {
            self.update(None);
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

    fn children(&self) -> &[NodeIndex<Ix>] {
        &self.children
    }
}

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

impl<D: Digest + Debug, Ix: IndexType> MrkleProof<D, Ix> {
    /// Construct [`MrkleProof`] from pre-constructed [`Tree`]
    /// and the expected public hash from leaves needed to
    /// reconstruct the node.
    pub(crate) fn generate_proof<T>(
        tree: &Tree<MrkleNode<T, D, Ix>, Ix>,
        leaf: NodeIndex<Ix>,
    ) -> Result<Self, ProofError> {
        // NOTE: clean up this slop.

        // Get the leaf node and validate it exists and is a leaf
        let length = tree.len();
        if length < 1 {
            return Err(ProofError::InvalidSize);
        }

        let leaf_node = tree
            .get(leaf.index())
            .ok_or(ProofError::out_of_bounds(length, leaf))?;

        if !leaf_node.is_leaf() {
            return Err(ProofError::ExpectedLeafHash);
        }

        let expected = if let Ok(node) = tree.try_root() {
            node.hash.clone()
        } else {
            return Err(ProofError::from(TreeError::MissingRoot));
        };

        // Collect siblings from leaf to root
        let mut siblings = Vec::new();
        let mut current = leaf;

        while let Some(current_node) = tree.get(current.index()) {
            if let Some(parent_idx) = current_node.parent {
                let parent_node = tree
                    .get(parent_idx.index())
                    .ok_or(ProofError::out_of_bounds(length, parent_idx))?;

                // Find our position among siblings and collect the others
                for &sibling_idx in &parent_node.children {
                    if sibling_idx != current {
                        let sibling = tree
                            .get(sibling_idx.index())
                            .ok_or(ProofError::out_of_bounds(length, sibling_idx))?;

                        siblings.push((sibling.hash.clone(), sibling_idx < current));
                    }
                }
                current = parent_idx;
            } else {
                // We've reached the root
                break;
            }
        }

        // Build the proof tree structure
        let mut proof = Tree::new();

        // Add the leaf node first
        let leaf_proof_node = MrkleProofNode::new(
            None, // Will set parent later
            Vec::new(),
            Some(leaf_node.hash.clone()),
        );
        let leaf_proof_idx = proof.push(leaf_proof_node);

        let mut current_proof_idx = leaf_proof_idx;

        // Build the proof tree from leaf up to root
        for (sibling_hash, is_left_sibling) in &siblings {
            // Create sibling node
            let sibling_proof_node = MrkleProofNode::new(
                None, // Will set parent later
                Vec::new(),
                Some(sibling_hash.clone()),
            );
            let sibling_proof_idx = proof.push(sibling_proof_node);

            // Create parent node
            let mut parent_children = Vec::new();
            if *is_left_sibling {
                parent_children.push(sibling_proof_idx);
                parent_children.push(current_proof_idx);
            } else {
                parent_children.push(current_proof_idx);
                parent_children.push(sibling_proof_idx);
            }

            let parent_proof_node = MrkleProofNode::new(
                None, // Will set parent later (or None if this becomes root)
                parent_children,
                None, // Internal nodes don't need hash in proof
            );
            let parent_proof_idx = proof.push(parent_proof_node);

            // Update parent references
            proof.get_mut(current_proof_idx.index()).unwrap().parent = Some(parent_proof_idx);
            proof.get_mut(sibling_proof_idx.index()).unwrap().parent = Some(parent_proof_idx);

            current_proof_idx = parent_proof_idx;
        }

        // Set the root of the proof tree
        if !siblings.is_empty() {
            proof.root = Some(current_proof_idx);
        } else {
            proof.root = Some(leaf_proof_idx);
        }

        // Create leaves vector with the target leaf
        let leaves = vec![leaf_proof_idx];

        Ok(Self {
            core: proof,
            expected,
            leaves,
            valid: None,
        })
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

    /// Returns leaf [`MrkleProofNode`] within the Tree.
    pub fn leaves(&self) -> Vec<&MrkleProofNode<D, Ix>> {
        self.leaves
            .iter()
            .filter_map(|idx| self.core.get(idx.index()))
            .collect()
    }

    ///
    pub fn get_leaf_mut(&mut self, index: NodeIndex<Ix>) -> Option<&mut MrkleProofNode<D, Ix>> {
        let index = self.leaves.get(index.index());
        if let Some(idx) = index {
            return self.core.get_mut(idx.index());
        } else {
            return None;
        }
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
                node_mut.update(Some(new_hash));

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
