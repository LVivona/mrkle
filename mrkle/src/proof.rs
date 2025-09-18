use crate::{Hasher, MrkleHasher, prelude::*};

use crate::{
    DefaultIx, Digest, GenericArray, IndexType, MrkleNode, Node, NodeIndex, Tree, TreeError, entry,
    error::ProofError,
};

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
    ///
    /// NOTE: *const u8 filler since we don't use generic trait `T`.
    pub(crate) core: Tree<*const u8, MrkleProofNode<D, Ix>, Ix>,
    /// Expected root hash that proves that the set of leaves
    /// are within the tree.
    pub(crate) expected: GenericArray<D>,
    /// Leaves needed index needed prove expected root
    pub(crate) leaves: Vec<NodeIndex<Ix>>,
    /// Proof already been validated.
    pub(crate) valid: Option<bool>,
}

impl<D: Digest, Ix: IndexType> MrkleProof<D, Ix> {
    /// Construct [`MrkleProof`] from pre-constructed [`Tree`]
    /// and the expected public hash from leaves needed to
    /// reconstruct the node.
    pub(crate) fn generate_proof<T>(
        tree: &Tree<T, MrkleNode<T, D, Ix>, Ix>,
        leaf: NodeIndex<Ix>,
    ) -> Result<Self, ProofError> {
        // Get the leaf node and validate it exists and is a leaf
        let leaf_node = tree.get(leaf.index()).ok_or(TreeError::IndexOutOfBounds {
            index: leaf.index(),
            len: tree.len(),
        })?;

        if !leaf_node.is_leaf() {
            return Err(ProofError::ExpectedLeafHash);
        }

        // // Get the expected root hash
        // let root = tree.try_root()?;
        // let expected = root.hash.clone();

        // // Collection to store the proof path (siblings only)
        // let mut proof_path: Vec<MrkleProofNode<D, Ix>> = Vec::new();
        // let leaves = vec![leaf];

        // // Traverse from leaf to root, collecting sibling hashes
        // let mut current = Some(leaf);

        // while let Some(node_idx) = current {
        //     if let Some(node) = tree.get(node_idx.index()) {
        //         // If this node has a parent, we need to find our sibling
        //         if let Some(parent_idx) = node.parent {
        //             if let Some(parent_node) = tree.get(parent_idx.index()) {
        //                 // Find sibling nodes (all children of parent except current node)
        //                 let siblings: Vec<_> = parent_node
        //                     .children
        //                     .iter()
        //                     .filter(|&&child_idx| child_idx != node_idx)
        //                     .collect();

        //                 // Add sibling hashes to proof
        //                 for &sibling_idx in siblings {
        //                     if let Some(sibling) = tree.get(sibling_idx.index()) {
        //                         proof_path.push(MrkleProofNode::new(
        //                             Some(parent_idx),
        //                             Vec::new(),
        //                             Some(sibling.hash.clone()),
        //                         ));
        //                     }
        //                 }
        //             }
        //             current = node.parent;
        //         } else {
        //             // We've reached the root
        //             break;
        //         }
        //     } else {
        //         return Err(ProofError::from(TreeError::IndexOutOfBounds {
        //             index: node_idx.index(),
        //             len: tree.len(),
        //         }));
        //     }
        // }
        // // Build the core tree with just the proof path
        // let mut core = Tree::new();
        // for (i, proof_node) in proof_path.into_iter().enumerate() {
        //     if proof_node.is_root() {
        //         core.root = Some(NodeIndex::new(i));
        //     }
        //     core.push(proof_node);
        // }

        // Ok(MrkleProof {
        //     core,
        //     expected,
        //     leaves,
        //     valid: None,
        // })
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

    pub fn get_leaf_mut(&mut self, index: NodeIndex<Ix>) -> Option<&mut MrkleProofNode<D, Ix>> {
        self.core.get_mut(index.index())
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

        println!("{:?}", self.core.root);

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
