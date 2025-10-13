//! Merkle Proofs and Path Verification
//!
//! This module provides types for constructing and verifying cryptographic
//! proofs of inclusion within a [`MrkleTree`].
//!
//! A [`MrkleProof`] represents one or more proof paths from a set of leaves
//! to a known root. Each [`ProofPath`] contains a sequence of [`ProofLevel`]s,
//! where each level defines sibling relationships and positional context used
//! to recompute the parent hash. Together, these allow a verifier to confirm
//! that a set of leaves belongs to a specific Merkle root without access to
//! the entire tree.

use crate::prelude::*;
use crate::{
    Digest, GenericArray, Hasher, IndexType, MrkleHasher, MrkleTree, Node, NodeIndex, ProofError,
    TreeError,
};

/// A cryptographic proof verifying that a set of leaves belong to a specific
/// [`MrkleTree`] root.
///
/// A `MrkleProof` can contain one or more [`ProofPath`]s, each describing
/// the sequence of sibling hashes required to reconstruct the tree’s root
/// from a given leaf.
///
/// # Type Parameters
///
/// * `D` — Digest algorithm used for hashing (e.g., `sha2::Sha256`).
#[derive(Debug, Clone)]
pub struct MrkleProof<D: Digest> {
    /// Expected root hash used for validation.
    expected_root: GenericArray<D>,

    /// Optional set of shared siblings used in multi-proof optimization.
    /// Currently unused in basic proofs.
    siblings: Option<Vec<GenericArray<D>>>,

    /// One or more proof paths from leaves to the expected root.
    paths: Vec<ProofPath<D>>,
}

impl<D: Digest> MrkleProof<D> {
    /// Constructs a new [`MrkleProof`] instance.
    ///
    /// Typically created via [`MrkleProof::generate_basic`].
    pub fn new(
        paths: Vec<ProofPath<D>>,
        siblings: Option<Vec<GenericArray<D>>>,
        expected_root: GenericArray<D>,
    ) -> Self {
        Self {
            paths,
            siblings,
            expected_root,
        }
    }

    /// Generates a basic proof for one or more leaves of a [`MrkleTree`].
    ///
    /// Each leaf index will produce an individual [`ProofPath`].
    /// For now, shared sibling optimization is not applied.
    ///
    /// # Errors
    ///
    /// Returns [`ProofError::InvalidSize`] if no leaves are provided.
    /// Returns [`TreeError::MissingRoot`] if the tree has no root.
    pub fn generate_basic<T, Ix: IndexType>(
        tree: &MrkleTree<T, D, Ix>,
        leaves: &[NodeIndex<Ix>],
    ) -> Result<Self, ProofError> {
        if leaves.is_empty() {
            return Err(ProofError::InvalidSize);
        }

        let root = tree
            .core
            .start()
            .ok_or(ProofError::from(TreeError::MissingRoot))?;

        let expected_root = tree.root_hash().clone();

        let mut paths = Vec::with_capacity(leaves.len());
        for &index in leaves {
            let path = ProofPath::<D>::generate(tree, root, index)?;
            paths.push(path);
        }

        Ok(Self::new(paths, None, expected_root))
    }

    /// Verifies that all leaves in this proof reconstruct the expected root.
    ///
    /// # Arguments
    /// * `leaves` — The leaf hashes (or precomputed digests) to verify.
    ///
    /// # Returns
    /// * `Ok(true)` if all paths reconstruct the expected root.
    /// * `Ok(false)` if any path produces a mismatched root.
    /// * `Err` if the proof is malformed (e.g., incomplete or inconsistent).
    pub fn verify(&self, leaves: Vec<GenericArray<D>>) -> Result<bool, ProofError> {
        if leaves.len() != self.paths.len() {
            return Err(ProofError::IncompleteProof {
                len: leaves.len(),
                expected: self.paths().len(),
            });
        }

        let computed_roots: Vec<GenericArray<D>> = leaves
            .iter()
            .zip(self.paths.iter())
            .map(|(leaf_data, path)| path.traverse(leaf_data.as_slice()))
            .collect();

        for computed_root in &computed_roots {
            if computed_root != &self.expected_root {
                return Ok(false);
            }
        }

        if let Some(_common_siblings) = &self.siblings {
            // Placeholder for future multi-proof verification logic
            todo!("Implement optimized multi-proof verification");
        }

        Ok(true)
    }

    /// Traverses a specific [`ProofPath`] given a leaf hash.
    ///
    /// This function can be used for debugging or manual verification.
    #[inline]
    pub fn traverse_proof(&self, proof: &ProofPath<D>, hash: &[u8]) -> GenericArray<D> {
        proof.traverse(hash)
    }

    /// Returns the expected root hash of this proof.
    pub fn expected_root(&self) -> &GenericArray<D> {
        &self.expected_root
    }

    /// Returns all proof paths contained in this proof.
    pub fn paths(&self) -> &[ProofPath<D>] {
        &self.paths
    }
}

/// A complete path from a leaf to the root within a [`MrkleTree`].
///
/// Each path is composed of one or more [`ProofLevel`]s,
/// where each level defines the position of the current node and
/// its sibling hashes within the same parent node.
#[derive(Debug, Clone)]
pub struct ProofPath<D: Digest> {
    /// Ordered list of levels from leaf → root.
    path: Vec<ProofLevel<D>>,
}

/// A single level in a [`ProofPath`].
///
/// Contains the position of the current node among its siblings and
/// the sibling hashes necessary to reconstruct the parent hash.
#[derive(Debug, Clone)]
pub struct ProofLevel<D: Digest> {
    /// Index of the current node within its parent’s children list.
    position: usize,
    /// Sibling hashes at this level (excluding the current node’s hash).
    siblings: Vec<GenericArray<D>>,
}

impl<D: Digest> ProofLevel<D> {
    /// Creates a new [`ProofLevel`] from position and sibling hashes.
    pub fn new(position: usize, siblings: Vec<GenericArray<D>>) -> Self {
        Self { position, siblings }
    }

    /// Returns the total number of children at this level
    /// (including the proven node itself).
    pub fn arity(&self) -> usize {
        self.siblings.len() + 1
    }
}

impl<D: Digest> ProofPath<D> {
    /// Constructs a new [`ProofPath`] from an ordered list of levels.
    pub fn new(path: Vec<ProofLevel<D>>) -> Self {
        Self { path }
    }

    /// Traverses the proof from a leaf hash upward to compute the root hash.
    ///
    /// At each level, the current hash is combined with sibling hashes
    /// in order of their position, producing a new parent hash.
    pub(crate) fn traverse(&self, hash: &[u8]) -> GenericArray<D> {
        let mut current_hash = GenericArray::<D>::from_slice(hash).clone();
        let hasher = MrkleHasher::<D>::new();

        for level in &self.path {
            let mut children = Vec::with_capacity(level.arity());
            let mut sibling_iter = level.siblings.iter();

            for i in 0..level.arity() {
                if i == level.position {
                    children.push(current_hash.clone());
                } else if let Some(sibling) = sibling_iter.next() {
                    children.push(sibling.clone());
                }
            }

            current_hash = hasher.concat_slice(&children.iter().collect::<Vec<_>>());
        }

        current_hash
    }

    /// Generates a proof path for a given leaf index up to a target root.
    ///
    /// # Errors
    ///
    /// * [`ProofError::InvalidSize`] — If the leaf index is out of range.
    /// * [`ProofError::PathRootMismatch`] — If traversal ends at a node
    ///   that does not correspond to the specified root.
    /// * [`UnexpectedInternalNode`] — Leaf index points to a non leaf node.
    pub(crate) fn generate<T, Ix: IndexType>(
        tree: &MrkleTree<T, D, Ix>,
        root: NodeIndex<Ix>,
        leaf: NodeIndex<Ix>,
    ) -> Result<ProofPath<D>, ProofError> {
        if leaf > tree.len() {
            return Err(ProofError::InvalidSize);
        }

        // NOTE: We can only handle leaves.
        if !tree.get(leaf.index()).unwrap().is_leaf() {
            return Err(ProofError::UnexpectedInternalNode);
        }

        let mut path = Vec::new();
        let mut current_idx = leaf;

        // NOTE: Loop up branch, gathering all siblings required to calculate the root hash
        // If the root index not equal the current_index we must assume
        // that the root is not within the branch and must through an error
        // given the false pretense.
        while let Some(node) = tree.get(current_idx.index()) {
            if current_idx == root {
                break;
            }

            if let Some(parent_idx) = node.parent() {
                let parent = tree.get(parent_idx.index()).ok_or(ProofError::from(
                    TreeError::IndexOutOfBounds {
                        index: parent_idx.index(),
                        len: tree.len(),
                    },
                ))?;

                let children = parent.children();
                let position =
                    children
                        .iter()
                        .position(|&idx| idx == current_idx)
                        .ok_or(ProofError::from(TreeError::IndexOutOfBounds {
                            index: current_idx.index(),
                            len: tree.len(),
                        }))?;

                let mut siblings = Vec::with_capacity(children.len() - 1);
                for (i, &child_idx) in children.iter().enumerate() {
                    if i != position {
                        let sibling = tree.get(child_idx.index()).ok_or(ProofError::from(
                            TreeError::IndexOutOfBounds {
                                index: child_idx.index(),
                                len: tree.len(),
                            },
                        ))?;
                        siblings.push(sibling.hash.clone());
                    }
                }

                path.push(ProofLevel::new(position, siblings));
                current_idx = parent_idx;
            } else {
                break;
            }
        }

        if current_idx != root {
            return Err(ProofError::PathRootMismatch(
                root.index(),
                current_idx.index(),
            ));
        }

        Ok(ProofPath::new(path))
    }
}

#[cfg(feature = "serde")]
impl<D: Digest> serde::Serialize for ProofLevel<D> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("ProofLevel", 2)?;
        state.serialize_field("position", &self.position)?;
        state.serialize_field(
            "siblings",
            &self
                .siblings
                .iter()
                .map(|o| o.as_slice())
                .collect::<Vec<&[u8]>>(),
        )?;
        state.end()
    }
}

#[cfg(feature = "serde")]
impl<'de, D: Digest> serde::Deserialize<'de> for ProofLevel<D> {
    fn deserialize<_D>(deserializer: _D) -> Result<Self, _D::Error>
    where
        _D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        #[serde(field_identifier, rename_all = "lowercase")]
        enum Field {
            Position,
            Siblings,
        }

        struct ProofLevelVisitor<D: Digest> {
            marker: core::marker::PhantomData<D>,
        }

        impl<'de, D: Digest> serde::de::Visitor<'de> for ProofLevelVisitor<D> {
            type Value = ProofLevel<D>;

            fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
                formatter.write_str("struct ProofLevel")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let position: usize = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;

                let siblings_bytes: Vec<Vec<u8>> = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(1, &self))?;

                let siblings: Vec<GenericArray<D>> = siblings_bytes
                    .into_iter()
                    .map(|bytes| GenericArray::<D>::clone_from_slice(&bytes))
                    .collect();

                Ok(ProofLevel { position, siblings })
            }

            fn visit_map<V>(self, mut map: V) -> Result<ProofLevel<D>, V::Error>
            where
                V: serde::de::MapAccess<'de>,
            {
                let mut position = None;
                let mut siblings_bytes: Option<Vec<Vec<u8>>> = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Position => {
                            if position.is_some() {
                                return Err(serde::de::Error::duplicate_field("pos"));
                            }
                            position = Some(map.next_value()?);
                        }
                        Field::Siblings => {
                            if siblings_bytes.is_some() {
                                return Err(serde::de::Error::duplicate_field("siblings"));
                            }
                            siblings_bytes = Some(map.next_value()?);
                        }
                    }
                }

                let position = position.ok_or_else(|| serde::de::Error::missing_field("pos"))?;
                let siblings_bytes =
                    siblings_bytes.ok_or_else(|| serde::de::Error::missing_field("siblings"))?;

                let siblings: Vec<GenericArray<D>> = siblings_bytes
                    .into_iter()
                    .map(|bytes| GenericArray::<D>::clone_from_slice(&bytes))
                    .collect();

                Ok(ProofLevel { position, siblings })
            }
        }

        const FIELDS: &[&str] = &["position", "siblings"];
        deserializer.deserialize_struct(
            "ProofLevel",
            FIELDS,
            ProofLevelVisitor {
                marker: core::marker::PhantomData,
            },
        )
    }
}

#[cfg(feature = "serde")]
impl<D: Digest> serde::Serialize for ProofPath<D> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;

        let mut state = serializer.serialize_struct("Proof", 1)?;
        state.serialize_field("path", &self.path)?;

        state.end()
    }
}

#[cfg(feature = "serde")]
impl<'de, D: Digest> serde::Deserialize<'de> for ProofPath<D> {
    fn deserialize<_D>(deserializer: _D) -> Result<Self, _D::Error>
    where
        _D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        #[serde(field_identifier, rename_all = "lowercase")]
        enum Field {
            Path,
        }

        struct ProofLevelVisitor<D: Digest> {
            marker: core::marker::PhantomData<D>,
        }

        impl<'de, D: Digest> serde::de::Visitor<'de> for ProofLevelVisitor<D> {
            type Value = ProofPath<D>;

            fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
                formatter.write_str("struct ProofPath")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let path: Vec<ProofLevel<D>> = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;

                Ok(ProofPath::<D>::new(path))
            }

            fn visit_map<V>(self, mut map: V) -> Result<ProofPath<D>, V::Error>
            where
                V: serde::de::MapAccess<'de>,
            {
                let mut path: Vec<ProofLevel<D>> = Vec::new();

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Path => {
                            path = map.next_value()?;
                        }
                    }
                }

                Ok(ProofPath::new(path))
            }
        }

        const FIELDS: &[&str] = &["path"];
        deserializer.deserialize_struct(
            "ProofPath",
            FIELDS,
            ProofLevelVisitor {
                marker: core::marker::PhantomData,
            },
        )
    }
}

#[cfg(test)]
mod test {

    use super::*;
    use crate::GenericArray;

    #[test]
    #[cfg(feature = "std")]
    fn test_single_mrkle_proof() {
        let tree = MrkleTree::<&str, sha1::Sha1>::from_leaves(vec!["a", "b", "c"]).unwrap();

        let root = tree.core.start().unwrap();
        let proof = ProofPath::generate(&tree, root, 2.into()).unwrap();

        let leaf_hash = tree
            .get(tree.leaf_indices()[2].index())
            .unwrap()
            .hash
            .as_slice();
        let computed_root = proof.traverse(leaf_hash);

        println!(
            "Computed root: {}",
            faster_hex::hex_string(computed_root.as_slice())
        );
        println!(
            "Expected root: {}",
            faster_hex::hex_string(tree.root_hash().as_slice())
        );

        assert_eq!(computed_root, *tree.root_hash());
    }

    #[test]
    fn test_proof_for_all_leaves() {
        let tree = MrkleTree::<&str, sha1::Sha1>::from_leaves(vec!["a", "b", "c", "d"]).unwrap();
        let root = tree.core.start().unwrap();
        let leaf_indices = tree.leaf_indices();

        // Verify proof for each leaf
        for (i, &leaf_idx) in leaf_indices.iter().enumerate() {
            let proof = ProofPath::<sha1::Sha1>::generate(&tree, root, (i as u32).into()).unwrap();
            let leaf_hash = tree.get(leaf_idx.index()).unwrap().hash.as_slice();
            let computed_root = proof.traverse(leaf_hash);

            assert_eq!(
                computed_root,
                *tree.root_hash(),
                "Proof failed for leaf index {}",
                i
            );
        }
    }

    #[test]
    fn test_proof_with_single_leaf() {
        let tree = MrkleTree::<&str, sha1::Sha1>::from_leaves(vec!["single"]).unwrap();
        let root = tree.core.start().unwrap();

        let proof = ProofPath::<sha1::Sha1>::generate(&tree, root, 0.into()).unwrap();
        let leaf_hash = tree
            .get(tree.leaf_indices()[0].index())
            .unwrap()
            .hash
            .as_slice();
        let computed_root = proof.traverse(leaf_hash);

        assert_eq!(computed_root, *tree.root_hash());
    }

    #[test]
    fn test_proof_with_larger_tree() {
        let leaves: Vec<&str> = vec!["a", "b", "c", "d", "e", "f", "g", "h"];
        let tree = MrkleTree::<&str, sha1::Sha1>::from_leaves(leaves).unwrap();
        let root = tree.core.start().unwrap();
        let leaf_indices = tree.leaf_indices();

        // Test a few specific leaves
        for &idx in &[0, 3, 7] {
            let proof = ProofPath::generate(&tree, root, idx.into()).unwrap();
            let leaf_hash = tree
                .get(leaf_indices[idx as usize].index())
                .unwrap()
                .hash
                .as_slice();
            let computed_root = proof.traverse(leaf_hash);

            assert_eq!(
                computed_root,
                *tree.root_hash(),
                "Proof failed for leaf index {}",
                idx
            );
        }
    }

    #[test]
    fn test_proof_invalid_leaf_index() {
        let tree = MrkleTree::<&str, sha1::Sha1>::from_leaves(vec!["a", "b", "c"]).unwrap();
        let root = tree.core.start().unwrap();

        // Try to generate proof for non-existent leaf
        let result = ProofPath::generate(&tree, root, 10.into());
        assert!(result.is_err());
    }

    #[test]
    fn test_proof_with_wrong_data() {
        let tree = MrkleTree::<&str, sha1::Sha1>::from_leaves(vec!["a", "b", "c"]).unwrap();
        let root = tree.core.start().unwrap();

        let proof = ProofPath::generate(&tree, root, 0.into()).unwrap();

        // Create a different tree and get a leaf hash from it
        let wrong_tree = MrkleTree::<&str, sha1::Sha1>::from_leaves(vec!["x", "y", "z"]).unwrap();
        let wrong_leaf_hash = wrong_tree
            .get(wrong_tree.leaf_indices()[0].index())
            .unwrap()
            .hash
            .as_slice();

        let computed_root = proof.traverse(wrong_leaf_hash);

        // The computed root should NOT match the original tree's root
        assert_ne!(computed_root, *tree.root_hash());
    }

    #[test]
    fn test_multi_proof_generation() {
        let tree = MrkleTree::<&str, sha1::Sha1>::from_leaves(vec!["a", "b", "c", "d"]).unwrap();
        let leaf_indices = vec![0.into(), 2.into()];

        let multi_proof = MrkleProof::generate_basic(&tree, &leaf_indices).unwrap();

        assert_eq!(multi_proof.paths.len(), 2);
        assert_eq!(multi_proof.expected_root, *tree.root_hash());
    }

    #[test]
    fn test_multi_proof_verify() {
        let tree = MrkleTree::<&str, sha1::Sha1>::from_leaves(vec!["a", "b", "c", "d"]).unwrap();
        let leaf_indices_to_prove = vec![0.into(), 2.into()];

        let multi_proof = MrkleProof::generate_basic(&tree, &leaf_indices_to_prove).unwrap();

        // Get the actual leaf data
        let leaves_data = leaf_indices_to_prove
            .iter()
            .map(|&idx: &NodeIndex<_>| {
                let leaf_idx = tree.leaf_indices()[idx.index()];
                let node = tree.get(leaf_idx.index()).unwrap();
                *node.hash()
            })
            .collect::<Vec<GenericArray<sha1::Sha1>>>();

        let result = multi_proof.verify(leaves_data);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_multi_proof_verify_wrong_leaf_count() {
        let tree = MrkleTree::<&str, sha1::Sha1>::from_leaves(vec!["a", "b", "c", "d"]).unwrap();
        let leaf_indices = vec![0.into(), 2.into()];

        let multi_proof = MrkleProof::generate_basic(&tree, &leaf_indices).unwrap();

        // Provide wrong number of leaves
        let wrong_leaves = vec![GenericArray::<sha1::Sha1>::clone_from_slice(&[0u8; 20][..])]; // Only 1 leaf instead of 2

        let result = multi_proof.verify(wrong_leaves);
        assert!(result.is_err());
    }

    #[test]
    fn test_multi_proof_verify_wrong_data() {
        let tree = MrkleTree::<&str, sha1::Sha1>::from_leaves(vec!["a", "b", "c", "d"]).unwrap();
        let leaf_indices = vec![0.into(), 2.into()];

        let multi_proof = MrkleProof::generate_basic(&tree, &leaf_indices).unwrap();

        // Provide wrong leaf data
        let wrong_leaves = vec![
            GenericArray::<sha1::Sha1>::clone_from_slice(&[0u8; 20][..]),
            GenericArray::<sha1::Sha1>::clone_from_slice(&[1u8; 20][..]),
        ];

        let result = multi_proof.verify(wrong_leaves);
        assert!(result.is_ok());
        assert!(!result.unwrap()); // Should return false, not error
    }

    #[test]
    fn test_multi_proof_empty_leaves() {
        let tree = MrkleTree::<&str, sha1::Sha1>::from_leaves(vec!["a", "b", "c"]).unwrap();
        let empty_indices: Vec<NodeIndex<u32>> = vec![];

        let result = MrkleProof::<sha1::Sha1>::generate_basic(&tree, &empty_indices);
        assert!(result.is_err());
    }

    #[test]
    fn test_proof_path_structure() {
        let tree = MrkleTree::<&str, sha1::Sha1>::from_leaves(vec!["a", "b", "c", "d"]).unwrap();
        let root = tree.core.start().unwrap();

        let proof = ProofPath::generate(&tree, root, 0.into()).unwrap();

        // Check that the path has the expected number of levels
        // For a tree with 4 leaves, we expect at least 2 levels (leaf->parent, parent->root)
        assert!(!proof.path.is_empty());

        // Check that each level has valid siblings
        for (i, level) in proof.path.iter().enumerate() {
            assert!(
                level.position < level.arity(),
                "Position {} should be less than arity {} at level {}",
                level.position,
                level.arity(),
                i
            );
            assert!(
                !level.siblings.is_empty(),
                "Level {} should have at least one sibling",
                i
            );
        }
    }

    #[test]
    fn test_proof_deterministic() {
        let tree = MrkleTree::<&str, sha1::Sha1>::from_leaves(vec!["a", "b", "c"]).unwrap();
        let root = tree.core.start().unwrap();

        // Generate the same proof twice
        let proof1 = ProofPath::<sha1::Sha1>::generate(&tree, root, 1.into()).unwrap();
        let proof2 = ProofPath::<sha1::Sha1>::generate(&tree, root, 1.into()).unwrap();

        // Both proofs should produce the same result
        let leaf_hash = tree
            .get(tree.leaf_indices()[1].index())
            .unwrap()
            .hash
            .as_slice();
        let root1: GenericArray<sha1::Sha1> = proof1.traverse(leaf_hash);
        let root2: GenericArray<sha1::Sha1> = proof2.traverse(leaf_hash);

        assert_eq!(root1, root2);
        assert_eq!(root1, *tree.root_hash());
    }

    #[test]
    fn test_traverse_proof_helper() {
        let tree = MrkleTree::<&str, sha1::Sha1>::from_leaves(vec!["a", "b", "c"]).unwrap();
        let leaf_indices = vec![0.into()];

        let multi_proof = MrkleProof::generate_basic(&tree, &leaf_indices).unwrap();
        let leaf_hash = tree
            .get(tree.leaf_indices()[0].index())
            .unwrap()
            .hash
            .as_slice();

        let computed_root = multi_proof.traverse_proof(&multi_proof.paths[0], leaf_hash);

        assert_eq!(computed_root, *tree.root_hash());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_proof_serialization() {
        let tree = MrkleTree::<&str, sha1::Sha1>::from_leaves(vec!["a", "b", "c"]).unwrap();
        let root = tree.core.start().unwrap();

        let proof = ProofPath::generate(&tree, root, 1.into()).unwrap();

        // Serialize
        let serialized = serde_json::to_string(&proof).unwrap();

        // Deserialize
        let deserialized: ProofPath<sha1::Sha1> = serde_json::from_str(&serialized).unwrap();

        // Verify deserialized proof works
        let leaf_hash = tree
            .get(tree.leaf_indices()[1].index())
            .unwrap()
            .hash
            .as_slice();
        let computed_root = deserialized.traverse(leaf_hash);

        assert_eq!(computed_root, *tree.root_hash());
    }
}
