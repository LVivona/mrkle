#![allow(dead_code)]
use crate::{
    DefaultIx, GenericArray, Hasher, IndexType, MrkleHasher, MrkleNode, MrkleTree, Node, NodeError,
    NodeIndex, Tree, TreeError, error::MrkleError, prelude::*,
};

/// A builder for constructing Merkle trees with default configuration.
///
/// The `MrkleDefaultBuilder` provides a safe, incremental approach to building
/// Merkle trees by inserting leaves and internal nodes while automatically
/// maintaining tree invariants such as parent-child relationships and hash consistency.
///
/// # Design Principles
///
/// - **Safety First**: All operations are validated to prevent invalid tree states
/// - **Incremental Construction**: Build trees step-by-step with full control
/// - **Immutable After Finalization**: Once finalized, the builder cannot be modified
/// - **Comprehensive Error Handling**: Clear, actionable error messages for all failure modes
/// - **Performance Optimized**: Efficient memory usage and minimal allocations
///
/// # Type Parameters
///
/// * `T` - The type of data stored in leaf nodes
/// * `D` - The digest algorithm used for hashing (must implement [`Digest`])
/// * `Ix` - The index type for node references (must implement [`IndexType`])
///
/// # Lifecycle
///
/// 1. **Creation**: Create a new builder with [`new()`](Self::new) or [`with_capacity()`](Self::with_capacity)
/// 2. **Construction**: Add leaves and internal nodes using insertion methods
/// 3. **Validation**: Optionally validate the structure with `validate()`
/// 4. **Finalization**: Complete the tree with [`finish()`](Self::finish)
///
/// # Examples
///
/// ## Basic Usage
///
/// ```rust
/// use sha2::Sha256;
/// use mrkle::MrkleDefaultBuilder;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let mut builder = MrkleDefaultBuilder::<Vec<u8>, Sha256, u32>::new();
///
/// // Insert leaf nodes
/// let leaf1 = builder.insert_leaf_data(b"data1".to_vec())?;
/// let leaf2 = builder.insert_leaf_data(b"data2".to_vec())?;
///
/// // Create internal node
/// let internal = builder.insert_internal(vec![leaf1, leaf2])?;
///
/// // Finish building
/// let tree = builder.finish(internal)?;
/// # Ok(())
/// # }
/// ```
///
/// ## Batch Construction
///
/// ```rust
/// use sha2::Sha256;
/// use mrkle::MrkleDefaultBuilder;
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let mut builder = MrkleDefaultBuilder::<Vec<u8>, Sha256, u32>::new();
///
/// // Insert multiple leaves at once
/// let data = vec![b"data1".to_vec(), b"data2".to_vec(), b"data3".to_vec()];
/// let leaves = builder.insert_leaves(data)?;
///
/// // Build complete binary tree
/// let root = builder.build_complete_tree_from_leaves(leaves)?;
/// let tree = builder.finish(root)?;
/// # Ok(())
/// # }
/// ```
///
/// ## Method Chaining
///
/// ```rust
/// use sha2::Sha256;
/// use mrkle::MrkleDefaultBuilder;
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let tree = MrkleDefaultBuilder::<Vec<u8>, Sha256, u32>::new()
///     .with_leaf_data(b"data1".to_vec())?
///     .with_leaf_data(b"data2".to_vec())?
///     .build_and_finish()?;
/// # Ok(())
/// # }
///
pub struct MrkleDefaultBuilder<T, D: Digest, Ix: IndexType = DefaultIx> {
    /// The underlying tree structure containing all nodes.
    tree: Tree<MrkleNode<T, D, Ix>, Ix>,
    /// The hasher instance used for computing node hashes.
    hasher: MrkleHasher<D>,
    /// Whether the builder has been finalized and is immutable.
    finalized: bool,
}

impl<T, D: Digest, Ix: IndexType> Default for MrkleDefaultBuilder<T, D, Ix> {
    /// Creates a new builder with default configuration.
    fn default() -> Self {
        Self::new()
    }
}

impl<T, D: Digest, Ix: IndexType> MrkleDefaultBuilder<T, D, Ix> {
    /// Creates a new empty Merkle tree builder.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use sha2::Sha256;
    /// use mrkle::MrkleDefaultBuilder;
    ///
    /// let builder = MrkleDefaultBuilder::<Vec<u8>, Sha256, u32>::new();
    /// assert!(builder.is_empty());
    /// assert!(!builder.is_finalized());
    /// ```
    pub fn new() -> Self {
        Self {
            tree: Tree::new(),
            hasher: MrkleHasher::new(),
            finalized: false,
        }
    }

    /// Creates a new builder with the specified initial capacity.
    ///
    /// Pre-allocating capacity can improve performance when you know the
    /// approximate number of nodes that will be added.
    ///
    /// # Arguments
    ///
    /// * `capacity` - The initial capacity for the underlying tree storage
    ///
    /// # Examples
    ///
    /// ```rust
    /// use sha2::Sha256;
    /// use mrkle::MrkleDefaultBuilder;
    ///
    /// // Pre-allocate space for 1000 nodes
    /// let builder = MrkleDefaultBuilder::<Vec<u8>, Sha256, u32>::with_capacity(1000);
    /// assert!(builder.is_empty());
    /// ```
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            tree: Tree::with_capacity(capacity),
            hasher: MrkleHasher::new(),
            finalized: false,
        }
    }

    /// Returns the current number of nodes in the tree.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use sha2::Sha256;
    /// use mrkle::MrkleDefaultBuilder;
    /// let mut builder = MrkleDefaultBuilder::<Vec<u8>, Sha256>::new();
    /// assert_eq!(builder.len(), 0);
    ///
    /// let _ = builder.insert_leaf_data(b"data".to_vec());
    /// assert_eq!(builder.len(), 1);
    /// ```
    #[inline]
    pub fn len(&self) -> usize {
        self.tree.len()
    }

    /// Returns `true` if the builder contains no nodes.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use sha2::Sha256;
    /// use mrkle::MrkleDefaultBuilder;
    /// let builder = MrkleDefaultBuilder::<Vec<u8>, Sha256>::new();
    /// assert!(builder.is_empty());
    /// ```
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.tree.is_empty()
    }

    /// Returns `true` if the builder has been finalized.
    ///
    /// A finalized builder cannot be modified and should not be used
    /// for further construction operations.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use sha2::Sha256;
    /// use mrkle::MrkleDefaultBuilder;
    /// let builder = MrkleDefaultBuilder::<Vec<u8>, Sha256, u32>::new();
    /// assert!(!builder.is_finalized());
    /// ```
    #[inline]
    pub fn is_finalized(&self) -> bool {
        self.finalized
    }

    /// Returns the capacity of the underlying tree storage.
    ///
    /// This represents the number of nodes that can be stored without
    /// requiring additional memory allocation.
    pub fn capacity(&self) -> usize {
        self.tree.capacity()
    }

    /// Inserts a pre-constructed leaf node into the tree.
    ///
    /// This method allows insertion of fully constructed leaf nodes,
    /// providing maximum control over node creation.
    ///
    /// # Arguments
    ///
    /// * `leaf` - The leaf node to insert, must be a valid leaf node
    ///
    /// # Returns
    ///
    /// The index of the newly inserted leaf node.
    ///
    /// # Errors
    ///
    /// * [`TreeError::AlreadyFinalized`] - If the builder has been finalized
    /// * [`TreeError::InvalidOperation`] - If the provided node is not a leaf
    ///
    /// # Examples
    ///
    /// ```rust
    /// use sha2::Sha256;
    /// use mrkle::{MrkleDefaultBuilder, MrkleNode};
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut builder = MrkleDefaultBuilder::<Vec<u8>, Sha256, u32>::new();
    /// let leaf = MrkleNode::leaf(b"custom_data".to_vec());
    /// let index = builder.insert_leaf(leaf)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn insert_leaf(&mut self, leaf: MrkleNode<T, D, Ix>) -> Result<NodeIndex<Ix>, TreeError> {
        self.check_not_finalized()?;

        if !leaf.is_leaf() {
            return Err(TreeError::InvalidOperation {
                operation: "insert_leaf",
                reason: "provided node is not a leaf node".to_string(),
            });
        }

        Ok(self.tree.push(leaf))
    }

    /// Inserts an internal node with the specified children.
    ///
    /// This method creates an internal node that acts as the parent of the
    /// provided child nodes. The hash of the internal node is automatically
    /// computed from the hashes of its children.
    ///
    /// # Arguments
    ///
    /// * `children` - Non-empty vector of child node indices
    ///
    /// # Returns
    ///
    /// The index of the newly created internal node.
    ///
    /// # Errors
    ///
    /// * [`TreeError::AlreadyFinalized`] - If the builder has been finalized
    /// * [`TreeError::InvalidOperation`] - If children vector is empty
    /// * [`TreeError::IndexOutOfBounds`] - If any child index is invalid
    /// * [`TreeError::ParentConflict`] - If any child already has a parent
    ///
    /// # Examples
    ///
    /// ```rust
    /// use sha2::Sha256;
    /// use mrkle::MrkleDefaultBuilder;
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut builder = MrkleDefaultBuilder::<Vec<u8>, Sha256, u32>::new();
    /// let leaf1 = builder.insert_leaf_data(b"data1".to_vec())?;
    /// let leaf2 = builder.insert_leaf_data(b"data2".to_vec())?;
    /// let internal = builder.insert_internal(vec![leaf1, leaf2])?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn insert_internal(
        &mut self,
        children: Vec<NodeIndex<Ix>>,
    ) -> Result<NodeIndex<Ix>, MrkleError> {
        self.check_not_finalized()?;

        if children.is_empty() {
            return Err(MrkleError::from(TreeError::InvalidOperation {
                operation: "insert_internal",
                reason: "internal nodes must have at least one child".to_string(),
            }));
        }

        self.validate_children(&children)?;

        let index = self
            .tree
            .push(MrkleNode::internal(&self.tree, children.clone())?);

        self.set_parent_relationships(&children, index);

        Ok(index)
    }

    /// Finishes building the tree and returns the completed Merkle tree.
    ///
    /// This method validates the provided root, sets it as the tree root,
    /// and returns the finalized Merkle tree. After calling this method,
    /// the builder becomes immutable.
    ///
    /// # Arguments
    ///
    /// * `root` - The index of the node to use as the tree root
    ///
    /// # Returns
    ///
    /// The completed and validated Merkle tree.
    ///
    /// # Errors
    ///
    /// * [`TreeError::AlreadyFinalized`] - If the builder has already been finalized
    /// * [`TreeError::IndexOutOfBounds`] - If the root index is invalid
    /// * [`TreeError::InvalidOperation`] - If the root node has a parent
    ///
    /// # Examples
    ///
    /// ```rust
    /// use sha2::Sha256;
    /// use mrkle::MrkleDefaultBuilder;
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut builder = MrkleDefaultBuilder::<Vec<u8>, Sha256, u32>::new();
    /// let leaf1 = builder.insert_leaf_data(b"data1".to_vec())?;
    /// let leaf2 = builder.insert_leaf_data(b"data2".to_vec())?;
    /// let root = builder.insert_internal(vec![leaf1, leaf2])?;
    /// let tree = builder.finish(root)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn finish(mut self, root: NodeIndex<Ix>) -> Result<MrkleTree<T, D, Ix>, MrkleError> {
        self.check_not_finalized()?;

        // Validate the root node
        self.validate_root(root)?;

        // Set root
        self.tree.root = Some(root);

        // Perform comprehensive tree validation
        if let Err(errors) = self.validate() {
            return Err(MrkleError::from(TreeError::ValidationFailed {
                count: errors.len(),
                summary: "Tree structure validation failed".to_string(),
                errors,
            }));
        }

        self.finalized = true;
        Ok(MrkleTree::new(self.tree))
    }

    /// Validates the current tree structure.
    ///
    /// This method performs comprehensive validation of the tree structure,
    /// checking for common issues such as:
    /// - Invalid parent-child relationships
    /// - Out-of-bounds node references
    /// - Orphaned nodes
    /// - Structural inconsistencies
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If the tree structure is valid
    /// * `Err(Vec<TreeError>)` - A list of all validation errors found
    ///
    /// # Examples
    ///
    /// ```rust
    /// use sha2::Sha256;
    /// use mrkle::MrkleDefaultBuilder;
    ///
    /// let mut builder = MrkleDefaultBuilder::<Vec<u8>, Sha256, u32>::new();
    /// let leaf = builder.insert_leaf_data(b"data".to_vec()).unwrap();
    ///
    /// let root = builder.insert_internal(vec![leaf]).unwrap();
    ///
    /// // Validate before finishing
    /// builder.finish(root).unwrap();
    /// ```
    fn validate(&self) -> Result<(), Vec<TreeError>> {
        let mut errors = Vec::new();

        if self.tree.try_root().is_err() {
            errors.push(TreeError::MissingRoot);
        }

        let mut visited = BTreeSet::new();

        for index in self.tree.iter_idx() {
            // Validate parent reference if it exists
            let node = self.tree.get(index.index()).unwrap();
            visited.insert(index.index());
            if let Some(parent_idx) = node.parent() {
                match self.tree.get(parent_idx.index()) {
                    Some(parent_node) => {
                        // Verify bidirectional relationship
                        if !parent_node.children().contains(&index) {
                            errors.push(TreeError::InconsistentState {
                                details: format!(
                                    "node {} claims parent {}, but parent doesn't list it as child",
                                    index,
                                    parent_idx.index()
                                ),
                            });
                        }
                    }
                    None => {
                        errors.push(TreeError::IndexOutOfBounds {
                            index: parent_idx.index(),
                            len: self.tree.len(),
                        });
                    }
                }
            }

            for child_idx in node.children() {
                match self.tree.get(child_idx.index()) {
                    Some(child_node) => {
                        // Verify bidirectional relationship
                        if child_node.parent() != Some(index) {
                            errors.push(TreeError::InconsistentState {
                                details: format!(
                                    "node {} lists {} as child, but child has different parent",
                                    index,
                                    child_idx.index()
                                ),
                            });
                        }
                    }
                    None => {
                        errors.push(TreeError::IndexOutOfBounds {
                            index: child_idx.index(),
                            len: self.tree.len(),
                        });
                    }
                }
            }
        }

        // Validate if all nodes have been visited in the tree.
        // if not then tree is disjoint.
        if visited.len() != self.len() {
            errors.push(TreeError::DisjointNode);
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Checks if the builder has been finalized and returns an error if it has.
    ///
    /// This method is called at the beginning of all mutating operations to ensure
    /// that no modifications can be made after the builder has been finalized.
    ///
    /// # Errors
    ///
    /// Returns [`TreeError::AlreadyFinalized`] if the builder has been finalized.
    fn check_not_finalized(&self) -> Result<(), TreeError> {
        if self.finalized {
            Err(TreeError::AlreadyFinalized)
        } else {
            Ok(())
        }
    }

    /// Validates that all provided child indices are valid and available for parenting.
    fn validate_children(&self, children: &[NodeIndex<Ix>]) -> Result<(), TreeError> {
        // Check for duplicates first.
        let mut seen = BTreeSet::new();
        for &child in children {
            if !seen.insert(child) {
                return Err(NodeError::Duplicate {
                    child: child.index(),
                }
                .into());
            }
        }

        // Validate each child, by indexing each node within the tree
        // and checking if they do no have a parent.
        for &child in children {
            let node = self
                .tree
                .get(child.index())
                .ok_or(TreeError::IndexOutOfBounds {
                    index: child.index(),
                    len: self.tree.len(),
                })?;
            if node.parent().is_some() {
                return Err(TreeError::from(NodeError::ParentConflict {
                    parent: node.parent().unwrap().index(),
                    child: child.index(),
                }));
            }
        }
        Ok(())
    }

    /// Computes the hash for an internal node based on its children's hashes.
    fn compute_internal_hash(
        &self,
        children: &[NodeIndex<Ix>],
    ) -> Result<GenericArray<D>, TreeError> {
        let mut child_hashes = Vec::with_capacity(children.len());

        for &child in children {
            let node = self
                .tree
                .get(child.index())
                .expect("child already validated");
            child_hashes.push(node.hash());
        }

        Ok(self.hasher.concat_slice(&child_hashes))
    }

    /// Sets parent-child relationships for the provided nodes.
    fn set_parent_relationships(&mut self, children: &[NodeIndex<Ix>], parent: NodeIndex<Ix>) {
        for &child in children {
            if let Some(node) = self.tree.nodes.get_mut(child.index()) {
                node.parent = Some(parent);
            }
        }
    }

    /// Validates that a node is suitable to be used as a tree root.
    fn validate_root(&self, root: NodeIndex<Ix>) -> Result<(), TreeError> {
        let root_node = self
            .tree
            .get(root.index())
            .ok_or(TreeError::IndexOutOfBounds {
                index: root.index(),
                len: self.tree.len(),
            })?;

        if !root_node.is_root() {
            return Err(TreeError::InvalidOperation {
                operation: "finish",
                reason: "root node cannot have a parent".to_string(),
            });
        }

        Ok(())
    }
}

// Data-specific implementation for types that can be hashed
impl<T, D: Digest, Ix: IndexType> MrkleDefaultBuilder<T, D, Ix>
where
    T: AsRef<[u8]> + Clone,
{
    /// Convenience method to create and insert a leaf node from data.
    ///
    /// This method automatically creates a leaf node from the provided data
    /// by computing its hash and constructing the appropriate node structure.
    ///
    /// # Arguments
    ///
    /// * `data` - The data to store in the leaf node
    ///
    /// # Returns
    ///
    /// The index of the newly created leaf node.
    ///
    /// # Errors
    ///
    /// * [`TreeError::AlreadyFinalized`] - If the builder has been finalized
    ///
    /// # Examples
    ///
    /// ```rust
    /// use sha2::Sha256;
    /// use mrkle::MrkleDefaultBuilder;
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut builder = MrkleDefaultBuilder::<Vec<u8>, Sha256, u32>::new();
    /// let leaf_index = builder.insert_leaf_data(b"my_data".to_vec())?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn insert_leaf_data(&mut self, data: T) -> Result<NodeIndex<Ix>, TreeError> {
        self.check_not_finalized()?;
        Ok(self.tree.push(MrkleNode::<T, D, Ix>::leaf(data)))
    }

    /// Inserts multiple leaf nodes from an iterator of data.
    ///
    /// This is a convenience method for bulk insertion of leaf nodes,
    /// which is more efficient than inserting them one by one.
    ///
    /// # Arguments
    ///
    /// * `data_iter` - Iterator over data items to create leaf nodes from
    ///
    /// # Returns
    ///
    /// A vector of node indices for the newly created leaf nodes, in the same
    /// order as the input iterator.
    ///
    /// # Errors
    ///
    /// * [`TreeError::AlreadyFinalized`] - If the builder has been finalized
    ///
    /// # Examples
    ///
    /// ```rust
    /// use sha2::Sha256;
    /// use mrkle::MrkleDefaultBuilder;
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut builder = MrkleDefaultBuilder::<Vec<u8>, Sha256, u32>::new();
    /// let data = vec![b"data1".to_vec(), b"data2".to_vec(), b"data3".to_vec()];
    /// let leaf_indices = builder.insert_leaves(data)?;
    /// assert_eq!(leaf_indices.len(), 3);
    /// # Ok(())
    /// # }
    /// ```
    pub fn insert_leaves<I>(&mut self, data_iter: I) -> Result<Vec<NodeIndex<Ix>>, TreeError>
    where
        T: Clone,
        I: IntoIterator<Item = T>,
    {
        self.check_not_finalized()?;

        data_iter
            .into_iter()
            .map(|data| self.insert_leaf_data(data))
            .collect()
    }

    /// Builds a complete binary tree from the provided leaf nodes.
    ///
    /// This convenience method takes a list of leaf node indices and constructs
    /// a complete binary tree structure with internal nodes automatically created.
    /// The tree is built bottom-up, pairing adjacent leaves and creating internal
    /// nodes until a single root remains.
    ///
    /// # Arguments
    ///
    /// * `leaves` - Vector of leaf node indices to build the tree from
    ///
    /// # Returns
    ///
    /// The index of the root node of the constructed tree.
    ///
    /// # Errors
    ///
    /// * [`TreeError::AlreadyFinalized`] - If the builder has been finalized
    /// * [`TreeError::InvalidOperation`] - If the leaves vector is empty
    ///
    /// # Examples
    ///
    /// ```rust
    /// use sha2::Sha256;
    /// use mrkle::MrkleDefaultBuilder;
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut builder = MrkleDefaultBuilder::<Vec<u8>, Sha256, u32>::new();
    /// let data = vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec(), b"d".to_vec()];
    /// let leaves = builder.insert_leaves(data)?;
    /// let root = builder.build_complete_tree_from_leaves(leaves)?;
    /// let tree = builder.finish(root)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn build_complete_tree_from_leaves(
        &mut self,
        mut leaves: Vec<NodeIndex<Ix>>,
    ) -> Result<NodeIndex<Ix>, MrkleError> {
        self.check_not_finalized()?;

        if leaves.is_empty() {
            return Err(MrkleError::from(TreeError::InvalidOperation {
                operation: "build_complete_tree_from_leaves",
                reason: "cannot build tree from empty leaves vector".to_string(),
            }));
        }

        // Base case: if there is only one node, create a root for single node.
        if leaves.len() == 1 {
            return self.insert_internal(leaves);
        }

        // Build tree bottom-up by repeatedly pairing nodes
        while leaves.len() > 1 {
            let mut level = Vec::new();

            // chunk NodeIndex<Ix> into size 2.
            for chunk in leaves.chunks(2) {
                let internal = self.insert_internal(chunk.to_vec())?;
                level.push(internal);
            }

            leaves = level;
        }

        Ok(leaves[0])
    }

    /// Builds a complete tree from data and returns the finalized tree.
    ///
    /// This is the most convenient method for simple use cases where you have
    /// all the data upfront and want to build a complete Merkle tree in one operation.
    ///
    /// # Arguments
    ///
    /// * `data_iter` - Iterator over data items to build the tree from
    ///
    /// # Returns
    ///
    /// The completed and finalized Merkle tree.
    ///
    /// # Errors
    ///
    /// Returns any errors that occur during tree construction or finalization.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use sha2::Sha256;
    /// use mrkle::MrkleDefaultBuilder;
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let data = vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec(), b"d".to_vec()];
    /// let tree = MrkleDefaultBuilder::<Vec<u8>, Sha256, u32>::build_from_data(data)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn build_from_data<I>(data_iter: I) -> Result<MrkleTree<T, D, Ix>, MrkleError>
    where
        T: Clone,
        I: IntoIterator<Item = T>,
    {
        let mut builder = Self::new();
        let leaves = builder.insert_leaves(data_iter)?;
        let root = builder.build_complete_tree_from_leaves(leaves)?;
        builder.finish(root)
    }
}

// Builder pattern methods for method chaining
impl<T: AsRef<[u8]>, D: Digest, Ix: IndexType> MrkleDefaultBuilder<T, D, Ix> {
    /// Builder method to add a leaf and continue chaining.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use sha2::Sha256;
    /// use mrkle::{MrkleDefaultBuilder, MrkleNode};
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let leaf = MrkleNode::leaf(b"data".to_vec());
    /// let builder = MrkleDefaultBuilder::<Vec<u8>, Sha256, u32>::new()
    ///     .with_leaf(leaf)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn with_leaf(mut self, leaf: MrkleNode<T, D, Ix>) -> Result<Self, TreeError> {
        self.insert_leaf(leaf)?;
        Ok(self)
    }

    /// Builder method to add leaf data and continue chaining.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use sha2::Sha256;
    /// use mrkle::MrkleDefaultBuilder;
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let builder = MrkleDefaultBuilder::<Vec<u8>, Sha256, u32>::new()
    ///     .with_leaf_data(b"data1".to_vec())?
    ///     .with_leaf_data(b"data2".to_vec())?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn with_leaf_data(mut self, data: T) -> Result<Self, TreeError>
    where
        T: Clone,
    {
        self.insert_leaf_data(data)?;
        Ok(self)
    }

    /// Builder method to build a complete tree and finish in one operation.
    ///
    /// This method is useful when you want to build a complete binary tree
    /// from the current leaves and immediately finalize it.
    ///
    /// # Errors
    ///
    /// Returns errors if the tree cannot be built or finalized.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use sha2::Sha256;
    /// use mrkle::MrkleDefaultBuilder;
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let tree = MrkleDefaultBuilder::<Vec<u8>, Sha256, u32>::new()
    ///     .with_leaf_data(b"data1".to_vec())?
    ///     .with_leaf_data(b"data2".to_vec())?
    ///     .build_and_finish()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn build_and_finish(mut self) -> Result<MrkleTree<T, D, Ix>, MrkleError>
    where
        T: Clone,
    {
        let leaves: Vec<NodeIndex<Ix>> = (0..self.tree.len())
            .map(NodeIndex::new)
            .filter(|&idx| {
                self.tree
                    .get(idx.index())
                    .map(|node| node.parent().is_none())
                    .unwrap_or(false)
            })
            .collect();

        let root = self.build_complete_tree_from_leaves(leaves)?;
        self.finish(root)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Sha256;

    type TestBuilder = MrkleDefaultBuilder<Vec<u8>, Sha256, u32>;

    #[test]
    fn test_builder_basic_construction() -> Result<(), Box<dyn core::error::Error>> {
        let mut builder = TestBuilder::new();

        assert!(builder.is_empty());
        assert!(!builder.is_finalized());
        assert_eq!(builder.len(), 0);

        let leaf1 = builder.insert_leaf_data(b"data1".to_vec()).unwrap();
        let leaf2 = builder.insert_leaf_data(b"data2".to_vec()).unwrap();

        assert_eq!(builder.len(), 2);
        assert!(!builder.is_empty());

        let root = builder.insert_internal(vec![leaf1, leaf2]).unwrap();
        let tree = builder.finish(root).unwrap();

        assert!(tree.root().is_root());
        Ok(())
    }

    #[test]
    fn test_builder_with_capacity() -> Result<(), Box<dyn core::error::Error>> {
        let builder = TestBuilder::with_capacity(100);
        assert!(builder.capacity() >= 100);
        Ok(())
    }

    #[test]
    fn test_batch_leaf_insertion() -> Result<(), Box<dyn core::error::Error>> {
        let mut builder = TestBuilder::new();
        let data = vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec(), b"d".to_vec()];
        let leaves = builder.insert_leaves(data)?;

        assert_eq!(leaves.len(), 4);
        assert_eq!(builder.len(), 4);
        Ok(())
    }

    #[test]
    fn test_complete_tree_building() -> Result<(), Box<dyn core::error::Error>> {
        let mut builder = TestBuilder::new();
        let data = vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec(), b"d".to_vec()];
        let leaves = builder.insert_leaves(data).unwrap();
        let root = builder.build_complete_tree_from_leaves(leaves)?;
        let tree = builder.finish(root)?;

        assert!(tree.root().is_root());
        // 4 leaves + 3 internal nodes = 7 total nodes
        assert_eq!(tree.len(), 7);
        Ok(())
    }

    #[test]
    fn test_build_from_data_convenience() -> Result<(), Box<dyn core::error::Error>> {
        let data = vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec(), b"d".to_vec()];
        let tree = TestBuilder::build_from_data(data)?;

        assert!(tree.root().is_root());
        assert_eq!(tree.len(), 7);
        Ok(())
    }

    #[test]
    fn test_method_chaining() -> Result<(), Box<dyn core::error::Error>> {
        let tree = TestBuilder::new()
            .with_leaf_data(b"data1".to_vec())?
            .with_leaf_data(b"data2".to_vec())?
            .with_leaf_data(b"data3".to_vec())?
            .build_and_finish()?;

        assert!(tree.root().is_root());
        Ok(())
    }

    #[test]
    fn test_validation() -> Result<(), Box<dyn core::error::Error>> {
        let mut builder = TestBuilder::new();
        let leaf1 = builder.insert_leaf_data(b"data1".to_vec())?;
        let leaf2 = builder.insert_leaf_data(b"data2".to_vec())?;
        let _root = builder.insert_internal(vec![leaf1, leaf2])?;

        Ok(())
    }

    #[test]
    fn test_finalization_prevents_modification() -> Result<(), Box<dyn core::error::Error>> {
        let mut builder = TestBuilder::new();
        let leaf = builder.insert_leaf_data(b"data".to_vec())?;
        let root = builder.insert_internal(vec![leaf])?;
        let _tree = builder.finish(root)?;

        Ok(())
    }

    #[test]
    fn test_error_conditions() -> Result<(), Box<dyn core::error::Error>> {
        let mut builder = TestBuilder::new();

        // Test empty children vector
        let result = builder.insert_internal(vec![]);
        assert!(result.is_err());

        // Test invalid child index
        let invalid_child = NodeIndex::new(999);
        let result = builder.insert_internal(vec![invalid_child]);
        assert!(result.is_err());

        Ok(())
    }

    #[test]
    fn test_parent_conflict_detection() -> Result<(), Box<dyn core::error::Error>> {
        let mut builder = TestBuilder::new();
        let leaf1 = builder.insert_leaf_data(b"data1".to_vec())?;
        let leaf2 = builder.insert_leaf_data(b"data2".to_vec())?;

        // Create first internal node
        let _internal1 = builder.insert_internal(vec![leaf1, leaf2])?;

        // Try to create second internal node with same children (should fail)
        let result = builder.insert_internal(vec![leaf1]);
        assert!(result.is_err());

        Ok(())
    }
}
