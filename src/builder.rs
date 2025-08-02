use crate::hasher::MrkleHasher;
use crypto::digest::Digest;

/// Strategy for padding leaf nodes when they don't meet the required partition size.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
enum PaddingStrategy {
    /// Pad with copies of the hashed buffer twice.
    ///
    /// This strategy duplicates the hash of the last available leaf node
    /// to fill remaining slots in the partition.
    #[default]
    COPY,

    /// Pad the rest of the buffer with zeros.
    ///
    /// This strategy fills remaining partition slots with zero-valued hashes,
    /// providing a deterministic padding approach.
    ZERO,
}

/// A builder for constructing Merkle trees with configurable hashing and partitioning strategies.
///
/// The `MrkleBuilder` provides a flexible interface for creating Merkle trees with custom
/// hash functions, partition sizes, and padding strategies. It supports both strict and
/// lenient validation modes to accommodate different use cases.
///
/// # Type Parameters
///
/// * `H` - A hasher implementing the `Hasher` trait for computing node hashes.
///
/// # Example
///
/// ```rust
/// use sha2::Sha256;
///
/// let builder = MrkleBuilder::<Sha256>::new()
///     .with_partition_size(4)
///     .with_padding_strategy(PaddingStrategy::ZERO)
///     .with_strict_validation(true);
/// ```
struct MrkleBuilder<D: Digest> {
    /// The hasher instance used for computing node hashes.
    hasher: MrkleHasher<D>,

    /// Optional partition size for grouping leaf nodes.
    ///
    /// When specified, leaf nodes are grouped into partitions of this size.
    /// If `None`, all leaves are processed as a single partition.
    /// This affects the tree structure and can optimize performance for
    /// certain tree traversal patterns.
    partition: Option<usize>,

    /// Strategy for handling insufficient leaf nodes in a partition.
    ///
    /// When the number of leaf nodes doesn't evenly divide into the specified
    /// partition size, this strategy determines how to pad the remaining slots:
    /// - `COPY`: Duplicates the hash of existing nodes
    /// - `ZERO`: Fills with zero-valued hashes
    padding_strategy: PaddingStrategy,

    /// Enable strict validation during tree construction.
    ///
    /// When `true`, the builder performs additional validation checks:
    /// - Ensures all input data is properly formatted
    /// - Validates partition sizes against input constraints
    /// - Performs integrity checks during construction
    ///
    /// When `false`, the builder prioritizes performance over validation,
    /// suitable for trusted input scenarios.
    strict_validation: bool,
}

impl<D: Digest> Default for MrkleBuilder<D> {
    /// Creates a new `MrkleBuilder` with default configuration.
    ///
    /// # Default Values
    ///
    /// - `hasher`: New instance of the specified hasher type
    /// - `partition`: `None` (no partitioning)
    /// - `padding_strategy`: `PaddingStrategy::COPY`
    /// - `strict_validation`: `false`
    fn default() -> Self {
        Self {
            hasher: MrkleHasher::<D>::new(),
            partition: None,
            padding_strategy: PaddingStrategy::COPY,
            strict_validation: false,
        }
    }
}
