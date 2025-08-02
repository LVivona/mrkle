use crate::entry::entry;
use crate::MrkleTree;

/// Defines the traversal order for a Merkle tree.
///
/// This trait allows different traversal strategies to be implemented
/// for iterating through Merkle tree nodes in various orders.
pub trait OrderTraversal: Copy {
    /// Returns a slice of entries in the specified traversal order.
    ///
    /// # Arguments
    /// * `root` - The root of the Merkle tree to traverse
    ///
    /// # Returns
    /// A slice containing references to entries in the traversal order
    fn as_slice<'a, T>(&self, root: &'a MrkleTree) -> &'a [T]
    where
        T: Into<&'a entry>;
}

/// Post-order traversal strategy for Merkle trees.
///
/// In post-order traversal, children are visited before their parents.
#[derive(Debug, Clone, Copy)]
pub struct PostOrder;

/// Breadth-first traversal strategy for Merkle trees.
///
/// In breadth-first traversal, nodes are visited level by level.
#[derive(Debug, Clone, Copy)]
pub struct BreadthOrder;

/// An iterator for traversing Merkle tree entries in a specified order.
///
/// This structure provides an ordered traversal of Merkle tree entries,
/// enabling iteration-based proofs to verify tree equality and integrity.
///
/// # Tree Structure Example
///
/// ```text
///         A
///       /   \
///      B     C
///    /   \    \
///   D     E    F
/// ```
///
/// ## Traversal Orders
///
/// - **Post Order**: `[D, E, B, F, C, A]`
/// - **Reverse Pre-order**: `[A, C, F, B, E, D]`
/// - **Reverse Post Order**: `[F, C, D, E, B, A]`
/// - **Breadth First**: `[A, B, C, D, E, F]`
///
/// # Examples
///
/// ```rust ignore
/// # use mrkle::{Orderedentry, entry};
/// let entries = vec![/* your entries */];
/// let mut ordered_iter = Orderedentry::new(&entries);
///
/// for entry in ordered_iter {
///     println!("Processing entry: {}", entry);
/// }
///
/// // Reset iterator to start from beginning
/// ordered_iter.reset();
/// ```
#[derive(Debug)]
pub struct Orderedentry<'a> {
    /// Current position in the iteration
    index: usize,
    /// Reference to the ordered entries
    entries: &'a [&'a entry],
}

impl<'a> Orderedentry<'a> {
    /// Creates a new ordered entry iterator.
    ///
    /// # Arguments
    /// * `entries` - A slice of entry references in the desired traversal order
    ///
    /// # Returns
    /// A new `Orderedentry` instance positioned at the beginning
    ///
    /// # Examples
    ///
    /// ```rust ignore
    /// # use mrkle::{Orderedentry, entry};
    /// let entries = vec![/* your entries */];
    /// let ordered_iter = Orderedentry::new(&entries);
    /// ```
    pub fn new(entries: &'a [&'a entry]) -> Self {
        Self { index: 0, entries }
    }

    /// Resets the iterator to the beginning of the traversal.
    ///
    /// After calling this method, the next call to `next()` will return
    /// the first entry in the traversal order.
    ///
    /// # Examples
    ///
    /// ```rust ignore
    /// # use mrkle::{Orderedentry, entry};
    /// let entries = vec![/* your entries */];
    /// let mut ordered_iter = Orderedentry::new(&entries);
    ///
    /// // Iterate through some entries...
    /// let _ = ordered_iter.next();
    /// let _ = ordered_iter.next();
    ///
    /// // Reset to start over
    /// ordered_iter.reset();
    /// assert_eq!(ordered_iter.current_position(), 0);
    /// ```
    pub fn reset(&mut self) {
        self.index = 0;
    }

    /// Returns the current position in the iteration.
    ///
    /// # Returns
    /// The zero-based index of the current position
    pub fn current_position(&self) -> usize {
        self.index
    }

    /// Returns the total number of entries in this ordered traversal.
    ///
    /// # Returns
    /// The total count of entries
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if the traversal contains no entries.
    ///
    /// # Returns
    /// `true` if empty, `false` otherwise
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns the remaining number of entries to iterate over.
    ///
    /// # Returns
    /// The number of entries remaining in the iteration
    pub fn remaining(&self) -> usize {
        self.entries.len().saturating_sub(self.index)
    }
}

impl<'a> Iterator for Orderedentry<'a> {
    type Item = &'a entry;

    /// Advances the iterator and returns the next entry.
    ///
    /// # Returns
    /// `Some(&entry)` if there are more entries, `None` when exhausted
    fn next(&mut self) -> Option<Self::Item> {
        if self.index < self.entries.len() {
            let entry = self.entries[self.index];
            self.index += 1;
            Some(entry)
        } else {
            None
        }
    }

    /// Returns the number of iterations remaining.
    ///
    /// # Returns
    /// A tuple containing the lower and upper bounds of remaining iterations
    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.remaining();
        (remaining, Some(remaining))
    }
}

impl<'a> ExactSizeIterator for Orderedentry<'a> {
    /// Returns the exact number of iterations remaining.
    fn len(&self) -> usize {
        self.remaining()
    }
}

impl<'a> PartialEq for Orderedentry<'a> {
    /// Compares two `Orderedentry` instances for equality.
    ///
    /// Two instances are considered equal if they contain the same entries
    /// in the same order, regardless of their current iteration position.
    ///
    /// # Arguments
    /// * `other` - The other `Orderedentry` to compare with
    ///
    /// # Returns
    /// `true` if both instances contain equivalent entries in the same order
    fn eq(&self, other: &Self) -> bool {
        self.entries.len() == other.entries.len()
            && self
                .entries
                .iter()
                .zip(other.entries.iter())
                .all(|(left, right)| left == right)
    }
}

impl<'a> Eq for Orderedentry<'a> {}

impl<'a> std::fmt::Display for Orderedentry<'a> {
    /// Formats the ordered entries for display.
    ///
    /// # Arguments
    /// * `f` - The formatter to write to
    ///
    /// # Returns
    /// A `fmt::Result` indicating success or failure
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Orderedentry [{} entries]: ", self.entries.len())?;
        for (i, entry) in self.entries.iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            write!(f, "{}", entry.to_hex())?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::Orderedentry;
    use crate::entry::entry;
    use sha1::Sha1;
    use sha2::{Digest, Sha256};

    /// Creates a test Merkle tree using SHA-1 hashing.
    ///
    /// # Returns
    /// A vector containing the serialized tree data
    fn create_sha1_test_tree() -> Vec<u8> {
        let hash1 = Sha1::digest(b"hello");
        let hash2 = Sha1::digest(b"world");
        let (left_entry, right_entry) = (entry::from_bytes(&hash1), entry::from_bytes(&hash2));

        let mut combined_buffer = [0u8; 40];
        combined_buffer[..20].copy_from_slice(left_entry.as_bytes());
        combined_buffer[20..].copy_from_slice(right_entry.as_bytes());

        let parent_hash = Sha1::digest(combined_buffer);
        let tree_entries = [entry::from_bytes(&parent_hash), left_entry, right_entry];

        let mut serialized_tree = Vec::with_capacity(60);
        for entry in &tree_entries {
            serialized_tree.extend_from_slice(entry.as_bytes());
        }

        serialized_tree
    }

    /// Creates a test Merkle tree using SHA-256 hashing.
    ///
    /// # Returns
    /// A vector containing the serialized tree data
    fn create_sha256_test_tree() -> Vec<u8> {
        let hash1 = Sha256::digest(b"hello");
        let hash2 = Sha256::digest(b"world");
        let (left_entry, right_entry) = (entry::from_bytes(&hash1), entry::from_bytes(&hash2));

        let mut combined_buffer = [0u8; 64];
        combined_buffer[..32].copy_from_slice(left_entry.as_bytes());
        combined_buffer[32..].copy_from_slice(right_entry.as_bytes());

        let parent_hash = Sha256::digest(combined_buffer);
        let tree_entries = [entry::from_bytes(&parent_hash), left_entry, right_entry];

        let mut serialized_tree = Vec::with_capacity(96);
        for entry in &tree_entries {
            serialized_tree.extend_from_slice(entry.as_bytes());
        }

        serialized_tree
    }

    #[test]
    fn test_sha1_tree_equivalence() {
        const HASH_SIZE: usize = 20;
        let tree_data = create_sha1_test_tree();

        let entries: Vec<&entry> = tree_data
            .chunks_exact(HASH_SIZE)
            .map(entry::from_bytes)
            .collect();

        let ordered_entries = Orderedentry::new(&entries);

        for (index, entry) in ordered_entries.enumerate() {
            let expected_start = index * HASH_SIZE;
            let expected_end = expected_start + HASH_SIZE;

            assert_eq!(
                &tree_data[expected_start..expected_end],
                entry.as_bytes(),
                "entry at index {} does not match expected bytes",
                index
            );
        }
    }

    #[test]
    fn test_sha256_tree_equivalence() {
        const HASH_SIZE: usize = 32;
        let tree_data = create_sha256_test_tree();

        let entries: Vec<&entry> = tree_data
            .chunks_exact(HASH_SIZE)
            .map(entry::from_bytes)
            .collect();

        let ordered_entries = Orderedentry::new(&entries);

        for (index, entry) in ordered_entries.enumerate() {
            let expected_start = index * HASH_SIZE;
            let expected_end = expected_start + HASH_SIZE;

            assert_eq!(
                &tree_data[expected_start..expected_end],
                entry.as_bytes(),
                "entry at index {} does not match expected bytes",
                index
            );
        }
    }

    #[test]
    fn test_iterator_reset_functionality() {
        const HASH_SIZE: usize = 20;
        let tree_data = create_sha1_test_tree();

        let entries: Vec<&entry> = tree_data
            .chunks_exact(HASH_SIZE)
            .map(entry::from_bytes)
            .collect();

        let mut ordered_entries = Orderedentry::new(&entries);

        // Consume some entries
        let first_entry = ordered_entries.next().unwrap();
        let second_entry = ordered_entries.next().unwrap();

        assert_eq!(ordered_entries.current_position(), 2);
        assert_eq!(ordered_entries.remaining(), 1);

        // Reset and verify we're back at the beginning
        ordered_entries.reset();
        assert_eq!(ordered_entries.current_position(), 0);
        assert_eq!(ordered_entries.remaining(), 3);

        // Verify the first entry is the same as before
        assert_eq!(ordered_entries.next().unwrap(), first_entry);
    }

    #[test]
    fn test_iterator_properties() {
        const HASH_SIZE: usize = 20;
        let tree_data = create_sha1_test_tree();

        let entries: Vec<&entry> = tree_data
            .chunks_exact(HASH_SIZE)
            .map(entry::from_bytes)
            .collect();

        let ordered_entries = Orderedentry::new(&entries);

        assert_eq!(ordered_entries.len(), 3);
        assert!(!ordered_entries.is_empty());
        assert_eq!(ordered_entries.size_hint(), (3, Some(3)));
    }

    #[test]
    fn test_equality_comparison() {
        const HASH_SIZE: usize = 20;
        let tree_data = create_sha1_test_tree();

        let entries: Vec<&entry> = tree_data
            .chunks_exact(HASH_SIZE)
            .map(entry::from_bytes)
            .collect();

        let ordered_entries1 = Orderedentry::new(&entries);
        let ordered_entries2 = Orderedentry::new(&entries);

        assert_eq!(ordered_entries1, ordered_entries2);
    }

    #[test]
    fn test_display_formatting() {
        const HASH_SIZE: usize = 20;
        let tree_data = create_sha1_test_tree();

        let entries: Vec<&entry> = tree_data
            .chunks_exact(HASH_SIZE)
            .map(entry::from_bytes)
            .collect();

        let ordered_entries = Orderedentry::new(&entries);
        let display_string = format!("{}", ordered_entries);

        assert!(display_string.contains("Orderedentry [3 entries]"));
    }
}
