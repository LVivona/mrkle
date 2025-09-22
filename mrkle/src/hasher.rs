use crypto::digest::{Digest, OutputSizeUser};

/// A fixed-size byte array used as a buffer for cryptographic hash output.
///
/// This is a type alias for [`GenericArray`](crypto::common::generic_array::GenericArray), specialized with
/// `u8` as the element type and the output size determined by the hash function `D`.
///
/// It is widely used across the [`RustCrypto`](https://github.com/RustCrypto) crates
/// (e.g., `sha1`, `sha2`, `sha3`, `blake2`) to represent digest outputs.
///
/// # Type Parameters
/// - `D`: A type that implements [`crypto::common::OutputSizeUser`], providing the
///   associated output size of the digest algorithm.
///
/// # Examples
/// ```
/// use sha2::Sha256;
/// use mrkle::{GenericArray, MrkleHasher, Hasher};
///
/// // A 32-byte buffer for a SHA-256 digest
/// let hasher: MrkleHasher<Sha256> = MrkleHasher::new();
/// let output : GenericArray<Sha256> = hasher.hash(b"hello world");
/// ```
pub type GenericArray<D> = crypto::common::generic_array::GenericArray<
    u8,
    <D as crypto::common::OutputSizeUser>::OutputSize,
>;

/// A trait for cryptographic hashing operations with support for data concatenation.
///
/// This trait provides a unified interface for hashing algorithms commonly used in
/// cryptographic applications such as Merkle trees, hash chains, and digital signatures.
///
/// # Type Parameters
///
/// The trait uses an associated type `Output` that must implement both `AsRef<[u8]>`
/// and `Clone`, ensuring hash outputs can be easily converted to byte slices and
/// efficiently copied when needed.
///
/// # Examples
///
/// ```rust
/// use sha2::Sha256;
/// use mrkle::Hasher;
///
/// let hasher = mrkle::MrkleHasher::<Sha256>::new();
/// let data = b"hello world";
/// let hash = hasher.hash(data);
///
/// // Concatenate two hashes
/// let hash1 = hasher.hash(b"first");
/// let hash2 = hasher.hash(b"second");
/// let combined = hasher.concat(&hash1, &hash2);
/// ```
pub trait Hasher {
    /// The output type of the hash function.
    ///
    /// Must implement `AsRef<[u8]>` for byte slice conversion and `Clone` for
    /// efficient copying of hash values.
    type Output: AsRef<[u8]> + Clone;

    /// Computes the hash of the provided data.
    ///
    /// # Arguments
    ///
    /// * `data` - Input data to be hashed. Accepts any type that can be converted
    ///   to a byte slice reference via `AsRef<[u8]>`.
    ///
    /// # Returns
    ///
    /// Returns the computed hash as `Self::Output`.
    fn hash(&self, data: impl AsRef<[u8]>) -> Self::Output;

    /// Concatenates two hash outputs and returns the hash of the combined result.
    ///
    /// This operation is commonly used in Merkle tree construction where parent
    /// nodes are computed by hashing the concatenation of their children's hashes.
    ///
    /// # Arguments
    ///
    /// * `lhs` - Left-hand side hash value
    /// * `rhs` - Right-hand side hash value
    ///
    /// # Returns
    ///
    /// Returns the hash of the concatenated input hashes.
    fn concat(&self, lhs: impl AsRef<[u8]>, rhs: impl AsRef<[u8]>) -> Self::Output;

    /// Concatenates multiple hash outputs and returns the hash of the combined result.
    ///
    /// This is a convenience method for hashing multiple hash values in sequence,
    /// useful for operations involving more than two hash inputs.
    ///
    /// # Arguments
    ///
    /// * `data` - A slice of hash outputs to be concatenated and hashed
    ///
    /// # Returns
    ///
    /// Returns the hash of all concatenated input hashes.
    fn concat_slice<T: AsRef<[u8]>>(&self, data: &[T]) -> Self::Output;

    /// Certificate Transparency leaf node hashes, a 0x00 byte is prepended to the hash data,
    /// while 0x01 is prepended when computing internal node hashes.
    ///
    /// # Returns
    ///
    /// The certificate appended depedning on if the leaf or parent.
    fn certificate(&self, leaf: bool) -> u8 {
        if leaf { 0x00 } else { 0x01 }
    }
}

/// A generic hasher implementation that wraps cryptographic digest algorithms.
///
/// `MrkleHasher` provides a concrete implementation of the `Hasher` trait using
/// any digest algorithm that implements the `crypto::digest::Digest` trait.
/// This allows for flexible hash algorithm selection while maintaining a
/// consistent interface.
///
/// # Type Parameters
///
/// * `D` - A digest algorithm implementing `crypto::digest::Digest`
///
/// # Examples
///
/// ```rust
/// use sha2::Sha256;
/// use sha3::Sha3_256;
/// use mrkle::{Hasher, MrkleHasher};
///
/// // Create a SHA-256 based hasher
/// let sha256_hasher = MrkleHasher::<Sha256>::new();
///
/// // Create a SHA3-256 based hasher
/// let sha3_hasher = MrkleHasher::<Sha3_256>::new();
///
/// let data = b"example data";
/// let sha256_hash = sha256_hasher.hash(data);
/// let sha3_hash = sha3_hasher.hash(data);
/// ```
pub struct MrkleHasher<D: Digest> {
    /// Phantom data to maintain the generic parameter `D` without storing it.
    /// This allows the struct to be zero-sized while preserving type information.
    phantom: core::marker::PhantomData<D>,
}

impl<D: Digest> Default for MrkleHasher<D> {
    fn default() -> Self {
        Self::new()
    }
}

impl<D: Digest> MrkleHasher<D> {
    /// Creates a new instance of `MrkleHasher`.
    ///
    /// This is a zero-cost constructor that creates a hasher instance
    /// parameterized by the specified digest algorithm.
    ///
    /// # Returns
    ///
    /// Returns a new `MrkleHasher<D>` instance.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use sha2::Sha256;
    ///
    /// let hasher = mrkle::MrkleHasher::<Sha256>::new();
    /// ```
    pub fn new() -> Self {
        MrkleHasher::<D> {
            phantom: core::marker::PhantomData,
        }
    }

    /// Public wrapping over the Digest Trait allowing for single
    /// use.
    ///
    /// ```
    /// use sha1::Sha1;
    ///
    ///
    /// let data = b"hello world";
    /// let output = mrkle::MrkleHasher::<Sha1>::digest(&data);
    /// ```
    pub fn digest<T: AsRef<[u8]>>(
        input: T,
    ) -> crypto::common::generic_array::GenericArray<u8, <D as OutputSizeUser>::OutputSize> {
        D::digest(input)
    }
}

impl<D: Digest> Hasher for MrkleHasher<D> {
    type Output = GenericArray<D>;

    /// Computes the hash using the underlying digest algorithm.
    ///
    /// # Implementation Details
    ///
    /// This method uses the `D::digest` function to compute the hash and
    /// converts the result to a `Vec<u8>` for consistent output handling.
    fn hash(&self, data: impl AsRef<[u8]>) -> Self::Output {
        D::digest(data)
    }

    /// Concatenates two hashes and computes the hash of the result.
    ///
    /// # Implementation Details
    ///
    /// Pre-allocates a vector with the exact capacity needed to avoid
    /// unnecessary reallocations during concatenation, then recursively
    /// calls `hash` on the combined data.
    #[inline]
    fn concat(&self, lhs: impl AsRef<[u8]>, rhs: impl AsRef<[u8]>) -> Self::Output {
        let mut hasher = D::new();
        hasher.update(lhs.as_ref());
        hasher.update(rhs.as_ref());
        hasher.finalize()
    }

    /// Concatenates multiple hashes and computes the hash of the result.
    ///
    /// # Implementation Details
    ///
    /// Uses the `concat` method on the slice to efficiently join all hash
    /// values into a single vector, then computes the hash of the result.
    #[inline]
    fn concat_slice<T: AsRef<[u8]>>(&self, data: &[T]) -> Self::Output {
        let mut hasher = D::new();
        for ptr in data {
            hasher.update(ptr);
        }
        hasher.finalize()
    }
}

#[cfg(test)]
mod test {

    use crate::hasher::Hasher;

    use super::MrkleHasher;
    use crypto::digest::Digest;
    use sha1::Sha1;
    use sha2::Sha256;
    use sha3::Keccak256;

    #[test]
    fn test_sha1_hasher() {
        let hasher = MrkleHasher::<Sha1>::new();
        let output = hasher.hash("hello world");

        let expected = sha1::Sha1::digest("hello world");
        assert_eq!(output, expected)
    }

    #[test]
    fn test_sha2_hasher() {
        let hasher = MrkleHasher::<Sha256>::new();
        let output = hasher.hash("hello world");

        let expected = sha2::Sha256::digest("hello world");
        assert_eq!(output, expected)
    }

    #[test]
    fn test_sha2_hasher_concat() {
        let hasher = MrkleHasher::<Sha256>::new();
        let output = hasher.concat("hello", "world");

        let expected = sha2::Sha256::digest("helloworld");
        assert_eq!(output, expected)
    }

    #[test]
    fn test_sha2_hasher_twice() {
        let hasher = MrkleHasher::<Sha256>::new();
        let output = hasher.hash("hello world");

        let expected = hasher.hash("hello world");
        assert_eq!(output, expected)
    }

    #[test]
    fn test_sha2_hasher_double_twice() {
        let hasher = MrkleHasher::<Sha256>::new();
        let output = hasher.hash(hasher.hash("hello world"));

        let expected = sha2::Sha256::digest(sha2::Sha256::digest("hello world"));
        assert_eq!(output, expected)
    }

    #[test]
    fn test_generate_certificate() {
        let hasher = MrkleHasher::<Sha256>::new();

        assert!(hasher.certificate(true) == 0x00);
        assert!(hasher.certificate(false) == 0x01)
    }

    #[test]
    fn test_sha3_keccak() {
        let plaintext = b"hello world";
        let hasher = MrkleHasher::<Keccak256>::new();
        let output = hasher.hash(plaintext);

        let expected = Keccak256::digest(plaintext);
        assert_eq!(output, expected)
    }

    #[test]
    fn test_sha3_keccak_digest() {
        let plaintext = b"hello world";
        let output = MrkleHasher::<Keccak256>::digest(plaintext);

        let expected = Keccak256::digest(plaintext);
        assert_eq!(output, expected)
    }
}
