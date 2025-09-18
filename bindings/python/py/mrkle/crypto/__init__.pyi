from typing import Union

class HASH:
    """
    A cryptographic hash object.

    This class provides a unified interface for various hash algorithms
    implemented in Rust for high performance.
    """

    def __new__(cls, kind: str) -> None:
        """
        Initialize a new hasher with the specified algorithm.

        Parameters
        ----------
        kind : str
            The hash algorithm to use. Supported algorithms include:
            'sha1', 'sha224', 'sha256', 'sha384', 'sha512',
            'keccak224', 'keccak256', 'keccak384', 'keccak512',
            'blake2b512', 'blake2s256'

        Raises
        ------
        ValueError
            If the specified hash algorithm is not supported.
        """
        ...

    def update(self, data: Union[bytes, bytearray, memoryview]) -> None:
        """
        Update the hash with the given data.

        Parameters
        ----------
        data : bytes, bytearray, or memoryview
            The data to add to the hash.

        Note
        ----
        This method can be called multiple times to incrementally hash data.
        """
        ...

    def digest(self) -> bytes:
        """
        Return the digest of the data as bytes.

        Returns
        -------
        bytes
            The hash digest as bytes.

        Note
        ----
        This method returns a copy of the digest and can be called multiple times.
        The hasher state is preserved and can continue to be updated.
        """
        ...

    def hexdigest(self) -> str:
        """
        Return the digest of the data as a hexadecimal string.

        Returns
        -------
        str
            The hash digest as a lowercase hexadecimal string.

        Note
        ----
        This method returns a copy of the digest and can be called multiple times.
        The hasher state is preserved and can continue to be updated.
        """
        ...

    def copy(self) -> "HASH":
        """
        Return a copy of the hasher object.

        Returns
        -------
        Hasher
            A new hasher object with the same algorithm and internal state.

        Note
        ----
        This allows you to compute intermediate hashes without affecting
        the original hasher's state.
        """
        ...

    @property
    def name(self) -> str:
        """
        The name of the hash algorithm.

        Returns
        -------
        str
            The algorithm name (e.g., 'sha256', 'keccak256').
        """
        ...

    @property
    def digest_size(self) -> int:
        """
        The size of the digest in bytes.

        Returns
        -------
        int
            The number of bytes in the digest output.

        Examples
        --------
        SHA-256 returns 32, SHA-512 returns 64, etc.
        """
        ...

    @property
    def block_size(self) -> int:
        """
        The internal block size of the hash algorithm in bytes.

        Returns
        -------
        int
            The block size used internally by the hash algorithm.

        Note
        ----
        This is primarily useful for HMAC implementations and
        understanding the algorithm's internal structure.
        """
        ...
