"""
Cryptographic digest definitions and utility functions for Merkle trees, and proof.

This module provides common cryptographic hash algorithms (SHA, SHA3/Keccak, BLAKE2)
and helper functions to create digest objects by name.
"""

from __future__ import annotations
from mrkle._mrkle_rs import crypto as _crypto

from typing import AbstractSet, Dict
from mrkle.crypto.typing import Digest

__all__ = [
    "new",
    "Sha1", "Sha224", "Sha256", "Sha384", "Sha512",
    "Keccak224", "Keccak256", "Keccak384", "Keccak512",
    "Blake2s", "Blake2b",
    "Digest"
]


# SHA-1 algorithms
Sha1: Digest = _crypto.sha1

# SHA-2 algorithms
Sha224: Digest = _crypto.sha224
Sha256: Digest = _crypto.sha256
Sha384: Digest = _crypto.sha384
Sha512: Digest = _crypto.sha512

# SHA-3 / Keccak algorithms
Keccak224: Digest = _crypto.keccak224
Keccak256: Digest = _crypto.keccak256
Keccak384: Digest = _crypto.keccak384
Keccak512: Digest = _crypto.keccak512

# BLAKE2 algorithms
Blake2s: Digest = _crypto.blake2s256
Blake2b: Digest = _crypto.blake2b512

_algorithms_map: Dict[str, Digest] = {
    "black2s": Blake2s,
    "black2b": Blake2b,
    "keccak224": Keccak224,
    "keccak256": Keccak256,
    "keccak384": Keccak384,
    "keccak512": Keccak512,
    "sha1": Sha1,
    "sha224": Sha224,
    "sha256": Sha256,
    "sha384": Sha384,
    "sha512": Sha512,
}

def new(name: str) -> Digest:
    """Create a new digest object by algorithm name.

    Args:
        name (str): The name of the digest algorithm (case-insensitive).

    Returns:
        Digest: The corresponding digest object.

    Raises:
        ValueError: If the algorithm name is not supported.
    """
    if digest := _algorithms_map.get(name.lower()):
        return digest
    else:
        raise ValueError(f"{name} is not a supported digest.")


def algorithms_guaranteed() -> AbstractSet[str]:
    """Return the set of digest algorithm names guaranteed to be available.

    Returns:
        AbstractSet[str]: A set of algorithm names as strings.
    """
    return set(_algorithms_map.keys())


def algorithms_available() -> AbstractSet[str]:
    """Return the set of digest algorithms currently available.

    This is equivalent to `algorithms_guaranteed` in the current implementation.

    Returns:
        AbstractSet[str]: A set of available algorithm names as strings.
    """
    return algorithms_guaranteed()
