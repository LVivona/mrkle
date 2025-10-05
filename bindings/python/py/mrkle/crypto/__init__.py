"""
Cryptographic digest definitions and utility functions for
Merkle trees, nodes and proofs.

This module provides common cryptographic
hash algorithms (SHA, SHA3/Keccak, BLAKE2) and helper
functions to create digest objects by name.
"""

from __future__ import annotations

from types import MappingProxyType
from collections.abc import Mapping, Set
from typing import Optional, Final

from mrkle._mrkle_rs import crypto
from mrkle.crypto.typing import Digest

Digest_T = type[Digest]

__all__ = [
    "new",
    "Sha1",
    "Sha224",
    "Sha256",
    "Sha384",
    "Sha512",
    "Keccak224",
    "Keccak256",
    "Keccak384",
    "Keccak512",
    "Blake2s",
    "Blake2b",
    "sha1",
    "sha224",
    "sha256",
    "sha384",
    "sha512",
    "keccak224",
    "keccak256",
    "keccak384",
    "keccak512",
    "blake2b",
    "blake2s",
    "Digest",
    "Digest_T",
]


# SHA-1
Sha1 = crypto.sha1

# SHA-2
Sha224 = crypto.sha224
Sha256 = crypto.sha256
Sha384 = crypto.sha384
Sha512 = crypto.sha512

# SHA-3 / Keccak
Keccak224 = crypto.keccak224
Keccak256 = crypto.keccak256
Keccak384 = crypto.keccak384
Keccak512 = crypto.keccak512

# BLAKE2
Blake2s = crypto.blake2s256
Blake2b = crypto.blake2b512

# READ-ONLY ACCESS
_algorithms_map: Final[Mapping[str, Digest_T]] = MappingProxyType(
    {
        "blake2s": Blake2s,
        "blake2b": Blake2b,
        "blake2b512": Blake2b,
        "blake2s256": Blake2s,
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
)


def sha1(data: Optional[bytes] = None) -> Digest:
    """Create a SHA-1 hash object."""
    digest: Digest = _algorithms_map["sha1"]()
    if data is not None:
        digest.update(data)
    return digest


def sha224(data: Optional[bytes] = None) -> Digest:
    """Create a SHA-224 hash object."""
    digest = _algorithms_map["sha224"]()
    if data is not None:
        digest.update(data)
    return digest


def sha256(data: Optional[bytes] = None) -> Digest:
    """Create a SHA-256 hash object."""
    digest = _algorithms_map["sha256"]()
    if data is not None:
        digest.update(data)
    return digest


def sha384(data: Optional[bytes] = None) -> Digest:
    """Create a SHA-384 hash object."""
    digest = _algorithms_map["sha384"]()
    if data is not None:
        digest.update(data)
    return digest


def sha512(data: Optional[bytes] = None) -> Digest:
    """Create a SHA-512 hash object."""
    digest = _algorithms_map["sha512"]()
    if data is not None:
        digest.update(data)
    return digest


def keccak224(data: Optional[bytes] = None) -> Digest:
    """Create a Keccak-224 hash object."""
    digest = _algorithms_map["keccak224"]()
    if data is not None:
        digest.update(data)
    return digest


def keccak256(data: Optional[bytes] = None) -> Digest:
    """Create a Keccak-256 hash object."""
    digest = _algorithms_map["keccak256"]()
    if data is not None:
        digest.update(data)
    return digest


def keccak384(data: Optional[bytes] = None) -> Digest:
    """Create a Keccak-384 hash object."""
    digest = _algorithms_map["keccak384"]()
    if data is not None:
        digest.update(data)
    return digest


def keccak512(data: Optional[bytes] = None) -> Digest:
    """Create a Keccak-512 hash object."""
    digest = _algorithms_map["keccak512"]()
    if data is not None:
        digest.update(data)
    return digest


def blake2b(data: Optional[bytes] = None) -> Digest:
    """Create a BLAKE2b hash object."""
    digest = _algorithms_map["blake2b"]()
    if data is not None:
        digest.update(data)
    return digest


def blake2s(data: Optional[bytes] = None) -> Digest:
    """Create a BLAKE2s hash object."""
    digest = _algorithms_map["blake2s"]()
    if data is not None:
        digest.update(data)
    return digest


def new(name: str, *, data: Optional[bytes] = None) -> Digest:
    """Create a new digest object by algorithm name.

    Args:
        name (str): The name of the digest algorithm (case-insensitive).
        data (bytes, optional): Initial data to update the digest with.

    Returns:
        Digest: The corresponding digest object.

    Raises:
        ValueError: If the algorithm name is not supported.
    """
    if digest := _algorithms_map.get(name.lower()):
        d = digest()
        if data is not None:
            d.update(data)
        return d
    else:
        raise ValueError(f"{name} is not a supported digest.")


def algorithms_guaranteed() -> Set[str]:
    """Return the set of digest algorithm names guaranteed to be available.

    Returns:
        Set[str]: A set of algorithm names as strings.
    """
    return set(_algorithms_map.keys())


def algorithms_available() -> Set[str]:
    """Return the set of digest algorithms currently available.

    Returns:
        Set[str]: A set of available algorithm names as strings.
    """
    return algorithms_guaranteed()
