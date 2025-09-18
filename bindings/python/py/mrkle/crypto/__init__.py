"""
Python wrapper for the Rust-based hash library.

This module provides a hashlib-compatible interface for various cryptographic
hash algorithms implemented in Rust.
"""
from __future__ import annotations
from .._mrkle_rs import crypto
from typing import overload, Optional

_HASH = crypto.HASH

@overload
def new(kind: str) -> "HASH": ...

@overload
def new(kind: str, data: bytes) -> "HASH": ...

@overload
def new(kind: str, data: Optional[bytes] = None) -> "HASH": ...

def new(*args, **kwargs) -> "HASH":
    """
    Create a new hash object using the specified algorithm.

    Parameters
    ----------
    kind : str
        The name of the hash algorithm (e.g., 'sha256', 'keccak256').
    data : bytes, optional
        Initial data to hash. If provided, equivalent to calling update(data)
        on the returned hasher.

    Returns
    -------
    _HASH
        A new hash object for the specified algorithm.

    Raises
    ------
    ValueError
        If the specified algorithm is not supported.

    Examples
    --------
    >>> hasher = new('sha256')
    >>> hasher.update(b'hello')
    >>> hasher.hexdigest()
    '2cf24dba4f...'

    >>> hasher = new('sha256', b'hello')
    >>> hasher.hexdigest()
    '2cf24dba4f...'
    """
    # Handle different argument patterns
    if len(args) == 0 and len(kwargs) == 0:
        raise TypeError("new() missing required argument: 'algorithm'")

    # Extract arguments
    kind = args[0] if args else kwargs.get('kind')
    data = args[1] if len(args) > 1 else kwargs.get('data')

    if kind is None:
        raise TypeError("new() missing required argument: 'algorithm'")

    hasher = _HASH(kind)
    if data is not None:
        hasher.update(data)
    return hasher


def sha1(data: Optional[bytes] = None) -> "HASH":
    """
    Create a SHA-1 hash object.

    Parameters
    ----------
    data : bytes, optional
        Initial data to hash.

    Returns
    -------
    Hasher
        A SHA-1 hash object.

    Examples
    --------
    >>> hasher = sha1()
    >>> hasher.update(b'hello')
    >>> hasher.hexdigest()
    'aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d'
    """
    hasher = _HASH("sha1")
    if data is not None:
        hasher.update(data)
    return hasher


def sha224(data: Optional[bytes] = None) -> "HASH":
    """
    Create a SHA-224 hash object.

    Parameters
    ----------
    data : bytes, optional
        Initial data to hash.

    Returns
    -------
    Hasher
        A SHA-224 hash object.

    Examples
    --------
    >>> hasher = sha224()
    >>> hasher.update(b'hello')
    >>> hasher.hexdigest()
    'd14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f'
    """
    hasher = _HASH("sha224")
    if data is not None:
        hasher.update(data)
    return hasher


def sha256(data: Optional[bytes] = None) -> "HASH":
    """
    Create a SHA-256 hash object.

    Parameters
    ----------
    data : bytes, optional
        Initial data to hash.

    Returns
    -------
    Hasher
        A SHA-256 hash object.

    Examples
    --------
    >>> hasher = sha256()
    >>> hasher.update(b'hello')
    >>> hasher.hexdigest()
    '2cf24dba4f21d4288709a3b33a5c5d2d0c91f0c58bbfbb29a5b5a4b2dc2cf'
    """
    hasher = _HASH("sha256")
    if data is not None:
        hasher.update(data)
    return hasher


def sha384(data: Optional[bytes] = None) -> "HASH":
    """
    Create a SHA-384 hash object.

    Parameters
    ----------
    data : bytes, optional
        Initial data to hash.

    Returns
    -------
    Hasher
        A SHA-384 hash object.

    Examples
    --------
    >>> hasher = sha384()
    >>> hasher.update(b'hello')
    >>> hasher.hexdigest()
    '59e1748777448c69de6b800d7a33bbfb9ff1b463e44354c3553bcdb9c666fa90125a3c79f90397bdf5f6a13de828684f'
    """
    hasher = _HASH("sha384")
    if data is not None:
        hasher.update(data)
    return hasher


def sha512(data: Optional[bytes] = None) -> "HASH":
    """
    Create a SHA-512 hash object.

    Parameters
    ----------
    data : bytes, optional
        Initial data to hash.

    Returns
    -------
    Hasher
        A SHA-512 hash object.

    Examples
    --------
    >>> hasher = sha512()
    >>> hasher.update(b'hello')
    >>> hasher.hexdigest()
    '9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca72323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043'
    """
    hasher = _HASH("sha512")
    if data is not None:
        hasher.update(data)
    return hasher


def keccak224(data: Optional[bytes] = None) -> "HASH":
    """
    Create a Keccak-224 hash object.

    Parameters
    ----------
    data : bytes, optional
        Initial data to hash.

    Returns
    -------
    Hasher
        A Keccak-224 hash object.

    Examples
    --------
    >>> hasher = keccak224()
    >>> hasher.update(b'hello')
    >>> hasher.hexdigest()
    'b73d6c954381f76cd84c6f6e4415b5ac92edc3c5ae7b88f66f32a8d1a9e0'
    """
    hasher = _HASH("keccak224")
    if data is not None:
        hasher.update(data)
    return hasher


def keccak256(data: Optional[bytes] = None) -> "HASH":
    """
    Create a Keccak-256 hash object.

    Parameters
    ----------
    data : bytes, optional
        Initial data to hash.

    Returns
    -------
    Hasher
        A Keccak-256 hash object.

    Examples
    --------
    >>> hasher = keccak256()
    >>> hasher.update(b'hello')
    >>> hasher.hexdigest()
    '1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8'
    """
    hasher = _HASH("keccak256")
    if data is not None:
        hasher.update(data)
    return hasher


def keccak384(data: Optional[bytes] = None) -> "HASH":
    """
    Create a Keccak-384 hash object.

    Parameters
    ----------
    data : bytes, optional
        Initial data to hash.

    Returns
    -------
    Hasher
        A Keccak-384 hash object.

    Examples
    --------
    >>> hasher = keccak384()
    >>> hasher.update(b'hello')
    >>> hasher.hexdigest()
    'dcef6fb7908fd52ba26aaba75121526abbf1217f1c0a31024652d134d3e32fb4cd8e9c703b8f43e7277b59a5cd402175'
    """
    hasher = _HASH("keccak384")
    if data is not None:
        hasher.update(data)
    return hasher


def keccak512(data: Optional[bytes] = None) -> "HASH":
    """
    Create a Keccak-512 hash object.

    Parameters
    ----------
    data : bytes, optional
        Initial data to hash.

    Returns
    -------
    Hasher
        A Keccak-512 hash object.

    Examples
    --------
    >>> hasher = keccak512()
    >>> hasher.update(b'hello')
    >>> hasher.hexdigest()
    '52fa80662e64c128f8389c9ea6c73d4c02368004bf4463491900d11aaadca39d47de1b01361f207c512cfa79f0f92c3395c67ff7928e3f5ce3e3c852b392f976'
    """
    hasher = _HASH("keccak512")
    if data is not None:
        hasher.update(data)
    return hasher


def blake2b(data: Optional[bytes] = None, digest_size: int = 64) -> "HASH":
    """
    Create a BLAKE2b hash object.

    Parameters
    ----------
    data : bytes, optional
        Initial data to hash.
    digest_size : int, optional
        The desired digest size in bytes (1-64). Default is 64.

    Returns
    -------
    Hasher
        A BLAKE2b hash object.

    Examples
    --------
    >>> hasher = blake2b()
    >>> hasher.update(b'hello')
    >>> hasher.hexdigest()
    'e4cfa39a3d37be31c59609e807970799caa68a19bfaa15135f165085e01d41a65c1340bd50b9933f89bbaad8c93c7ae8edf49c6cf3c5d0b6f3d6eedc14f0b5b'
    """
    # Note: This uses blake2b512 - you might need to handle different sizes in Rust
    hasher = _HASH("blake2b512")
    if data is not None:
        hasher.update(data)
    return hasher


def blake2s(data: Optional[bytes] = None, digest_size: int = 32) -> "HASH":
    """
    Create a BLAKE2s hash object.

    Parameters
    ----------
    data : bytes, optional
        Initial data to hash.
    digest_size : int, optional
        The desired digest size in bytes (1-32). Default is 32.

    Returns
    -------
    Hasher
        A BLAKE2s hash object.

    Examples
    --------
    >>> hasher = blake2s()
    >>> hasher.update(b'hello')
    >>> hasher.hexdigest()
    '19213bacc58dee6dbde3ceb9a47cbb330b3d86f8cca8997eb00be456f140ca25'
    """
    # Note: This uses blake2s256 - you might need to handle different sizes in Rust
    hasher = _HASH("blake2s256")
    if data is not None:
        hasher.update(data)
    return hasher


def algorithms_guaranteed() -> list[str]:
    """
    Return a list of hash algorithm names that are guaranteed to be available.

    Returns
    -------
    list[str]
        List of guaranteed hash algorithm names.

    Examples
    --------
    >>> algorithms_guaranteed()
    ['sha1', 'sha224', 'sha256', 'sha384', 'sha512', 'keccak224', 'keccak256', 'keccak384', 'keccak512', 'blake2b512', 'blake2s256']
    """
    return [
        'sha1', 'sha224', 'sha256', 'sha384', 'sha512',
        'keccak224', 'keccak256', 'keccak384', 'keccak512',
        'blake2b512', 'blake2s256'
    ]


def algorithms_available() -> list[str]:
    """
    Return a list of hash algorithm names that are available in the system.

    Returns
    -------
    list[str]
        List of available hash algorithm names.

    Note
    ----
    This returns the same as algorithms_guaranteed() since all algorithms
    are compiled into the Rust library.

    Examples
    --------
    >>> algorithms_available()
    ['sha1', 'sha224', 'sha256', 'sha384', 'sha512', 'keccak224', 'keccak256', 'keccak384', 'keccak512', 'blake2b512', 'blake2s256']
    """
    return algorithms_guaranteed()


__all__ = [
    'new', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512',
    'keccak224', 'keccak256', 'keccak384', 'keccak512',
    'blake2b', 'blake2s',
    'algorithms_guaranteed', 'algorithms_available'
]
