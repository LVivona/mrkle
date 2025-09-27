"""

"""
from mrkle.crypto.typing import Digest

from mrkle._mrkle_rs import crypto

__all__ = ["Sha1", "Sha224", "Sha256", "Sha384", "Sha512", "Keccak224", "Keccak256", "Keccak384", "Keccak512", "Blake2s", "Blake2b", "Digest"]

# sha1 algorithms
Sha1   = crypto.sha1

# sha2 algorithms
Sha224 = crypto.sha224
Sha256 = crypto.sha256
Sha384 = crypto.sha384
Sha512 = crypto.sha512

# sha3/Keccak
Keccak224 = crypto.keccak224
Keccak256 = crypto.keccak256
Keccak384 = crypto.keccak384
Keccak512 = crypto.keccak512

# BLAKE2
Blake2s = crypto.blake2s256
Blake2b = crypto.blake2b512
