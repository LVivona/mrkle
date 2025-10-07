import pytest
import hashlib
from mrkle import crypto


# Algorithms that are available in hashlib
HASHLIB_ALGS = {
    "Sha1": hashlib.sha1,
    "Sha224": hashlib.sha224,
    "Sha256": hashlib.sha256,
    "Sha384": hashlib.sha384,
    "Sha512": hashlib.sha512,
    "Blake2b": hashlib.blake2b,
    "Blake2s": hashlib.blake2s,
}

# Algorithms only available in mrkle.crypto (not in hashlib stdlib)
MRKLE_ONLY_ALGS = [
    "Keccak224",
    "Keccak256",
    "Keccak384",
    "Keccak512",
]

PAYLOADS = [
    b"",
    b"hello world",
    b"The quick brown fox jumps over the lazy dog",
    b"a" * 10_000,  # stress test large input
]


@pytest.mark.parametrize(
    "alg,payload", [(alg, payload) for alg in HASHLIB_ALGS for payload in PAYLOADS]
)
def test_hashlib_compatible(alg, payload):
    """Test algorithms supported by both hashlib and mrkle.crypto."""
    h1 = HASHLIB_ALGS[alg](payload).digest()
    h2 = getattr(crypto, alg).digest(payload)
    assert h1 == h2, f"Mismatch for {alg} with payload {payload!r}"


@pytest.mark.parametrize(
    "alg,payload", [(alg, payload) for alg in MRKLE_ONLY_ALGS for payload in PAYLOADS]
)
def test_mrkle_only(alg, payload):
    """Test keccak-family hashes (not in hashlib)."""
    h = getattr(crypto, alg).digest(payload)
    assert isinstance(h, (bytes, bytearray))
    assert len(h) == getattr(crypto, alg)().output_size()
