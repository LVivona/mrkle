import pytest
import hashlib
from mrkle import crypto


# Algorithms that are available in hashlib
HASHLIB_ALGS = {
    "sha1": hashlib.sha1,
    "sha224": hashlib.sha224,
    "sha256": hashlib.sha256,
    "sha384": hashlib.sha384,
    "sha512": hashlib.sha512,
    "blake2b": hashlib.blake2b,
    "blake2s": hashlib.blake2s,
}

# Algorithms only available in mrkle.crypto (not in hashlib stdlib)
MRKLE_ONLY_ALGS = [
    "keccak224",
    "keccak256",
    "keccak384",
    "keccak512",
]

PAYLOADS = [
    b"",
    b"hello world",
    b"The quick brown fox jumps over the lazy dog",
    b"a" * 10_000,  # stress test large input
]


@pytest.mark.parametrize("alg,payload", [
    (alg, payload) for alg in HASHLIB_ALGS for payload in PAYLOADS
])
def test_hashlib_compatible(alg, payload):
    """Test algorithms supported by both hashlib and mrkle.crypto."""
    h1 = HASHLIB_ALGS[alg](payload).digest()
    h2 = getattr(crypto, alg)(payload).digest()
    assert h1 == h2, f"Mismatch for {alg} with payload {payload!r}"


@pytest.mark.parametrize("alg,payload", [
    (alg, payload) for alg in MRKLE_ONLY_ALGS for payload in PAYLOADS
])
def test_mrkle_only(alg, payload):
    """Test keccak-family hashes (not in hashlib)."""
    h = getattr(crypto, alg)(payload).digest()
    assert isinstance(h, (bytes, bytearray))
    assert len(h) == getattr(crypto, alg)().digest_size


def test_copy_and_hexdigest():
    """Check copy() and hexdigest() behave like hashlib."""
    h1 = crypto.sha256(b"abc")
    h2 = h1.copy()
    assert h1.digest() == h2.digest()
    assert h1.hexdigest() == h2.hexdigest()
    assert isinstance(h1.hexdigest(), str)
    assert len(h1.hexdigest()) == 64


crypto.HASH
