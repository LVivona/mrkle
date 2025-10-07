"""Tests for MrkleNode functionality."""

import hashlib
import pytest
from mrkle.node import MrkleNode
from mrkle.crypto import (
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
    Keccak224,
    Keccak256,
    Keccak384,
    Keccak512,
    Blake2s,
    Blake2b,
)
from mrkle.crypto.typing import Digest


# Type checking tests
def test_sha1_isinstance_of_digest():
    assert isinstance(Sha1, type)
    assert issubclass(Sha1, Digest)


def test_sha256_isinstance_of_digest():
    assert isinstance(Sha256, type)
    assert issubclass(Sha256, Digest)


def test_all_digests_are_digest_types():
    digest_types = [
        Sha1,
        Sha224,
        Sha256,
        Sha384,
        Sha512,
        Keccak224,
        Keccak256,
        Keccak384,
        Keccak512,
        Blake2s,
        Blake2b,
    ]
    for dtype in digest_types:
        assert isinstance(dtype, type)
        assert issubclass(dtype, Digest)


# Basic node creation tests
def test_empty_bytes():
    node = MrkleNode.leaf("")
    assert node.is_leaf()
    assert node.dtype() == Sha1()
    assert node.digest() == hashlib.sha1(b"").digest()
    assert node.hexdigest() == hashlib.sha1(b"").hexdigest()


def test_leaf_with_string():
    node = MrkleNode.leaf("Hello world")
    assert node.is_leaf()
    assert node.digest() == hashlib.sha1(b"Hello world").digest()
    assert node.hexdigest() == hashlib.sha1(b"Hello world").hexdigest()


def test_leaf_with_bytes():
    data = b"Hello world"
    node = MrkleNode.leaf(data)
    assert node.is_leaf()
    assert node.digest() == hashlib.sha1(data).digest()
    assert node.hexdigest() == hashlib.sha1(data).hexdigest()


def test_leaf_with_different_digest():
    node = MrkleNode.leaf("Hello world", name="sha256")
    assert node.is_leaf()
    assert node.dtype() == Sha256()
    assert node.digest() == hashlib.sha256(b"Hello world").digest()
    assert node.hexdigest() == hashlib.sha256(b"Hello world").hexdigest()


def test_leaf_with_unicode():
    data = "Hello 世界 🌍"
    node = MrkleNode.leaf(data)
    assert node.is_leaf()
    assert node.digest() == hashlib.sha1(data.encode("utf-8")).digest()


def test_leaf_with_empty_unicode():
    node = MrkleNode.leaf("")
    assert node.is_leaf()
    assert node.digest() == hashlib.sha1(b"").digest()


# Node comparison tests
def test_different_node_type():
    node_sha1 = MrkleNode.leaf("Hello world")
    node_sha224 = MrkleNode.leaf("Hello world", name="sha224")
    assert node_sha1 != node_sha224
    assert node_sha1.dtype() != node_sha224.dtype()


def test_same_data_same_digest():
    node1 = MrkleNode.leaf("Hello world")
    node2 = MrkleNode.leaf("Hello world")
    assert node1 == node2
    assert node1.dtype() == node2.dtype()
    assert node1.digest() == node2.digest()


def test_different_data_same_digest_type():
    node1 = MrkleNode.leaf("Hello")
    node2 = MrkleNode.leaf("World")
    assert node1 != node2
    assert node1.dtype() == node2.dtype()
    assert node1.digest() != node2.digest()


def test_node_equality_reflexive():
    node = MrkleNode.leaf("test")
    assert node == node


def test_node_equality_symmetric():
    node1 = MrkleNode.leaf("test")
    node2 = MrkleNode.leaf("test")
    assert node1 == node2
    assert node2 == node1


def test_node_equality_transitive():
    node1 = MrkleNode.leaf("test")
    node2 = MrkleNode.leaf("test")
    node3 = MrkleNode.leaf("test")
    assert node1 == node2
    assert node2 == node3
    assert node1 == node3


def test_node_not_equal_to_non_node():
    node = MrkleNode.leaf("test")
    assert node != "test"
    assert node != b"test"
    assert node != 123
    assert node is not None


# Digest output tests
def test_sha1_output_length():
    node = MrkleNode.leaf("test", name="sha1")
    assert len(node.digest()) == 20
    assert len(node.hexdigest()) == 40


def test_sha224_output_length():
    node = MrkleNode.leaf("test", name="sha224")
    assert len(node.digest()) == 28
    assert len(node.hexdigest()) == 56


def test_sha256_output_length():
    node = MrkleNode.leaf("test", name="sha256")
    assert len(node.digest()) == 32
    assert len(node.hexdigest()) == 64


def test_sha384_output_length():
    node = MrkleNode.leaf("test", name="sha384")
    assert len(node.digest()) == 48
    assert len(node.hexdigest()) == 96


def test_sha512_output_length():
    node = MrkleNode.leaf("test", name="sha512")
    assert len(node.digest()) == 64
    assert len(node.hexdigest()) == 128


def test_keccak224_output_length():
    node = MrkleNode.leaf("test", name="keccak224")
    assert len(node.digest()) == 28
    assert len(node.hexdigest()) == 56


def test_keccak256_output_length():
    node = MrkleNode.leaf("test", name="keccak256")
    assert len(node.digest()) == 32
    assert len(node.hexdigest()) == 64


def test_keccak384_output_length():
    node = MrkleNode.leaf("test", name="keccak384")
    assert len(node.digest()) == 48
    assert len(node.hexdigest()) == 96


def test_keccak512_output_length():
    node = MrkleNode.leaf("test", name="keccak512")
    assert len(node.digest()) == 64
    assert len(node.hexdigest()) == 128


def test_blake2s_output_length():
    node = MrkleNode.leaf("test", name="blake2s")
    assert len(node.digest()) == 32
    assert len(node.hexdigest()) == 64


def test_blake2b_output_length():
    node = MrkleNode.leaf("test", name="blake2b")
    assert len(node.digest()) == 64
    assert len(node.hexdigest()) == 128


# Hexdigest format tests
def test_hexdigest_is_lowercase():
    node = MrkleNode.leaf("test")
    hexdigest = node.hexdigest()
    assert hexdigest == hexdigest.lower()


def test_hexdigest_is_hex():
    node = MrkleNode.leaf("test")
    hexdigest = node.hexdigest()
    assert all(c in "0123456789abcdef" for c in hexdigest)


def test_hexdigest_matches_digest():
    node = MrkleNode.leaf("test")
    assert node.hexdigest() == node.digest().hex()


# Edge cases
def test_leaf_with_null_byte():
    data = b"hello\x00world"
    node = MrkleNode.leaf(data)
    assert node.is_leaf()
    assert node.digest() == hashlib.sha1(data).digest()


def test_leaf_with_large_data():
    data = b"x" * 1_000_000
    node = MrkleNode.leaf(data)
    assert node.is_leaf()
    assert node.digest() == hashlib.sha1(data).digest()


def test_leaf_with_binary_data():
    data = bytes(range(256))
    node = MrkleNode.leaf(data)
    assert node.is_leaf()
    assert node.digest() == hashlib.sha1(data).digest()


# Hash consistency tests
def test_same_input_same_hash():
    nodes = [MrkleNode.leaf("test") for _ in range(10)]
    digests = [node.digest() for node in nodes]
    assert all(d == digests[0] for d in digests)


def test_different_input_different_hash():
    nodes = [MrkleNode.leaf(str(i)) for i in range(10)]
    digests = [node.digest() for node in nodes]
    assert len(set(digests)) == 10


def test_hash_deterministic():
    data = "deterministic test"
    node1 = MrkleNode.leaf(data)
    node2 = MrkleNode.leaf(data)
    node3 = MrkleNode.leaf(data)
    assert node1.digest() == node2.digest() == node3.digest()
    assert node1.hexdigest() == node2.hexdigest() == node3.hexdigest()


# Digest type tests
def test_all_sha_variants():
    data = "test"
    sha_variants = ["sha1", "sha224", "sha256", "sha384", "sha512"]
    nodes = [MrkleNode.leaf(data, name=variant) for variant in sha_variants]

    # All should be leaves
    assert all(node.is_leaf() for node in nodes)

    # All should have different digests
    digests = [node.digest() for node in nodes]
    assert len(set(digests)) == len(sha_variants)


def test_all_keccak_variants():
    data = "test"
    keccak_variants = ["keccak224", "keccak256", "keccak384", "keccak512"]
    nodes = [MrkleNode.leaf(data, name=variant) for variant in keccak_variants]

    assert all(node.is_leaf() for node in nodes)

    digests = [node.digest() for node in nodes]
    assert len(set(digests)) == len(keccak_variants)


def test_all_blake_variants():
    data = "test"
    blake_variants = ["blake2s", "blake2b"]
    nodes = [MrkleNode.leaf(data, name=variant) for variant in blake_variants]

    assert all(node.is_leaf() for node in nodes)

    digests = [node.digest() for node in nodes]
    assert len(set(digests)) == len(blake_variants)


# Invalid input tests
def test_invalid_digest_name():
    with pytest.raises(ValueError):
        _ = MrkleNode.leaf("test", name="invalid_digest")


def test_invalid_digest_name_case_insensitive():
    # Should work with different cases

    node1 = MrkleNode.leaf("test", name="SHA256")
    node2 = MrkleNode.leaf("test", name="sha256")
    assert node1 == node2


# String representation tests
def test_node_repr():
    node = MrkleNode.leaf("test")
    repr_str = repr(node)
    assert "MrkleNode" in repr_str or "mrkle" in repr_str.lower()


def test_node_str():
    node = MrkleNode.leaf("test")
    str_rep = str(node)
    assert isinstance(str_rep, str)
    assert len(str_rep) > 0


# Hashability tests
def test_node_is_hashable():
    node = MrkleNode.leaf("test")
    hash_value = hash(node)
    assert isinstance(hash_value, int)
