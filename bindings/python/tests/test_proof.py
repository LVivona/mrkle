from mrkle.errors import ProofError
import pytest

import mrkle
from mrkle.tree import MrkleTree


def test_empty_tree_proof():
    with pytest.raises(mrkle.TreeError) as _:
        tree = MrkleTree.from_leaves([])
        _ = tree.generate_proof(0)


def test_empty_dict():
    with pytest.raises(
        ValueError, match="The dictionary can not contain more than one root."
    ):
        tree = MrkleTree.from_dict({}, format="flatten")
        _ = tree.generate_proof(0)


def test_single_leaf_tree_proof():
    tree = MrkleTree.from_leaves(["hello"])
    node = tree[0]
    proof = tree.generate_proof(node)

    assert proof.verify(node.digest())
    assert proof.verify(node.digest().hex())


def test_from_multiple_leaves():
    tree = MrkleTree.from_leaves(["a", "b", "c", "d"])
    nodes = tree[0:2]
    proof = tree.generate_proof(nodes)
    assert proof.verify(nodes)


def test_from_non_leaf():
    tree = MrkleTree.from_leaves(["a", "b", "c"])
    with pytest.raises(ProofError) as _:
        node = tree[3]
        proof = tree.generate_proof(node)
        assert proof.verify(node)
