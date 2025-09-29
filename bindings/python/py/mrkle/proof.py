"""Implmentation of MrkleTree.

Provides utilities to create and verify Merkle proofs. A Merkle
proof demonstrates that a given leaf node is part of a Merkle tree with a
known root hash. Proofs are typically represented as a sequence of sibling
hashes from the leaf up to the root.

Example:
    >>> from mrkle.tree import MrkleTree
    >>> from mrkle.proof import MerkleProof
    >>> leaves = [b'leaf1', b'leaf2', b'leaf3']
    >>> tree = MerkleTree.from_leaves(leaves)
    >>> proof = tree.get_proof(1)  # proof for 'leaf2'
    >>> MerkleProof(proof).verify(tree.root_hash, b'leaf2')
    True

Notes:
- Proofs are valid only for the tree they were generated from.
- The module supports hashing algorithms compatible with the `crypto` module.
- For bulk verification, consider batching proofs to reduce hash computations.
"""

from __future__ import annotations
from typing import Generic, AbstractSet

from mrkle.node import MrkleNode
from mrkle.typing import _D


class MrkleProof(Generic[_D]):
    def __init__(
        self, tree: "MrkleTree[_D]", leaves: AbstractSet[MrkleNode[_D]]
    ) -> None: ...
