"""mrkle is a fast and flexible Merkle Tree library built with Rust and PyO3.

It provides efficient construction of Merkle Trees,
verification of Merkle Proofs for single and multiple elements,
and generic support for any hashable data type.
"""

from __future__ import annotations
from ._mrkle_rs import __version__

from . import crypto
from . import tree
from . import node

from .node import MrkleNode
from .tree import MrkleTree, MrkleProof
from .iter import MrkleTreeIter

from .errors import (
    MerkleError,
    TreeError,
    SerdeError,
    NodeError,
    ProofError,
)


__all__ = [
    "__version__",
    "crypto",
    "tree",
    "node",
    "MrkleNode",
    "MrkleTree",
    "MrkleProof",
    "MrkleTreeIter",
    "MerkleError",
    "TreeError",
    "SerdeError",
    "NodeError",
    "ProofError",
]
