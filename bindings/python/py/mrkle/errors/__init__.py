"""Error classes shared between the Rust and Python layers of Mrkle.

This module re-exports error types defined in the Rust extension
(`mrkle._mrkle_rs.errors`) so they can be caught and handled in Python code.

These errors represent different failure domains within Mrkle's Merkle tree
implementation:

- **MerkleError** — Base error type for all Mrkle-related exceptions.
- **ProofError** — Errors raised during proof validation or construction.
- **TreeError** — Errors related to tree structure or operations.
- **NodeError** — Errors specific to individual node states or mutations.
- **SerdeError** — Serialization or deserialization failures.

Example:
    >>> from mrkle.errors import ProofError
    >>> from mrkle.tree import MrkleTree
    >>> tree = MrkleTree.from_leaves(["a", "b", "c"], name="sha224")
    >>> try:
    ...     proof = tree.generate_proof(3)
    ... except ProofError as e:
    ...     print("Invalid proof:", e)
"""

from mrkle._mrkle_rs import errors

__all__ = [
    "MerkleError",
    "ProofError",
    "TreeError",
    "NodeError",
    "SerdeError",
]

MerkleError = errors.MerkleError
ProofError = errors.ProofError
TreeError = errors.TreeError
NodeError = errors.NodeError
SerdeError = errors.SerdeError
