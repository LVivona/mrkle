"""Implementation of MrkleTree & MrkleNode"""

from __future__ import annotations

from collections.abc import Sequence, Set
from typing import (
    Generic,
    Union,
    Optional,
    List,
    overload,
)
from typing_extensions import TypeAlias

from mrkle._mrkle_rs import tree

from mrkle.crypto import new
from mrkle.typing import _D, Buffer, _TreeT
from mrkle.proof import MrkleProof
from mrkle.iter import MrkleTreeIter
from mrkle.node import MrkleNode, Node

_TREE_MAP = {
    "blake2s": tree.MrkleTreeBlake2s,
    "blake2b": tree.MrkleTreeBlake2b,
    "keccak224": tree.MrkleTreeKeccak224,
    "keccak256": tree.MrkleTreeKeccak256,
    "keccak384": tree.MrkleTreeKeccak384,
    "keccak512": tree.MrkleTreeKeccak512,
    "sha1": tree.MrkleTreeSha1,
    "sha224": tree.MrkleTreeSha224,
    "sha256": tree.MrkleTreeSha256,
    "sha384": tree.MrkleTreeSha384,
    "sha512": tree.MrkleTreeSha512,
}


class MrkleTree(Generic[_D]):
    __slots__ = ("_inner", "_digest")

    def __init__(self, *args, **kwds):
        raise TypeError("Direct instantiation of MrkleTree is not allowed.")

    @property
    def root(self) -> bytes:
        """Return root of MrkleTree[_D]"""
        return self._inner.root

    @property
    def leaves(self) -> List[Node]:
        """Return MrkleNode[_D] from MrkleTree"""
        return self._inner.leaves()

    def dtype(self) -> _D:
        """Return Digest type"""
        return self._digest

    @classmethod
    def from_leaves(
        cls, leaves: List[Union[str, Buffer]], *, name: Optional[str] = None
    ) -> "MrkleTree[_D]":
        """"""
        if name is None:
            name = "sha1"
        digest: _D = new(name)
        name = digest.name()

        buffer: List[bytes] = [
            leaf.encode("utf-8") if isinstance(leaf, str) else bytes(leaf)
            for leaf in leaves
        ]

        if inner := _TREE_MAP.get(name):
            return cls._construct_tree_backend(inner.from_leaves(buffer), digest)
        else:
            raise ValueError(
                f"{name} is not digested that a supported with in MrkleTree."
            )

    def generate_proof(self, leaves: Set[Node]) -> "MrkleProof[_D]":
        """Generate proof from MrkleTree"""
        return MrkleProof(self, leaves)

    @classmethod
    def _construct_tree_backend(cls, inner: _TreeT, digest: _D) -> "Tree":
        obj = object.__new__(cls)
        object.__setattr__(obj, "_inner", inner)
        object.__setattr__(obj, "_digest", digest)
        return obj

    @overload
    def __getitem__(self, key: slice) -> List[Node]: ...

    @overload
    def __getitem__(self, key: Sequence[int]) -> List[Node]: ...

    def __getitem__(self, key: Union[int, slice, Sequence[int]]) -> List[Node]:
        if isinstance(key, int):
            return list()
        elif isinstance(key, slice):
            return list()
        elif isinstance(key, Sequence):
            return list()
        else:
            raise TypeError(f"Invalid index type: {type(key)}")

    def __iter__(self) -> "MrkleTreeIter[_D]":
        return MrkleTreeIter.from_tree(self._inner.__iter__(), self._digest)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, MrkleNode):
            return NotImplemented
        if type(self._inner) is not type(other._inner):
            return False
        return self._inner == other._inner

    def __len__(self) -> int:
        return len(self._inner)

    def __hash__(self) -> int:
        return hash((type(self._inner), self._inner))

    def __repr__(self) -> str:
        return f"<{self._digest.name()} mrkle.tree.MrkleTree object at {hex(id(self))}>"

    def __str__(self) -> str:
        root: str = self._inner.root()
        return f"MrkleTree(root={root[0 : min(len(root), 4)]}, length={len(self)}, dtype={self._digest.name()})"


Tree: TypeAlias = MrkleTree[_D]
