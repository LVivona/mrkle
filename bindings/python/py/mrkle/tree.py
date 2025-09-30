"""Implementation of MrkleTree & MrkleNode"""

from __future__ import annotations

from collections.abc import Sequence, Set
from typing import (
    Generic,
    Union,
    Optional,
    overload,
)
from mrkle.crypto.typing import Digest
from typing_extensions import TypeAlias

from mrkle.crypto import new
from mrkle.typing import D as _D, Buffer
from mrkle.iter import MrkleTreeIter
from mrkle.node import MrkleNode
from mrkle._tree import TreeT as _TreeT, _TREE_MAP


class MrkleTree(Generic[_D]):
    _inner: _TreeT
    _dtype: _D

    __slots__ = ("_inner", "_dtype")

    def __init__(self, tree: _TreeT):
        self._inner = tree
        self._dtype = tree.dtype()

    def root(self) -> str:
        """Return root hex string"""
        return self._inner.root()

    def leaves(self) -> list[MrkleNode[_D]]:
        """Return list of MrkleNode[_D] from MrkleTree[_D]"""
        return list(
            map(
                lambda x: MrkleNode[_D](x),
                self._inner.leaves(),
            )
        )

    def dtype(self) -> _D:
        """Return Digest type"""
        return self._dtype

    def _capacity(self) -> int:
        return self._inner.capacity()

    @classmethod
    def from_leaves(
        cls, leaves: list[Union[str, Buffer]], *, name: Optional[str] = None
    ) -> "MrkleTree[_D]":
        """"""
        if name is None:
            name = "sha1"
        digest = new(name)
        name = digest.name()

        buffer: list[bytes] = [
            leaf.encode("utf-8") if isinstance(leaf, str) else bytes(leaf)
            for leaf in leaves
        ]

        if inner := _TREE_MAP.get(name):
            return cls._construct_tree_backend(inner.from_leaves(buffer), digest)
        else:
            raise ValueError(
                f"{name} is not digested that a supported with in MrkleTree."
            )

    def generate_proof(self, leaves: Set[MrkleNode[_D]]) -> "MrkleProof[_D]":
        """Generate proof from MrkleTree"""
        return MrkleProof(self, leaves)

    @classmethod
    def _construct_tree_backend(cls, tree: _TreeT, dtype: Digest) -> "MrkleTree[_D]":
        assert tree.dtype() == dtype, (
            f"Missmatch {tree.dtype():!s} does not match {dtype:!s}"
        )
        obj = object.__new__(cls)
        object.__setattr__(obj, "_inner", tree)
        object.__setattr__(obj, "_dtype", dtype)
        return obj

    def _internal(self) -> _TreeT:
        return self._inner

    @overload
    def __getitem__(self, key: slice) -> list[MrkleNode[_D]]: ...

    @overload
    def __getitem__(self, key: Sequence[int]) -> list[MrkleNode[_D]]: ...

    def __getitem__(self, key: Union[int, slice, Sequence[int]]) -> list[MrkleNode[_D]]:
        if isinstance(key, int):
            return list()
        elif isinstance(key, slice):
            return list()
        elif isinstance(key, Sequence):
            return list()
        else:
            raise TypeError(f"Invalid index type: {type(key)}")

    def __iter__(self) -> "MrkleTreeIter[_D]":
        return MrkleTreeIter.from_tree(self._inner, self._dtype)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, MrkleTree):
            if self.dtype() != other.dtype():
                return False

            return self._inner == other._inner
        else:
            return False

    def __len__(self) -> int:
        return len(self._inner)

    def __hash__(self) -> int:
        return hash((type(self._inner), self._inner))

    def __repr__(self) -> str:
        return f"<{self._dtype.name()} mrkle.tree.MrkleTree object at {hex(id(self))}>"

    def __str__(self) -> str:
        root: str = self._inner.root()
        return (
            f"MrkleTree(root={root[0 : min(len(root), 4)]},"
            f" length={len(self)}, dtype={self._dtype:!s})"
        )

    def __format__(self, format_spec: str, /) -> str:
        return super().__format__(format_spec)


class MrkleProof(Generic[_D]):
    def __init__(self, tree: "MrkleTree[_D]", leaves: Set[MrkleNode[_D]]) -> None: ...


Tree: TypeAlias = MrkleTree[_D]
