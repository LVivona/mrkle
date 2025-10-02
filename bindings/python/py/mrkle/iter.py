from __future__ import annotations
from collections.abc import Iterator
from typing import Generic
from typing_extensions import override

from mrkle._tree import TreeT as _TreeT, IterableT as _IterableT
from mrkle.node import MrkleNode
from mrkle.typing import D as _D, SLOT_T as _SLOT_T


class MrkleTreeIter(Generic[_D], Iterator[MrkleNode[_D]]):
    """Merkle tree iterator interface.

    This class provides a generic iterator over a Merkle tree, traversing
    the nodes in breadth-first order with a specified digest algorithm.

    Examples:
        >>> from mrkle.tree import MrkleTree
        >>> from mrkle.iter import MrkleTreeIter
        >>> tree = MrkleTree.from_leaves([b"data1", b"data2"], name="sha256")
        >>> for node in tree:
        ...     print(node)
        ...
        MrkleNode(id=5b6d, leaf=False, dtype=Sha256())
        MrkleNode(id=5b41, leaf=True, dtype=Sha256())
        MrkleNode(id=d98c, leaf=True, dtype=Sha256())
    """

    _inner: _IterableT
    _dtype: str
    __slots__: _SLOT_T = ("_inner", "_dtype")

    def __init__(self, tree: _TreeT) -> None:
        self._dtype = tree.dtype()
        self._inner = tree.__iter__()

    @classmethod
    def from_tree(cls, _tree: _TreeT, _dtype: _D) -> "MrkleTreeIter[_D]":
        assert _tree.dtype() == _dtype, (
            f"Missmatch {_tree.dtype()} does not match {_dtype}"
        )
        obj = object.__new__(cls)
        object.__setattr__(obj, "_inner", _tree.__iter__())
        object.__setattr__(obj, "_dtype", _dtype.name())
        return obj

    @override
    def __iter__(self) -> "MrkleTreeIter[_D]":
        return self

    @override
    def __next__(
        self,
    ) -> MrkleNode[_D]:
        if node := next(self._inner):
            return MrkleNode._construct_from_node_t(node)
        else:
            raise StopIteration

    @override
    def __repr__(self) -> str:
        return f"<{self._dtype:!s} mrkle.iter.MrkleTreeIter object at {hex(id(self))}>"

    @override
    def __str__(self) -> str:
        return f"MrkleTreeIter(dtype={self._dtype.capitalize()}())"
