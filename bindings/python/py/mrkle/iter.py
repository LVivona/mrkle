from __future__ import annotations
from typing import Generic, Iterator

from mrkle._tree import TreeT as _TreeT, IterableT as _IterableT
from mrkle.node import MrkleNode
from mrkle.typing import D as _D, SLOT_T as _SLOT_T


class MrkleTreeIter(Generic[_D], Iterator[MrkleNode[_D]]):
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

    def __iter__(self) -> "MrkleTreeIter[_D]":
        return self

    def __next__(
        self,
    ) -> MrkleNode[_D]:
        if node := next(self._inner):
            return MrkleNode(node)
        else:
            raise StopIteration

    def __repr__(self) -> str:
        return f"<{self._dtype:!s} mrkle.iter.MrkleTreeIter object at {hex(id(self))}>"

    def __str__(self) -> str:
        return f"MrkleTreeIter(dtype={self._dtype.capitalize()}())"
