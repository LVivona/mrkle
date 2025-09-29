from __future__ import annotations
from typing import Generic, Optional

from mrkle.crypto import new
from mrkle.node import MrkleNode, Node
from mrkle.typing import _D, _Iter

class MrkleTreeIter(Generic[_D]):

    __slots__ = ("_inner", "_digest")

    @classmethod
    def from_tree(cls, _inner : _Iter, _digest : _D) -> "MrkleTreeIter[_D]":
        obj = object.__new__(cls)
        object.__setattr__(obj, "_inner", _inner)
        object.__setattr__(obj, "_digest", _digest.name())
        return obj


    def __init__(self, *args, **kwargs):
        raise TypeError(
            "Direct instantiation of MrkleTreeIter is not allowed;"
            "use `from_tree` instead."
        )

    def __iter__(self) -> "MrkleTreeIter[_D]":
        return self

    def __next__(self) -> Optional[Node]:
        if node:= next(self._inner):
            return MrkleNode.\
                _construct_node_backend(node, new(self._digest))

    def __repr__(self) -> str:
        return f"<{self._digest} mrkle.iter.MrkleTreeIter object at {hex(id(self))}>"
