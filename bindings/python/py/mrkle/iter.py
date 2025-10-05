from __future__ import annotations
from collections.abc import Iterator
from typing import Generic, cast

from typing_extensions import override

from mrkle._tree import Tree_T, Iterable_T

from mrkle.node import MrkleNode

from mrkle.typing import D as _D, SLOT_T
from mrkle.crypto.typing import Digest


class MrkleTreeIter(Generic[_D], Iterator[MrkleNode[_D]]):
    """Merkle tree iterator interface.

    This class provides a generic iterator over a Merkle tree, traversing
    the nodes in breadth-first order with a specified digest algorithm.

    Examples:
        >>> from mrkle.tree import MrkleTree
        >>> tree = MrkleTree.from_leaves([b"data1", b"data2"], name="sha256")
        >>> for node in tree:
        ...     print(node)
        ...
        MrkleNode(id=5b6d, leaf=False, dtype=Sha256())
        MrkleNode(id=5b41, leaf=True, dtype=Sha256())
        MrkleNode(id=d98c, leaf=True, dtype=Sha256())
    """

    _inner: Iterable_T
    _dtype: Digest
    __slots__: SLOT_T = ("_inner", "_dtype")

    def __init__(self, tree: Tree_T) -> None:
        self._dtype = tree.dtype()
        self._inner = tree.__iter__()

    @classmethod
    def from_tree(cls, _tree: Tree_T, _dtype: Digest) -> "MrkleTreeIter[_D]":
        """Create a new Merkle tree iterator from an existing tree.

        Args:
            _tree (TreeT): The internal Merkle tree object to iterate over.
            _dtype (_D): The digest algorithm associated with the tree, such as
                        :class:`Sha256` or :class:`Blake2b`.

        Returns:
            MrkleTreeIter[_D]: New iterator instance.

        Raises:
            AssertionError: If the digest algorithm of `_tree` does not match `_dtype`.

        Example:
            >>> from mrkle.tree import MrkleTree
            >>> from mrkle.digest import Sha256
            >>> from mrkle.iter import MrkleTreeIter
            >>> tree = MrkleTree.from_leaves([b"data1", b"data2"], name="sha256")
            >>> iterator = MrkleTreeIter.from_tree(tree, Sha256)
            >>> next(iterator)
            <sha256 mrkle.tree.MrkleNode object at 0x100...>
        """
        assert (
            _tree.dtype() == _dtype
        ), f"Missmatch {_tree.dtype()} does not match {_dtype}"
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
    ) -> "MrkleNode[_D]":
        if node := next(self._inner):
            return cast(MrkleNode[_D], MrkleNode.construct_from_node(node))
        else:
            raise StopIteration

    @override
    def __repr__(self) -> str:
        return f"<{self._dtype:!s} mrkle.iter.MrkleTreeIter object at {hex(id(self))}>"

    @override
    def __str__(self) -> str:
        return f"MrkleTreeIter(dtype={self._dtype.name().capitalize()}())"
