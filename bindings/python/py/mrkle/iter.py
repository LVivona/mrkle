from __future__ import annotations
from collections.abc import Iterator
from typing import final

from mrkle.crypto import new
from typing_extensions import override

from mrkle._tree import Tree_T, Iterable_T

from mrkle.node import MrkleNode

from mrkle.crypto.typing import Digest


@final
class MrkleTreeIter(Iterator[MrkleNode]):
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
    _dtype_name: str
    __slots__ = ("_inner", "_dtype_name")

    def __init__(self, tree: Tree_T) -> None:
        self._dtype_name = tree.dtype().name()
        self._inner = tree.__iter__()

    @classmethod
    def from_tree(cls, _tree: Tree_T) -> "MrkleTreeIter":
        """Create a new Merkle tree iterator from an existing tree.

        Args:
            _tree (TreeT): The internal Merkle tree object to iterate over.

        Returns:
            MrkleTreeIter: New iterator instance.

        Example:
            >>> from mrkle.tree import MrkleTree
            >>> tree = MrkleTree.from_leaves([b"data1", b"data2"], name="sha256")
            >>> iterator = iter(tree)
            >>> next(iterator)
            <sha256 mrkle.tree.MrkleNode object at 0x...>
        """
        obj = object.__new__(cls)
        object.__setattr__(obj, "_inner", _tree.__iter__())
        object.__setattr__(obj, "_dtype_name", _tree.dtype().name())
        return obj

    def dtype(self) -> Digest:
        """Return the digest type used by this iterator.

        Returns:
            Digest: The digest algorithm instance (e.g., Sha1(), Sha256()).
        """
        return new(self._dtype_name)

    @override
    def __iter__(self) -> "MrkleTreeIter":
        return self

    @override
    def __next__(
        self,
    ) -> "MrkleNode":
        if node := next(self._inner):
            return MrkleNode(node)
        else:
            raise StopIteration

    @override
    def __repr__(self) -> str:
        return (
            f"<{self._dtype_name} mrkle.iter.MrkleTreeIter object at {hex(id(self))}>"
        )

    @override
    def __str__(self) -> str:
        return f"MrkleTreeIter(dtype={self._dtype_name})"
