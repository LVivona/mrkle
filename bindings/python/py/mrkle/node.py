from __future__ import annotations

from array import array
from collections.abc import Sequence
from typing_extensions import override

from mrkle.crypto import new
from mrkle.crypto.typing import Digest

from mrkle.typing import BufferLike as Buffer

from mrkle._tree import Node_T, NODE_MAP

from typing import Any, Union, Optional, final


__all__ = ["MrkleNode"]


@final
class MrkleNode:
    """A generic Merkle tree node.

    This class provides an immutable Python interface for Merkle tree nodes
    with a specific digest algorithm. Users should **not** instantiate nodes
    directly; instead, use the `leaf` class method to create leaf nodes with
    the appropriate digest.

    Attributes:
        _inner (Node): The underlying Rust-based Merkle node instance.
        _dtype_name (str): The name of the digest algorithm used by this node.


    Examples:
        >>> from mrkle.tree import MrkleTree
        >>> tree = MrkleTree.from_leaves(["a", "b", "c"])
        >>> node = tree[0]
        >>>
    """

    _inner: Node_T
    _dtype_name: str
    __slots__ = (
        "_inner",
        "_dtype_name",
    )

    def __init__(self, node: Node_T, *args, **kwargs) -> None:
        self._inner = node
        self._dtype_name = node.dtype().name()

    @classmethod
    def construct_from_node(cls, node: Node_T, **kwargs: dict[str, Any]) -> MrkleNode:
        """Internal method to create a MrkleNode instance bypassing __init__.

        Args:
            inner (Node): The Rust-based Merkle node.

        Returns:
            MrkleNode: A new instance wrapping the given inner node.

        """
        obj = object.__new__(cls)
        object.__setattr__(obj, "_inner", node)
        object.__setattr__(obj, "_dtype_name", node.dtype().name())

        return obj

    def parent(self) -> Optional[int]:
        """Return parent index within the tree."""
        return self._inner.parent()

    def children(self) -> Sequence[int]:
        """Return children indcies within the tree."""
        return self._inner.children()

    def value(self) -> Optional[bytes]:
        """Return internal value of node."""
        return self._inner.value()

    def digest(self) -> bytes:
        """Return digested bytes from the crypto digest."""
        return self._inner.digest()

    def hexdigest(self) -> str:
        """Return hexidecimal digested bytes from the crypto digest."""
        return self._inner.hexdigest()

    @classmethod
    def leaf(
        cls, data: Union[Buffer, str], *, name: Optional[str] = None
    ) -> "MrkleNode":
        """Create a leaf node from input data.

        Args:
            data: The input data buffer or string to hash for the leaf node.
            name: The digest algorithm name (default: "sha1").

        Returns:
            MrkleNode: A new leaf node containing the hashed value.

        Raises:
            ValueError: Raised when the digest algorithm is not supported.
            UnicodeEncodeError: Raised when string is not utf-8 supported.
        """
        if name is None:
            name = "sha1"

        if isinstance(data, str):
            buffer = data.encode("utf-8")
        elif isinstance(data, (bytes, bytearray)):
            buffer = bytes(data)
        elif isinstance(data, memoryview):
            buffer = data.tobytes()
        elif isinstance(data, array):
            buffer = data.tobytes()
        else:
            try:
                buffer = bytes(data)
            except (TypeError, ValueError) as e:
                raise TypeError(
                    f"Cannot convert {type(data).__name__} to bytes. "
                ) from e

        digest: Digest = new(name, data=buffer)
        value = digest.finalize_reset()

        if inner := NODE_MAP.get(name.lower()):
            node: Node_T = inner.leaf_with_digest(buffer, value)
            return cls.construct_from_node(node)
        else:
            raise ValueError(
                f"{name} is not digested that a supported with in MrkleNode."
            )

    def is_leaf(self) -> bool:
        """Check whether this node is a leaf node.

        Returns:
            bool: True if the node is a leaf, False otherwise.
        """
        return self._inner.is_leaf()

    def dtype(self) -> Digest:
        """Return the digest object used."""
        return new(self._dtype_name)

    @override
    def __setattr__(self, name: str, value: object) -> None:
        """Prevent setting attributes to enforce immutability.

        Raises:
            AttributeError: Always, since MrkleNode objects are immutable.
        """
        if name in {"_inner", "_dtype_name"}:
            if getattr(self, name, None) is None:
                object.__setattr__(self, name, value)
                return
            raise AttributeError(f"{name!r} is immutable once set")

        raise AttributeError(f"{self.__class__.__name__!r} objects are immutable")

    @override
    def __delattr__(self, name: str) -> None:
        """Prevent deleting attributes to enforce immutability.

        Raises:
            AttributeError: Always, since MrkleNode objects are immutable.
        """
        raise AttributeError(f"{repr(self)} objects are immutable")

    @override
    def __repr__(self) -> str:
        """Return the canonical string representation of the node.

        Returns:
            str: Representation including the digest type and object id.
        """
        return f"<{self._dtype_name} mrkle.tree.MrkleNode object at {hex(id(self))}>"

    @override
    def __str__(self) -> str:
        """Return a human-readable string representation of the node.

        Returns:
            str: Basic repersentation of MrkleNode.
        """
        id: str = self._inner.hexdigest()
        return (
            f"MrkleNode(id={id[0 : min(len(id), 4)]}, "
            f"leaf={self.is_leaf()}, dtype={self._dtype_name})"
        )

    @override
    def __eq__(self, other: object) -> bool:
        """Check equality between two MrkleNode instances.

        Args:
            other (object): Another object to compare.

        Returns:
            bool: True if `other` is a MrkleNode with the same underlying node.
        """
        if not isinstance(other, MrkleNode):
            return NotImplemented
        if type(self._inner) is not type(other._inner):
            return False
        return self._inner == other._inner

    @override
    def __hash__(self) -> int:
        """Compute the hash of the node for use in sets or dict keys."""
        return hash(self.digest())
