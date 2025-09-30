from __future__ import annotations

from mrkle.crypto import new
from mrkle.crypto.typing import Digest
from mrkle.typing import D as _D, Buffer, SLOT_T as _SLOT_T
from mrkle._tree import NodeT as _NodeT, NODE_MAP

from typing import Generic, Union, Optional, overload, cast


__all__ = ["MrkleNode"]


class MrkleNode(Generic[_D]):
    """A generic Merkle tree node.

    This class provides an immutable Python interface for Merkle tree nodes
    with a specific digest algorithm. Users should **not** instantiate nodes
    directly; instead, use the `leaf` class method to create leaf nodes with
    the appropriate digest.

    Attributes:
        _inner (Node): The underlying Rust-based Merkle node instance.
        _dtype (str): The name of the digest algorithm used by this node.

    Type Parameters:
        D: Digest type used for hashing (e.g., Sha1, Sha256).
    """

    _inner: _NodeT
    _dtype: str
    __slots__: _SLOT_T = ("_inner", "_dtype")

    def __init__(self, node: _NodeT) -> None:
        raise TypeError(
            f"Cannot instantiate {self.__class__.__name__} directly. "
            "Use MrkleNode.leaf(...) to create leaf nodes."
        )

    @classmethod
    def _construct_from_node_t(cls, node: _NodeT) -> "MrkleNode[_D]":
        dtype: Digest = node.dtype()
        obj = object.__new__(cls)
        object.__setattr__(obj, "_inner", node)
        object.__setattr__(obj, "_dtype", dtype.name())
        return obj

    @classmethod
    def __construct_node_backend(cls, node: _NodeT, dtype: Digest) -> "MrkleNode[_D]":
        """Internal method to create a MrkleNode instance bypassing __init__.

        Args:
            inner (Node): The Rust-based Merkle node.
            digest (_D): The digest object used for this node.

        Returns:
            MrkleNode[_D]: A new instance wrapping the given inner node.
        """
        assert node.dtype() == dtype, (
            f"Missmatch {node.dtype():!s} does not match {dtype:!s}"
        )
        obj = object.__new__(cls)
        object.__setattr__(obj, "_inner", node)
        object.__setattr__(obj, "_dtype", dtype.name())
        return obj

    def digest(self) -> bytes:
        """Return digested bytes from the crypto digest."""
        return self._inner.digest()

    def hexdigest(self) -> str:
        """Return hexidecimal digested bytes from the crypto digest."""
        return self._inner.hexdigest()

    @classmethod
    @overload
    def leaf(cls, data: str) -> "MrkleNode[_D]": ...

    @classmethod
    @overload
    def leaf(cls, data: str, *, name: Optional[str] = None) -> "MrkleNode[_D]": ...

    @classmethod
    @overload
    def leaf(cls, data: bytes) -> "MrkleNode[_D]": ...

    @classmethod
    @overload
    def leaf(cls, data: bytes, *, name: Optional[str] = None) -> "MrkleNode[_D]": ...

    @classmethod
    @overload
    def leaf(cls, data: Buffer) -> "MrkleNode[_D]": ...

    @classmethod
    @overload
    def leaf(cls, data: Buffer, *, name: Optional[str] = None) -> "MrkleNode[_D]": ...

    @classmethod
    def leaf(
        cls, data: Union[str, bytes, Buffer], *, name: Optional[str] = None
    ) -> "MrkleNode[_D]":
        """Create a leaf node from input data.

        Args:
            data (T): The input data buffer to hash for the leaf node.
            name (Optional[str]): The digest algorithm name (default: "sha1").

        Returns:
            MrkleNode[_D]: A new leaf node containing the hashed value.

        Raises:
            ValueError: If the digest algorithm is not supported.
        """
        if name is None:
            name = "sha1"

        if isinstance(data, str):
            buffer = bytes(data.encode("utf-8"))
        elif isinstance(data, Buffer):
            buffer = bytes(data)
        else:
            buffer = data

        digest: Digest = new(name, data=buffer)
        value = digest.finalize_reset()

        if inner := NODE_MAP.get(name.lower()):
            node: _NodeT = inner.leaf_with_digest(buffer, value)
            return cls.__construct_node_backend(node, digest)
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

    def dtype(self) -> _D:
        """Return the digest object used."""
        return cast(_D, new(self._dtype))

    def __setattr__(self, name: str, value) -> None:
        """Prevent setting attributes to enforce immutability.

        Raises:
            AttributeError: Always, since MrkleNode objects are immutable.
        """

        raise AttributeError(f"{repr(self)} objects are immutable")

    def __delattr__(self, name: str) -> None:
        """Prevent deleting attributes to enforce immutability.

        Raises:
            AttributeError: Always, since MrkleNode objects are immutable.
        """
        raise AttributeError(f"{repr(self)} objects are immutable")

    def __repr__(self) -> str:
        """Return the canonical string representation of the node.

        Returns:
            str: Representation including the digest type and object id.
        """
        return f"<{self._dtype} mrkle.tree.MrkleNode object at {hex(id(self))}>"

    def __str__(self) -> str:
        """Return a human-readable string representation of the node.

        Returns:
            str: Basic repersentation of MrkleNode.
        """
        id: str = self._inner.hexdigest()
        return (
            f"MrkleNode(id={id[0 : min(len(id), 4)]}, "
            f"leaf={self.is_leaf()}, dtype={self._dtype.capitalize()}())"
        )

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

    def __hash__(self) -> int:
        """Compute the hash of the node for use in sets or dict keys."""
        return hash(self.digest())
