from __future__ import annotations
from mrkle.crypto import new
from mrkle.typing import _D, Buffer, _NodeT

from mrkle._mrkle_rs import tree

from typing import (
    Generic,
    Union,
    Optional,
    Type,
    Dict,
    overload,
)
from typing_extensions import TypeAlias

_NODE_MAP: Dict[str, Type[_NodeT]] = {
    "blake2s": tree.MrkleNodeBlake2s,
    "blake2b": tree.MrkleNodeBlake2b,
    "keccak224": tree.MrkleNodeKeccak224,
    "keccak256": tree.MrkleNodeKeccak256,
    "keccak384": tree.MrkleNodeKeccak384,
    "keccak512": tree.MrkleNodeKeccak512,
    "sha1": tree.MrkleNodeSha1,
    "sha224": tree.MrkleNodeSha224,
    "sha256": tree.MrkleNodeSha256,
    "sha384": tree.MrkleNodeSha384,
    "sha512": tree.MrkleNodeSha512,
}

class MrkleNode(Generic[_D]):
    """A generic Merkle tree node.

    This class provides an immutable Python interface for Merkle tree nodes
    with a specific digest algorithm. Users should **not** instantiate nodes
    directly; instead, use the `leaf` class method to create leaf nodes with
    the appropriate digest.

    Attributes:
        _inner (Node): The underlying Rust-based Merkle node instance.
        _digest (str): The name of the digest algorithm used by this node.

    Type Parameters:
        D: Digest type used for hashing (e.g., Sha1, Sha256).
    """

    __slots__ = ("_inner", "_digest")

    def __init__(self, *args, **kwargs) -> None:
        """Prevent direct instantiation.

        Raises:
            TypeError: Always, since users must use `leaf` to create nodes.
        """
        raise TypeError(
            "Direct instantiation of MrkleNode is not allowed;"
            "use `leaf` instead."
        )

    @classmethod
    def _construct_node_backend(cls, inner: _NodeT, digest: _D) -> "MrkleNode[_D]":
        """Internal method to create a MrkleNode instance bypassing __init__.

        Args:
            inner (Node): The Rust-based Merkle node.
            digest (_D): The digest object used for this node.

        Returns:
            MrkleNode[_D]: A new instance wrapping the given inner node.
        """
        obj = object.__new__(cls)
        object.__setattr__(obj, "_inner", inner)
        object.__setattr__(obj, "_digest", digest.name())
        return obj

    @classmethod
    @overload
    def leaf(cls, data: str) -> "Node":
        ...

    @classmethod
    @overload
    def leaf(cls, data: str, *, name: Optional[str] = None) -> "Node":
        ...

    @classmethod
    @overload
    def leaf(cls, data: Buffer) -> "Node":
        ...

    @classmethod
    @overload
    def leaf(cls, data: Buffer, *, name: Optional[str] = None) -> "Node":
        ...

    @classmethod
    def leaf(
        cls, data: Union[str, Buffer], *, name: Optional[str] = None
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

        digest: _D = new(name)

        if isinstance(data, str):
            buffer = bytes(data.encode("utf-8"))
        else:
            buffer = bytes(data)

        name = digest.name()
        value = digest.digest(buffer)

        if inner := _NODE_MAP.get(name):
            return cls._construct_node_backend(
                inner.leaf_with_digest(buffer, value), digest
            )
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
        return new(self._digest)

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
        return (
            f"<{self._digest} mrkle.tree.MrkleNode"
            f" object at {hex(id(self))}>"
        )

    def __str__(self) -> str:
        """Return a human-readable string representation of the node.

        Returns:
            str: Basic repersentation of MrkleNode.
        """
        id : str = self._inner.hash()
        return f"MrkleNode(id={id[0:min(len(id), 4)]}, leaf={self.is_leaf()}, dtype={self._digest})"

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
        """Compute the hash of the node for use in sets or dict keys.
        """
        return hash((type(self._inner), self._inner))

Node: TypeAlias = MrkleNode[_D]
