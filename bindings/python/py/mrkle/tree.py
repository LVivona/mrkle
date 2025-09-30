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
from mrkle.typing import D as _D, Buffer, SLOT_T
from mrkle.iter import MrkleTreeIter
from mrkle.node import MrkleNode
from mrkle.proof import MrkleProof
from mrkle._tree import TreeT as _TreeT, TREE_MAP

__all__ = ["MrkleTree"]


class MrkleTree(Generic[_D]):
    """A generic Merkle tree.

    This class provides an immutable Python interface for Merkle trees
    with a specific digest algorithm. Users should **not** instantiate trees
    directly; instead, use the `from_leaves` class method to construct a tree
    from leaf data with the appropriate digest.

    Attributes:
        _inner (TreeT): The underlying Rust-based Merkle tree instance.
        _dtype (Digest): The digest algorithm instance used by this tree.

    Type Parameters:
        _D: Digest type used for hashing (e.g., Sha1, Sha256).

    Examples:
        >>> from mrkle.tree import MrkleTree
        >>> tree = MrkleTree.from_leaves([b"data1", b"data2"], name="sha256")
        >>> tree.root()
        'a1b2c3d4...'
        >>> len(tree)
        3
    """

    _inner: _TreeT
    _dtype: _D

    __slots__: SLOT_T = ("_inner", "_dtype")

    def __init__(self, tree: _TreeT) -> None:
        """Initialize a MrkleTree instance.

        Warning:
            Users should not call this constructor directly. Use the
            `from_leaves` class method instead.

        Args:
            tree (TreeT): The underlying Rust-based tree instance.

        Raises:
            TypeError: If instantiated directly by users.
        """
        self._inner = tree
        self._dtype = tree.dtype()

    def root(self) -> str:
        """Return the root hash as a hexadecimal string.

        Returns:
            str: The hexadecimal representation of the root hash.

        Examples:
            >>> tree = MrkleTree.from_leaves([b"a", b"b"])
            >>> root = tree.root()
            >>> isinstance(root, str)
            True
        """
        return self._inner.root()

    def leaves(self) -> list[MrkleNode[_D]]:
        """Return a list of all leaf nodes in the tree.

        Returns:
            list[MrkleNode[_D]]: A list containing all leaf nodes with the
                same digest type as the tree.

        Examples:
            >>> tree = MrkleTree.from_leaves([b"a", b"b", b"c"])
            >>> leaves = tree.leaves()
            >>> len(leaves)
            3
            >>> all(leaf.is_leaf() for leaf in leaves)
            True
        """
        return list(
            map(
                lambda x: MrkleNode._construct_from_node_t(x),
                self._inner.leaves(),
            )
        )

    def dtype(self) -> _D:
        """Return the digest type used by this tree.

        Returns:
            _D: The digest algorithm instance (e.g., Sha1(), Sha256()).

        Examples:
            >>> tree = MrkleTree.from_leaves([b"data"], name="sha256")
            >>> digest = tree.dtype()
            >>> digest.name()
            'sha256'
        """
        return self._dtype

    def _capacity(self) -> int:
        """Return the allocation capacity of the internal tree structure.

        This is an internal method that exposes the underlying vector capacity
        of the Rust-based tree structure.

        Returns:
            int: The current capacity of the internal tree storage.
        """
        return self._inner.capacity()

    @classmethod
    def from_leaves(
        cls, leaves: list[Union[str, Buffer]], *, name: Optional[str] = None
    ) -> "MrkleTree[_D]":
        """Construct a Merkle tree from a list of leaf data.

        This is the basic way to create a MrkleTree instance. The method
        creates leaf nodes from the provided data, hashes them using the
        specified digest algorithm, and constructs a complete Merkle tree.

        Args:
            leaves (list[Union[str, Buffer]]): A list of data to be used as
                leaf nodes. Strings will be UTF-8 encoded to bytes.
            name (Optional[str], optional): The digest algorithm name
                (e.g., "sha1", "sha256", "blake2b"). Defaults to "sha1".

        Returns:
            MrkleTree[_D]: A new Merkle tree instance containing the provided
                leaves hashed with the specified digest algorithm.

        Raises:
            ValueError: If the digest algorithm name is not supported.

        Examples:
            >>> # Create tree with default SHA-1
            >>> tree = MrkleTree.from_leaves([b"a", b"b", b"c"])
            >>>
            >>> # Create tree with SHA-256
            >>> tree = MrkleTree.from_leaves(["data1", "data2"], name="sha256")
            >>>
            >>> # Create tree with BLAKE2b
            >>> tree = MrkleTree.from_leaves([b"x", b"y"], name="blake2b")
        """
        if name is None:
            name = "sha1"
        digest = new(name)
        name = digest.name()

        buffer: list[bytes] = [
            leaf.encode("utf-8") if isinstance(leaf, str) else bytes(leaf)
            for leaf in leaves
        ]

        if inner := TREE_MAP.get(name):
            return cls._construct_tree_backend(inner.from_leaves(buffer), digest)
        else:
            raise ValueError(
                f"{name} is not a digest algorithm supported by MrkleTree."
            )

    def generate_proof(self, leaves: Set[MrkleNode[_D]]) -> "MrkleProof[_D]":
        """Generate a Merkle proof for the specified leaf nodes.

        Args:
            leaves (Set[MrkleNode[_D]]): A set of leaf nodes to generate
                a proof for.

        Returns:
            MrkleProof[_D]: A Merkle proof object that can verify the
                inclusion of the specified leaves in this tree.

        Examples:
            >>> tree = MrkleTree.from_leaves([b"a", b"b", b"c"])
            >>> leaf = tree.leaves()[0]
            >>> proof = tree.generate_proof({leaf})
        """
        return MrkleProof(self._inner, leaves)

    def to_string(self) -> str:
        """pretty print of MrkleTree.

        Returns:
           str: A pretty print string of a tree.

        Examples:
            >>> tree = MrkleTree.from_leaves([b"a", b"b", b"c"])
            >>> print(tree.to_string())
            f6a9...50e0
            +-- 84a5...dbb4
            '-- 0056...0f34
                +-- 86f7...67b8
                '-- e9d7...8f98
        """
        return self._inner.to_string()

    to_str = to_string

    @classmethod
    def _construct_tree_backend(cls, tree: _TreeT, dtype: Digest) -> "MrkleTree[_D]":
        """Internal method to create a MrkleTree instance bypassing __init__.

        This method is used internally to construct tree instances with
        pre-validated components, avoiding the normal initialization path.

        Args:
            tree (TreeT): The underlying Rust-based tree instance.
            dtype (Digest): The digest algorithm instance.

        Returns:
            MrkleTree[_D]: A new tree instance wrapping the given components.

        Raises:
            AssertionError: If the tree's digest type doesn't match the
                provided digest type.
        """
        assert tree.dtype() == dtype, (
            f"Mismatch: {tree.dtype()!s} does not match {dtype!s}"
        )
        obj = object.__new__(cls)
        object.__setattr__(obj, "_inner", tree)
        object.__setattr__(obj, "_dtype", dtype)
        return obj

    def _internal(self) -> _TreeT:
        """Return the internal Rust-based tree instance.

        This is an internal method for accessing the underlying tree structure.

        Returns:
            TreeT: The wrapped Rust tree instance.
        """
        return self._inner

    @overload
    def __getitem__(self, key: slice) -> list[MrkleNode[_D]]: ...

    @overload
    def __getitem__(self, key: Sequence[int]) -> list[MrkleNode[_D]]: ...

    def __getitem__(self, key: Union[int, slice, Sequence[int]]) -> list[MrkleNode[_D]]:
        """Access nodes by index, slice, or sequence of indices.

        Args:
            key (Union[int, slice, Sequence[int]]): The index specification.

        Returns:
            list[MrkleNode[_D]]: A list of nodes at the specified indices.

        Raises:
            TypeError: If the key type is invalid.

        Note:
            This method is not yet fully implemented.
        """
        if isinstance(key, int):
            return list()
        elif isinstance(key, slice):
            return list()
        elif isinstance(key, Sequence):
            return list()
        else:
            raise TypeError(f"Invalid index type: {type(key)}")

    def __iter__(self) -> "MrkleTreeIter[_D]":
        """Return an iterator over all nodes in the tree.

        The iteration is performed in breadth-first order.

        Returns:
            MrkleTreeIter[_D]: An iterator over tree nodes.

        Examples:
            >>> tree = MrkleTree.from_leaves([b"a", b"b"])
            >>> for node in tree:
            ...     print(node.hexdigest())
        """
        return MrkleTreeIter.from_tree(self._inner, self._dtype)

    def __eq__(self, other: object) -> bool:
        """Check equality between two MrkleTree instances.

        Two trees are equal if they use the same digest algorithm and have
        identical internal tree structures.

        Args:
            other (object): Another object to compare.

        Returns:
            bool: True if both trees are equal, False otherwise.
            NotImplemented: If other is not a MrkleTree instance.

        Examples:
            >>> tree1 = MrkleTree.from_leaves([b"a", b"b"])
            >>> tree2 = MrkleTree.from_leaves([b"a", b"b"])
            >>> tree1 == tree2
            True
        """
        if not isinstance(other, MrkleTree):
            return NotImplemented

        if self.dtype() != other.dtype():
            return False

        return self._inner == other._inner

    def __len__(self) -> int:
        """Return the total number of nodes in the tree.

        Returns:
            int: The count of all nodes (leaves and internal nodes).

        Examples:
            >>> tree = MrkleTree.from_leaves([b"a", b"b"])
            >>> len(tree)
            3
        """
        return len(self._inner)

    def __hash__(self) -> int:
        """Compute the hash of the tree for use in sets or dict keys.

        Returns:
            int: The hash value of the tree.
        """
        return hash((type(self._inner), self._inner))

    def __repr__(self) -> str:
        """Return the canonical string representation of the tree.

        Returns:
            str: Representation including the digest type and object id.

        Examples:
            >>> tree = MrkleTree.from_leaves([b"a"], name="sha256")
            >>> repr(tree)
            '<sha256 mrkle.tree.MrkleTree object at 0x...>'
        """
        return f"<{self._dtype.name()} mrkle.tree.MrkleTree object at {hex(id(self))}>"

    def __str__(self) -> str:
        """Return a human-readable string representation of the tree.

        Returns:
            str: Basic representation showing root hash prefix, length,
                and digest type.

        Examples:
            >>> tree = MrkleTree.from_leaves([b"a", b"b"])
            >>> str(tree)
            'MrkleTree(root=a1b2, length=3, dtype=Sha1())'
        """
        root: str = self._inner.root()
        return (
            f"MrkleTree(root={root[0 : min(len(root), 4)]},"
            f" length={len(self)}, dtype={self._dtype!s})"
        )

    def __format__(self, format_spec: str, /) -> str:
        """Format the tree according to the given format specification.

        Args:
            format_spec (str): The format specification string.

        Returns:
            str: The formatted string representation.
        """
        return super().__format__(format_spec)


Tree: TypeAlias = MrkleTree[_D]
