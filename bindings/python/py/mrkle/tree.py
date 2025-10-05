from __future__ import annotations

from collections.abc import Sequence, Iterable
from typing import (
    Any,
    Generic,
    Literal,
    Union,
    Optional,
    final,
    overload,
)
from typing_extensions import TypeAlias, override

from mrkle.crypto import new
from mrkle.crypto.typing import Digest

from mrkle.utils import unflatten
from mrkle.typing import D as _D, Buffer, SLOT_T

from mrkle.iter import MrkleTreeIter
from mrkle.node import MrkleNode

from mrkle.errors import MerkleError, ProofError, SerdeError, TreeError

from mrkle._proof import Proof_T, PROOF_MAP
from mrkle._tree import Node_T, Tree_T, TREE_MAP


__all__ = ["MrkleTree", "MrkleProof", "Tree"]


@final
class MrkleTree(Generic[_D]):
    """A generic Merkle tree.

    This class provides an immutable Python interface for Merkle trees
    with a specific digest algorithm. Users should not instantiate trees
    directly; instead, use the `from_leaves` class method to construct a tree
    from leaf data with the appropriate digest.

    Attributes:
        _inner (TreeT): The underlying Rust-based Merkle tree instance.
        _dtype (Digest): The digest algorithm instance used by this tree.

    Examples:
        >>> from mrkle.tree import MrkleTree
        >>> tree = MrkleTree.from_leaves([b"data1", b"data2"], name="sha256")
        >>> tree.root().hex()
        '5b6d4b08...'
        >>> len(tree)
        3
    """

    _inner: Tree_T
    _dtype: Digest
    __slots__: SLOT_T = ("_inner", "_dtype")

    def __init__(self, tree: Tree_T) -> None:
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

    def root(self) -> Optional[bytes]:
        """Return the root hash as a hexadecimal string.

        Returns:
            bytes: The bytes of the root hash.

        Examples:
            >>> tree = MrkleTree.from_leaves([b"a", b"b"])
            >>> root = tree.root()
            >>> isinstance(root, bytes)
            True
            >>>
            >>> tree = MrkleTree.from_leaves([])
            >>> tree.root()
            >>> tree.is_empty()
        """
        try:
            return self._inner.root()
        except TreeError:
            return None

    def leaves(self) -> list["MrkleNode[_D]"]:
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
                self._construct_mrkle_node,
                self._inner.leaves(),
            )
        )

    @staticmethod
    def _construct_mrkle_node(inner: Node_T) -> "MrkleNode[_D]":
        return MrkleNode.construct_from_node(inner)

    def is_empty(self) -> bool:
        """Return if the MrkleTree is empty."""
        return self._inner.is_empty()

    def dtype(self) -> Digest:
        """Return the digest type used by this tree.

        Returns:
            Digest: The digest algorithm instance (e.g., Sha1(), Sha256()).

        Examples:
            >>> tree = MrkleTree.from_leaves([b"data"], name="sha256")
            >>> digest = tree.dtype()
            >>> digest.name()
            'sha256'
        """
        return self._dtype

    def capacity(self) -> int:
        """Return the allocation capacity of the internal tree structure.

        This is an internal method that exposes the underlying vector capacity
        of the Rust-based tree structure.

        Returns:
            int: The current capacity of the internal tree storage.
        """
        return self._inner.capacity()

    @classmethod
    def from_leaves(
        cls, leaves: Sequence[Union[Buffer, str]], *, name: Optional[str] = None
    ) -> "MrkleTree[_D]":
        """Construct a Merkle tree from a list of leaf data.

        This is the basic way to create a MrkleTree instance. The method
        creates leaf nodes from the provided data, hashes them using the
        specified digest algorithm, and constructs a complete Merkle tree.

        Args:
            leaves (Sequence[Union[Buffer, str]]): A list of data to be used as
                leaf nodes. Strings will be UTF-8 encoded to bytes.
            name (Optional[str], optional): The digest algorithm name
                (e.g., "sha1", "sha256", "blake2b"). Defaults to "sha1".

        Returns:
            MrkleTree[_D]: A new Merkle tree instance containing the provided
                leaves hashed with the specified digest algorithm.

        Raises:
            ValueError: If the digest algorithm name is not supported.
            AssertionError: If the tree's digest type doesn't match the
                provided digest type.

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

        if inner := TREE_MAP.get(name):
            return cls._construct_tree_backend(inner.from_leaves(leaves), digest)
        else:
            raise ValueError(
                f"{name} is not a digest algorithm supported by MrkleTree."
            )

    def generate_proof(
        self,
        leaves: Union[int, Iterable[int]],
    ) -> "MrkleProof[_D]":
        """Generate a Merkle proof for the specified leaf nodes.

        Args:
            leaves (Set[MrkleNode[_D]]): A set of leaf nodes to generate
                a proof for.

        Returns:
            MrkleProof[_D]: A Merkle proof object that can verify the
                inclusion of the specified leaves in this tree.

        Examples:
            >>> tree = MrkleTree.from_leaves([b"a", b"b", b"c"])
            >>> proof = tree.generate_proof([0])
        """
        return MrkleProof.generate(self, leaves)

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
    def loads(
        cls,
        data: Union[str, bytes],
        name: Optional[str] = None,
        *,
        encoding: Optional[Literal["json", "cbor"]] = None,
    ) -> "MrkleTree[_D]":
        """Deserialize a tree from string (JSON) or bytes (CBOR).

        Args:
            data: Serialized tree data (str for JSON, bytes for CBOR).
            encoding: Serialization format used. Defaults to "cbor".

        Returns:
            MrkleTree[_D]: Deserialized tree instance.

        Raised:
            ValueError: Raised when the specified digest algorithm is not
            recognized in the default registry.

        Examples:
            >>> tree = MrkleTree.from_leaves([b"a", b"b"], name="sha256")
            >>> data = tree.dumps(encoding="json")
            >>> restored = MrkleTree.loads(data, encoding="json")
            >>> restored == tree
            True

        """

        if name is None:
            return cls._find_loads(data, encoding=encoding)
        else:
            if tree := TREE_MAP.get(name):
                return MrkleTree(tree.loads(data, encoding=encoding))
            else:
                raise ValueError(
                    f"{name} is not a digest algorithm supported by MrkleTree."
                )

    def dumps(
        self,
        encoding: Optional[Literal["json", "cbor"]] = None,
    ) -> Union[str, bytes]:
        """Serialize the tree to string (JSON) or bytes (CBOR).

        Args:
            encoding: Serialization format - "json" returns str, "cbor" returns bytes.
            Defaults to "cbor".

        Returns:
            Union[str, bytes]: Serialized tree data.

        Examples:
            >>> tree = MrkleTree.from_leaves([b"a", b"b"], name="sha256")
            >>> json_str = tree.dumps(encoding="json")
            >>> cbor_bytes = tree.dumps(encoding="cbor")
            >>> cbor_default = tree.dumps()  # Uses CBOR by default
        """
        return self._inner.dumps(encoding=encoding)

    to_str = to_string

    @classmethod
    def from_dict(
        cls,
        data: dict[str, Any],
        name: Optional[str] = None,
        *,
        fmt: Literal["flatten", "nested"] = "nested",
    ) -> "MrkleTree[_D]":
        """Construct a MrkleTree from a dict.

        Returns:
            MrkleTree[_D]: A new tree instance built from the given dictionary data.

        Raised:
            ValueError: Raised when the specified digest algorithm is not
            recognized in the default registry.
            AssertionError: If the tree's digest type doesn't match the
            provided digest type.

        # Example
            >>> from mrkle import MrkleTree
            >>> data = { "a.a" : b"let", "a.b" : b"a", "a.c.b" : b"=", "a.c.a" : b"1" }
            >>> tree = MrkleTree.from_dict(data, fmt="flatten")
            >>> tree.root().hex()
            '34e31fe4180705565b3bb314ad56a3f513616e29'
        """
        if name is None:
            name = "sha1"
        digest = new(name)
        name = digest.name()

        # NOTE: need to test between rust impl
        # and python impl to see if there is
        # some speed improvments in speed
        # handling it \w in rust runtime.
        if fmt == "flatten":
            data = unflatten(data)

        if inner := TREE_MAP.get(name):
            return cls._construct_tree_backend(inner.from_dict(data=data), digest)
        else:
            raise ValueError(
                f"{name} is not a digest algorithm supported by MrkleTree."
            )

    @classmethod
    def _construct_tree_backend(cls, tree: Tree_T, dtype: Digest) -> "MrkleTree[_D]":
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

    @classmethod
    def _find_loads(
        cls,
        data: Union[str, bytes],
        encoding: Optional[Literal["json", "cbor"]] = None,
    ) -> "MrkleTree[_D]":
        """Internal method to find the correct tree type and deserialize.

        Args:
            data: Serialized tree data.
            encoding: Serialization format used.

        Returns:
            MrkleTree[_D]: Deserialized tree instance.

        Raises:
            SerdeError: If deserialization fails for all tree types.
            AssertionError: If the tree’s digest type doesn’t match the
            provided digest type.
        """

        for name, tree in TREE_MAP.items():
            try:
                inner = tree.loads(data, encoding=encoding)
                digest = new(name)
                return cls._construct_tree_backend(inner, digest)
            except AssertionError as e:
                # NOTE: this only should thrown when the
                # construct does not match the inner backend
                # for example MrkleNodeSha1, and dtype sha224.
                raise e
            except MerkleError:
                # NOTE: MrkleError abstract over the SerdeError thrown
                # we ignore until a possible match. else we raise
                # our serde.
                continue

        raise SerdeError("Could not deserialize tree from given data.")

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
            TypeError: Rasied if the key type is invalid.
            IndexError: Rasied with key is out of range.

        """
        return self._inner[key]

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

    @override
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

    @override
    def __hash__(self) -> int:
        """Compute the hash of the tree for use in sets or dict keys.

        Returns:
            int: The hash value of the tree.
        """
        return hash((type(self._inner), self.root()))

    @override
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

    @override
    def __str__(self) -> str:
        """Return a human-readable string representation of the tree.

        Returns:
            str: Basic representation showing root hash prefix, length,
                and digest type.

        Examples:
            >>> tree = MrkleTree.from_leaves([b"a", b"b"])
            >>> str(tree)
            'MrkleTree(root=0056, length=3, dtype=Sha1())'
        """
        root: str = self._inner.root().hex()
        return (
            f"MrkleTree(root={root[0 : min(len(root), 4)]},"
            f" length={len(self)}, dtype={self._dtype!s})"
        )

    @override
    def __format__(self, format_spec: str, /) -> str:
        """Format the tree according to the given format specification.

        Args:
            format_spec (str): The format specification string.

        Returns:
            str: The formatted string representation.
        """
        return super().__format__(format_spec)


@final
class MrkleProof(Generic[_D]):
    """A generic Merkle proof.

    Provides utilities to create and verify Merkle proofs. A Merkle
    proof demonstrates that a given leaf node is part of a Merkle tree with a
    known root hash. Proofs are typically represented as a sequence of sibling
    hashes from the leaf up to the root.

    Example:
        >>> from mrkle.tree import MrkleTree
        >>> from mrkle.proof import MerkleProof
        >>> leaves = [b'leaf1', b'leaf2', b'leaf3']
        >>> tree = MrkleTree.from_leaves(leaves)
        >>> proof = tree.generate_proof([0])
        >>> str(proof)
        'MrkleProof(expected=70a6, length=5, dtype=Sha1())'

    """

    _inner: Proof_T
    _dtype: Digest

    __slots__: SLOT_T = ("_inner", "_dtype")

    def __init__(self, proof: Proof_T) -> None:
        self._inner = proof
        self._dtype = proof.dtype()

    def expected(self) -> bytes:
        """Returns the expected hash of the proof."""
        return self._inner.expected()

    def expected_hexdigest(self) -> str:
        """Returns the expected hexadecimal hash of the proof."""
        return self._inner.expected_hexdigest()

    @classmethod
    def generate(
        cls, tree: "MrkleTree[_D]", leaves: Union[int, Iterable[int]]
    ) -> "MrkleProof[_D]":
        """Generate MrkleProof from MrkleTree, and leaf index."""
        name = tree.dtype().name()
        proof = PROOF_MAP.get(name)
        if proof is None:
            raise ValueError(
                f"{name!r} is not a digest algorithm supported by MrkleTree."
            )

        if isinstance(leaves, int):
            leaf_indices = [leaves]
        else:
            leaf_indices = list(leaves)

        return cls(proof.generate(tree, leaf_indices))

    def update(self, leaves: Union[bytes, list[bytes], str, list[str]]) -> None:
        """Update the proof with new leaf values.

        Args:
            leaves: A single leaf (bytes or hex str) or a list of leaves.

        Examples:
            >>> tree = MrkleTree.from_leaves([b"a", b"b"])
            >>> proof = tree.generate_proof([0])
            >>> leaf = tree.leaves()[0]
            >>> proof.update(leaf.digest())
            >>> proof.validate()
            True
        """
        self._inner.update(leaves)

    def validate(self) -> bool:
        """Validate this proof against a given root hash.

        Returns:
            bool: True if the proof is valid, False otherwise.

        Examples:
            >>> tree = MrkleTree.from_leaves([b"a", b"b"], name="sha256")
            >>> proof = tree.generate_proof([0])
            >>> leaf = tree.leaves()[1]
            >>> proof.update(leaf.digest())
            >>> proof.validate()
            False
            >>> proof.refresh()
            >>> leaf = tree.leaves()[0]
            >>> proof.update(leaf.digest())
            >>> proof.validate()
            True

        """
        return self._inner.validate()

    def try_validate(self) -> bool:
        """Validate this proof against a given root hash, return exception if false."""
        try:
            return self._inner.try_validate()
        except ProofError as e:
            raise e

    def refresh(self) -> None:
        """Reset this proof."""
        return self._inner.refresh()

    def dtype(self) -> Digest:
        """Return the digest type used by this tree.

        Returns:
            Digest: The digest algorithm instance (e.g., Sha1(), Sha256()).
        """
        return self._dtype

    def to_string(self) -> str:
        """Pretty print of MrkleProof.

        Returns:
           str: A pretty print string of a tree.

        """
        return self._inner.to_string()

    to_str = to_string

    def dumps(
        self,
        encoding: Optional[Literal["json", "cbor"]] = None,
        **kwargs: dict[str, Any],
    ) -> Union[str, bytes]:
        """Serialize a tree into json string or cbor bytes.

        Args:
            encoding: Serialization format used. Defaults to "cbor".

        Raises:
            ValueError: Raised when unable to convert into proper encoding type.
            SerdeError: Raised when the data cannot be deserialized into a valid object.
        """
        return self._inner.dumps(encoding=encoding, **kwargs)

    @classmethod
    def loads(
        cls,
        data: Union[str, bytes],
        encoding: Optional[Literal["json", "cbor"]] = None,
        *,
        name: Optional[str] = None,
    ) -> "MrkleProof[_D]":
        """Deserialize a tree from string (JSON) or bytes (CBOR).

        Args:
            data: Serialized tree data (str for JSON, bytes for CBOR).
            encoding: Serialization format used. Defaults to "cbor".

        Returns:
            MrkleProof[_D]: Deserialized merkle proof tree instance.

        Raises:
            ValueError: Raised when unable to convert into proper encoding type.
            SerdeError: Raised when the data cannot be deserialized into a valid object.

        Examples:
            >>> tree = MrkleTree.from_leaves([b"a", b"b"], name="sha256")
            >>> data = tree.dumps(encoding="json")
            >>> restored = MrkleTree.loads(data, encoding="json")
            >>> restored == tree
            True
        """

        if name is None:
            return cls._find_loads(data, encoding=encoding)
        else:
            if tree := PROOF_MAP.get(name):
                return MrkleProof(tree.loads(data, encoding=encoding))
            else:
                raise ValueError(
                    f"{name} is not a digest algorithm supported by MrkleTree."
                )

    @classmethod
    def _find_loads(
        cls,
        data: Union[str, bytes],
        encoding: Optional[Literal["json", "cbor"]] = None,
    ) -> "MrkleProof[_D]":
        """Internal method to find the correct tree type and deserialize.

        Args:
            data: Serialized tree data.
            encoding: Serialization format used.

        Returns:
            MrkleProof[_D]: Deserialized tree instance.

        Raises:
            SerdeError: Raised when deserialization fails for all tree types.
        """

        for _, tree in PROOF_MAP.items():
            try:
                inner = tree.loads(data, encoding=encoding)
                return cls(inner)
            except SerdeError:
                continue

        raise SerdeError("Could not deserialize tree from given data.")

    def __len__(self) -> int:
        return len(self._inner)

    @override
    def __repr__(self) -> str:
        """Return the canonical string representation of the tree.

        Returns:
            str: Representation including the digest type and object id.

        Examples:
            >>> tree = MrkleTree.from_leaves([b"a"], name="sha256")
            >>> repr(tree)
            '<sha256 mrkle.tree.MrkleTree object at 0x...>'
        """
        return f"<{self._dtype.name()} mrkle.tree.MrkleProof object at {hex(id(self))}>"

    @override
    def __str__(self) -> str:
        """Return a human-readable string representation of the tree.

        Returns:
            str: Basic representation showing root hash prefix, length,
                and digest type.

        Examples:
            >>> tree = MrkleTree.from_leaves([b"a", b"b"])
            >>> leaf = tree.leaves()[0]
            >>> proof = tree.generate_proof([0])
            >>> str(tree)
            'MrkleProof(root=ce7a, length=3, dtype=Sha1())'
        """

        root: str = self._inner.expected_hexdigest()
        return (
            f"MrkleProof(expected={root[0 : min(len(root), 4)]},"
            f" length={len(self)}, dtype={self._dtype!s})"
        )

    @override
    def __format__(self, format_spec: str, /) -> str:
        """Format the tree according to the given format specification.

        Args:
            format_spec (str): The format specification string.

        Returns:
            str: The formatted string representation.
        """
        return super().__format__(format_spec)


Tree: TypeAlias = MrkleTree[_D]
