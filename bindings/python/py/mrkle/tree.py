from __future__ import annotations

import json

from collections.abc import Iterator, Iterable, Sequence

from typing import (
    Any,
    Literal,
    Union,
    Optional,
    final,
    overload,
)
from typing_extensions import override

from mrkle.crypto import new
from mrkle.crypto.typing import Digest

from mrkle.utils import unflatten
from mrkle.typing import BufferLike as Buffer, File

from mrkle.iter import MrkleTreeIter
from mrkle.node import MrkleNode

from mrkle.errors import TreeError

from mrkle._proof import Proof_T, PROOF_MAP
from mrkle._tree import Node_T, Tree_T, TREE_MAP


__all__ = ["MrkleTree", "MrkleProof"]


@final
class MrkleTree:
    """A generic Merkle tree.

    This class provides an immutable Python interface for Merkle trees
    with a specific digest algorithm. Users should not instantiate trees
    directly; instead, use the `from_leaves` or `from_dict` class method
    to construct a tree from leaf data with the appropriate digest.

    Attributes:
        _inner (Tree_T): The underlying Rust-based Merkle tree instance.

    Examples:
        >>> from mrkle.tree import MrkleTree
        >>> tree = MrkleTree.from_leaves([b"data1", b"data2"], name="sha256")
        >>> tree.root().hex()
        '5b6d4b089e2331b3e00a803326df50cdc2df81c7df405abea149421df227640b'
        >>> len(tree)
        3
    """

    _inner: Tree_T
    __slots__ = "_inner"

    def __init__(self, tree: Tree_T) -> None:
        """Initialize a MrkleTree instance.

        Args:
            tree (Tree_T): The underlying Rust-based tree instance.

        """
        self._inner = tree

    def root(self) -> Optional[bytes]:
        """Return the root hash as bytes.

        Returns:
            Optional[bytes]: The root hash as bytes, or None if tree is empty.

        Examples:
            >>> tree = MrkleTree.from_leaves([b"a", b"b"])
            >>> root = tree.root()
            >>> isinstance(root, bytes)
            True

            >>> tree = MrkleTree.from_leaves([])
            >>> tree.root() is None
            True
            >>> tree.is_empty()
            True
        """
        try:
            return self._inner.root()
        except TreeError:
            return None

    def try_root(self) -> bytes:
        """Return the root hash as bytes.

        Returns:
            bytes: The root hash as bytes.

        Raises:
            TreeError: Raised when the tree is empty and has no root.

        Examples:
            >>> tree = MrkleTree.from_leaves([b"a", b"b"])
            >>> root = tree.try_root()
            >>> isinstance(root, bytes)
            True
        """
        return self._inner.root()

    def leaves(self) -> list["MrkleNode"]:
        """Return a list of all leaf nodes in the tree.

        Returns:
            list[MrkleNode]: A list containing all leaf nodes with the
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
    def _construct_mrkle_node(inner: Node_T) -> "MrkleNode":
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
        return self._inner.dtype()

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
        cls,
        leaves: Union[Sequence[Union[Buffer, str]], Iterator[Union[Buffer, str]]],
        name: Optional[str] = None,
    ) -> "MrkleTree":
        """Construct a Merkle tree from a list of leaf data.

        This is the basic way to create a MrkleTree instance. The method
        creates leaf nodes from the provided data, hashes them using the
        specified digest algorithm, and constructs a complete Merkle tree.

        Args:
            leaves (Union[Sequence[Union[Buffer, str]], Iterator[Union[Buffer, str]]]):
                A list of data to be used as leaf nodes.
                Strings will be UTF-8 encoded to bytes.
            name (Optional[str], optional): The digest algorithm name
                (e.g., "sha1", "sha256", "blake2b"). Defaults to "sha1".

        Returns:
            MrkleTree: A new Merkle tree instance containing the provided
                leaves hashed with the specified digest algorithm.

        Raises:
            ValueError: If the digest algorithm name is not supported.
            TypeError: If data is of an unsupported type.

        Examples:
            >>> from mrkle.tree import MrkleTree
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
            return cls._construct_tree_backend(inner.from_leaves(leaves))
        else:
            raise ValueError(
                f"{name} is not a digest algorithm supported by MrkleTree."
            )

    def branch(self, node: Union["MrkleNode", int]) -> "MrkleBranch":
        """Return a branch iterator from a leaf node to the root.

        Args:
            node: Either a MrkleNode instance or an integer index of a node
                in the tree.

        Returns:
            MrkleBranch: An iterator that yields nodes from the specified node
                up to the root.

        Raises:
            TreeError: If node not found in its parent's children
            or has not parent.

        Examples:
            >>> tree = MrkleTree.from_leaves([b"a", b"b", b"c"])
            >>> branch = tree.branch(0)  # From first leaf
            >>> for node in branch:
            ...     print(node.hexdigest())
        """
        if isinstance(node, MrkleNode):
            index = _find_index_from_node(self, node)
        else:
            index = node
        return MrkleBranch(self, index)

    def generate_proof(
        self,
        leaves: Union[
            int,
            slice,
            Sequence[int],
            Sequence[MrkleNode],
            "MrkleNode",
        ],
    ) -> "MrkleProof":
        """Generate a Merkle proof for the specified leaf nodes.

        Args:
            leaves (Union[int, slice, Sequence[int], "MrkleNode"]): A set of leaf.

        Returns:
            MrkleProof: A Merkle proof object that can verify the
                inclusion of the specified leaves in this tree.

        Raises:
            ValueError: If there are no proved leaves.
            TreeError: If the tree has no root.
            IndexError: If a node index is out of bounds.
            ProofError: If the generated path is invalid.

        Examples:
            >>> tree = MrkleTree.from_leaves([b"a", b"b", b"c"])
            >>> proof = tree.generate_proof(0)
        """
        return MrkleProof.generate(self, leaves)

    proof = generate_proof

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
        format: Literal["json"] = "json",
    ) -> "MrkleTree":
        """Deserialize a tree from string or bytes (JSON/CBOR).

        Args:
            data: Serialized tree data (str or bytes).
            name: Optional digest algorithm name. If None, will auto-detect from data.
            format: Serialization format - "json" or "cbor". Defaults to "json".

        Returns:
            MrkleTree: Deserialized tree instance.

        Raises:
            ValueError: Raised when the specified digest algorithm is not
                recognized in the default registry.
            SerdeError: Raised when deserialization fails.

        Examples:
            >>> tree = MrkleTree.from_leaves([b"a", b"b"], name="sha256")
            >>> data = tree.dumps(format="json")
            >>> restored = MrkleTree.loads(data, format="json")
            >>> restored == tree
            True

            >>> # Auto-detect algorithm from data
            >>> restored = MrkleTree.loads(data)

            >>> # Specify algorithm explicitly
            >>> restored = MrkleTree.loads(data, name="sha256", format="json")
        """
        if name is None:
            return cls._find_loads(data)
        else:
            if tree := TREE_MAP.get(name):
                return MrkleTree(tree.loads(data, format=format))
            else:
                raise ValueError(
                    f"{name} is not a digest algorithm supported by MrkleTree."
                )

    @classmethod
    def load(
        cls,
        fp: File,
        name: Optional[str] = None,
        *,
        format: Literal["json"] = "json",
    ) -> "MrkleTree":
        """Deserialize a tree from a file-like object.

        Args:
            fp: File-like object to read from (text or binary mode).
            name: Optional digest algorithm name. If None, will auto-detect from data.
            format: Serialization format - "json" or "cbor". Defaults to "json".

        Returns:
            MrkleTree: Deserialized tree instance.

        Raises:
            ValueError: Raised when the specified digest algorithm is not
                recognized in the default registry.
            SerdeError: Raised when deserialization fails.
            IOError: Raised when file reading fails.

        Examples:
            >>> tree = MrkleTree.from_leaves([b"a", b"b"], name="sha256")
            >>> with open('tree.json', 'w') as f:
            ...     tree.dumps(fp=f, indent=2)

            >>> # Load from file
            >>> with open('tree.json', 'r') as f:
            ...     restored = MrkleTree.load(f)

            >>> # Auto-detect algorithm
            >>> with open('tree.json', 'r') as f:
            ...     restored = MrkleTree.load(f)

            >>> # Specify algorithm explicitly
            >>> with open('tree.sha256.json', 'r') as f:
            ...     restored = MrkleTree.load(f, name="sha256")
        """
        if name is None:
            return cls._find_load(fp, format=format)
        else:
            if tree := TREE_MAP.get(name):
                return MrkleTree(tree.load(fp, format=format))
            else:
                raise ValueError(
                    f"{name} is not a digest algorithm supported by MrkleTree."
                )

    @classmethod
    def _find_loads(
        cls, data: Union[str, bytes], *, format: Literal["json"] = "json"
    ) -> "MrkleTree":
        """Auto-detect digest algorithm from serialized data and deserialize.

        Args:
            data: Serialized tree data.
            format: Serialization format. Defaults to "json".

        Returns:
            MrkleTree: Deserialized tree instance.

        Raises:
            ValueError: If the hash type in data is not recognized.
            SerdeError: If deserialization fails.
        """

        metadata = json.loads(data if isinstance(data, str) else data.decode("utf-8"))

        if hash_type := metadata.get("hash_type"):
            if isinstance(hash_type, str):
                if tree := TREE_MAP.get(hash_type):
                    # NOTE: when implement binary update format Literal.
                    return MrkleTree(tree.loads(data, format=format))
                else:
                    raise ValueError(
                        (
                            f"Hash type '{hash_type}' from data is not supported "
                            "by MrkleTree."
                        )
                    )
            else:
                return NotImplemented

        else:
            raise ValueError("Serialized data does not contain 'hash_type' field")

    @classmethod
    def _find_load(
        cls,
        fp: File,
        *,
        format: Literal["json"] = "json",
    ) -> "MrkleTree":
        """Auto-detect digest algorithm from file and deserialize.

        Args:
            fp: File-like object to read from.
            format: Serialization format. Defaults to "json".

        Returns:
            MrkleTree: Deserialized tree instance.

        Raises:
            ValueError: If the hash type in file is not recognized.
            SerdeError: If deserialization fails.
        """
        # Read all data from file
        data = fp.read()
        return cls._find_loads(data, format=format)

    def dumps(
        self,
        fp: Optional[File] = None,
        *,
        encoding: Literal["utf-8", "bytes"] = "utf-8",
        indent: Optional[int] = None,
    ) -> Optional[Union[str, bytes]]:
        """Serialize the tree to JSON format.

        Args:
            fp: Optional file-like object to write to. If provided, returns None.
            encoding: Output encoding; "utf-8" returns str, "bytes" returns bytes.
                Defaults to "utf-8".
            indent: Number of spaces for indentation. None for compact output.

        Returns:
            Optional[Union[str, bytes]]: Serialized tree data as string or bytes,
                or None if fp is provided.

        Examples:
            >>> tree = MrkleTree.from_leaves([b"a", b"b"], name="sha256")
            >>> json_str = tree.dumps()
            >>> json_bytes = tree.dumps(encoding="bytes")
            >>>
            >>> # Write to file
            >>> with open('tree.json', 'w') as f:
            ...     tree.dumps(fp=f, indent=2)  # Returns None
        """
        return self._inner.dumps(fp=fp, encoding=encoding, indent=indent)

    to_str = to_string

    @classmethod
    def from_dict(
        cls,
        data: dict[str, Any],
        name: Optional[str] = None,
        *,
        format: Literal["flatten", "nested"] = "nested",
        sep: str = ".",
    ) -> "MrkleTree":
        """Construct a MrkleTree from a tree-like dict.

        A tree-like dictionary is defined as a dictionary that contains only leaves.
        The depth of the tree can be represented as nested or flattened.

        Args:
            data: Dictionary containing the tree data.
            name: Name of the digest algorithm (defaults to "sha1").
            format: Format of the input dictionary - "flatten" for dot-separated keys
                or "nested" for recursive dictionaries (default: "nested").
            sep: Separator character used for flattened keys (default: ".").

        Returns:
            MrkleTree: A new tree instance built from the given dictionary data.

        Raises:
            ValueError: Raised when the specified digest algorithm is not recognized
                in the default registry, or when a tree traversal error occurs.

        Note:
            - Flatten format: defines the depth within the key using a separator
              (e.g., "a.b.c" represents nested path a -> b -> c)
            - Nested format: defines a recursive dictionary where only the leaf
              nodes contain values

        Example:
            >>> from mrkle import MrkleTree
            >>> data = {"a.a": b"let", "a.b": b"a", "a.c.b": b"=", "a.c.a": b"1"}
            >>> tree_flatten = MrkleTree.from_dict(data, format="flatten")
            >>> tree_flatten.root().hex()
            '34e31fe4180705565b3bb314ad56a3f513616e29'
            >>> data = {'a': {'a': b'let', 'b': b'a', 'c': {'a': b'=', 'b': b'1'}}}
            >>> tree_unflatten = MrkleTree.from_dict(data)
            >>> assert tree_unflatten == tree_flatten
            >>>
        """
        if name is None:
            name = "sha1"
        digest = new(name)
        name = digest.name()
        # NOTE: need to test between rust impl
        # and python impl to see if there is
        # some speed improvments in speed
        # handling it \w in rust runtime.
        if format == "flatten":
            data = unflatten(data, sep=sep)
        if inner := TREE_MAP.get(name):
            return cls._construct_tree_backend(inner.from_dict(data=data))
        else:
            raise ValueError(
                f"{name} is not a digest algorithm supported by MrkleTree."
            )

    @classmethod
    def _construct_tree_backend(cls, tree: Tree_T) -> "MrkleTree":
        """Internal method to create a MrkleTree instance bypassing __init__.

        This method is used internally to construct tree instances with
        pre-validated components, avoiding the normal initialization path.

        Args:
            tree (Tree_T): The underlying Rust-based tree instance.
            dtype (Digest): The digest algorithm instance.

        Returns:
            MrkleTree: A new tree instance wrapping the given components.

        """
        obj = object.__new__(cls)
        object.__setattr__(obj, "_inner", tree)
        return obj

    @overload
    def __getitem__(self, key: int) -> MrkleNode: ...

    @overload
    def __getitem__(self, key: slice) -> list[MrkleNode]: ...

    @overload
    def __getitem__(self, key: Sequence[int]) -> list[MrkleNode]: ...

    def __getitem__(
        self, key: Union[int, slice, Sequence[int]]
    ) -> Union[list[MrkleNode], MrkleNode]:
        """Access nodes by index, slice, or sequence of indices.

        Args:
            key (Union[int, slice, Sequence[int]]): The index specification.

        Returns:
            Union[list[MrkleNode], MrkleNode]: A list of nodes or single node.

        Raises:
            TypeError: Raised if the key type is invalid.
            IndexError: Raised when key is out of range.
        """
        return self._inner[key]

    def __iter__(self) -> "MrkleTreeIter":
        """Return an iterator over all nodes in the tree.

        The iteration is performed in breadth-first order.

        Returns:
            MrkleTreeIter: An iterator over tree nodes.

        Examples:
            >>> tree = MrkleTree.from_leaves([b"a", b"b"])
            >>> for node in tree:
            ...     print(node.hexdigest())
        """
        return MrkleTreeIter.from_tree(self._inner)

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
            >>> tree3 = MrkleTree.from_leaves([b"a", b"b"], name="sha224")
            >>> tree1 == tree3
            False
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
        return (
            f"<{self._inner.dtype().name()} mrkle.tree.MrkleTree "
            f"object at {hex(id(self))}>"
        )

    @override
    def __str__(self) -> str:
        """Return a human-readable string representation of the proof.

        Returns:
            str: Basic representation showing expected hash prefix, length,
                and digest type.

        Examples:
            >>> tree = MrkleTree.from_leaves([b"a", b"b"])
            >>> str(tree)
            'MrkleTree(expected=ce7a, length=3, dtype=sha1)'
        """
        root = self.root()
        expected = root[:4].hex() if root else None
        length = len(self) if root else 0
        dtype = self.dtype().name()

        return f"MrkleTree(root={expected}, length={length}, dtype={dtype})"

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
class MrkleProof:
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
        >>> proof = tree.generate_proof(0)
        >>> str(proof)
        'MrkleProof(expected=70a6, length=5, dtype=sha1)'

    """

    _inner: Proof_T
    _dtype_name: str

    __slots__ = ("_inner", "_dtype_name")

    def __init__(self, proof: Proof_T) -> None:
        """Initialize a MrkleProof instance.

        Args:
            proof: The underlying Rust-based proof instance.
        """
        self._inner = proof
        self._dtype_name = proof.dtype().name()

    def expected(self) -> bytes:
        """Returns the expected hash of the proof."""
        return self._inner.expected()

    def expected_hexdigest(self) -> str:
        """Returns the expected hexadecimal hash of the proof."""
        return self._inner.expected_hexdigest()

    @classmethod
    def generate(
        cls,
        tree: "MrkleTree",
        leaves: Union[int, slice, Sequence[int], Sequence[MrkleNode], "MrkleNode"],
    ) -> "MrkleProof":
        """Generate MrkleProof from MrkleTree, and leaf index.

        Examples:
            >>> from mrkle.tree import MrkleTree, MrkleProof
            >>> tree = MrkleTree.from_leaves(["a", "b", "c"])
            >>> leaf = tree[0]
            >>> proof = tree.generate_proof(leaf)
            >>> # or
            >>> proof = MrkleProof.generate(tree, node)

        """

        name = tree.dtype().name()

        if proof := PROOF_MAP.get(name):
            if isinstance(leaves, int):
                leaves = [leaves]
            elif isinstance(leaves, MrkleNode):
                leaves = [_find_index_from_node(tree, leaves)]
            elif isinstance(leaves, Sequence):
                leaves = list(
                    map(
                        lambda node: _find_index_from_node(tree, node)
                        if isinstance(node, MrkleNode)
                        else node,
                        leaves,
                    )
                )

            return cls(proof.generate(tree, leaves))
        else:
            raise ValueError(
                f"{name!r} is not a digest algorithm supported by MrkleTree."
            )

    def verify(
        self,
        leaves: Union[
            Sequence[str],
            Sequence[bytes],
            Sequence[MrkleNode],
            str,
            bytes,
            MrkleNode,
        ],
    ) -> bool:
        """Verify if the expected digest belongs to the tree.

        Returns:
            bool: True if the proof is valid, False otherwise.

        Examples:
            >>> from mrkle.tree import MrkleTree
            >>>
            >>> tree = MrkleTree.from_leaves([b"a", b"b"], name="sha256")
            >>> proof = tree.generate_proof(0)
            >>> leaf = tree[1]
            >>> proof.verify(leaf.digest())
            False
            >>>
            >>> leaf = tree[0]
            >>> proof.verify(leaf.digest())
            True
            >>> leaf = tree[0]
            >>> proof.verify(leaf)
            True

        """
        return self._inner.verify(leaves=leaves)

    def dtype(self) -> Digest:
        """Return the digest type used by this tree.

        Returns:
            Digest: The digest algorithm instance (e.g., Sha1(), Sha256()).
        """
        return new(self._dtype_name)

    def __len__(self) -> int:
        """Return length of nodes within the tree."""
        return len(self._inner)

    @override
    def __repr__(self) -> str:
        """Return the canonical string representation of the tree.

        Returns:
            str: Representation including the digest type and object id.

        Examples:
            >>> tree = MrkleTree.from_leaves([b"a"], name="sha256")
            >>> proof = tree.generate_proof(0)
            >>> repr(proof)
            '<sha256 mrkle.tree.MrkleProof object at 0x...>'
        """
        return f"<{self._dtype_name} mrkle.tree.MrkleProof object at {hex(id(self))}>"

    @override
    def __str__(self) -> str:
        """Return a human-readable string representation of the proof.

        Returns:
            str: Basic representation showing expected hash prefix, length,
                and digest type.

        Examples:
            >>> tree = MrkleTree.from_leaves([b"a", b"b"])
            >>> proof = tree.generate_proof(0)
            >>> str(proof)
            'MrkleProof(expected=ce7a, dtype=sha1)'
        """
        root = self._inner.expected_hexdigest()
        expected = root[:4] if root else None

        return f"MrkleProof(expected={expected}, dtype={self._dtype_name})"

    @override
    def __format__(self, format_spec: str, /) -> str:
        """Format the tree according to the given format specification.

        Args:
            format_spec (str): The format specification string.

        Returns:
            str: The formatted string representation.
        """
        return super().__format__(format_spec)


class MrkleBranch(Iterable[MrkleNode]):
    """MrkleTree branch iterator pattern.

    This class provieds a iterator over a singluar branch over a MrkleTree
    traversing from the child to the parent.

    Example:
        >>> from mrkle.tree import MrkleTree
        >>> data = {'a': {'a': b'let', 'b': b'a', 'c': {'a': b'=', 'b': b'1'}}}
        >>> tree = MrkleTree.from_dict(data)
        >>> node = tree[0]
        >>> branch = tree.branch(node)
        >>> for n in branch:
        ...     print(n)
        ...
        MrkleNode(id=0262, leaf=True, dtype=sha1)
        MrkleNode(id=34e3, leaf=False, dtype=sha1)
    """

    _tree: MrkleTree
    _cursor: MrkleNode | None
    __slots__: tuple[str, ...] = ("_tree", "_cursor")

    def __init__(self, _tree: MrkleTree, index: int) -> None:
        self._tree = _tree
        self._cursor = _tree[index]

    @override
    def __iter__(self) -> "MrkleBranch":
        return self

    def __next__(self) -> MrkleNode:
        if self._cursor is None:
            raise StopIteration

        node_ptr = self._cursor

        parent = node_ptr.parent()
        if parent is not None:
            self._cursor = self._tree[parent]
        else:
            self._cursor = None

        return node_ptr

    @override
    def __repr__(self) -> str:
        return f"<mrkle.iter.MrkleBranch object at {hex(id(self))}>"

    @override
    def __str__(self) -> str:
        node_type = self._tree.dtype().name()
        return f"MrkleBranch(dtype={node_type})"


def _find_index_from_node(tree: "MrkleTree", item: "MrkleNode") -> int:
    if p := item.parent():
        parent = tree[p]
        for c in parent.children():
            node = tree[c]
            if node == item:
                return c
        raise TreeError(f"Node {item!r} not found in its parent's children.")
    else:
        raise TreeError(f"Node {item!r} has no parent (root or detached).")
