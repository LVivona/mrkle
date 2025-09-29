import sys
from typing import runtime_checkable, Protocol, TypeVar, Union
from typing_extensions import TypeAlias
from mrkle.crypto.typing import Digest

from mrkle._mrkle_rs import tree

if sys.version_info >= (3, 12):
    # Buffer protocol is available in Python 3.12+
    from collections.abc import Buffer as ByteBuffer

    Buffer: TypeAlias = ByteBuffer
else:
    # Fallback for older Python versions
    @runtime_checkable
    class SupportsBytes(Protocol):
        """Protocol for objects that support conversion to bytes."""

        def __bytes__(self) -> bytes:
            """Convert the object to bytes."""
            ...

    Buffer: TypeAlias = SupportsBytes

# Internal Rust Digest Trait
_D = TypeVar("_D", bound=Digest)


_NodeT: TypeAlias = Union[
    tree.MrkleNodeBlake2s,
    tree.MrkleNodeBlake2b,
    tree.MrkleNodeKeccak224,
    tree.MrkleNodeKeccak256,
    tree.MrkleNodeKeccak384,
    tree.MrkleNodeKeccak512,
    tree.MrkleNodeSha1,
    tree.MrkleNodeSha224,
    tree.MrkleNodeSha256,
    tree.MrkleNodeSha384,
    tree.MrkleNodeSha512,
]

_TreeT: TypeAlias = Union[
    tree.MrkleNodeBlake2s,
    tree.MrkleNodeBlake2b,
    tree.MrkleNodeKeccak224,
    tree.MrkleNodeKeccak256,
    tree.MrkleNodeKeccak384,
    tree.MrkleNodeKeccak512,
    tree.MrkleNodeSha1,
    tree.MrkleNodeSha224,
    tree.MrkleNodeSha256,
    tree.MrkleNodeSha384,
    tree.MrkleNodeSha512,
]

_Iter: TypeAlias = Union[
    tree.MrkleTreeIterBlake2s,
    tree.MrkleTreeIterBlake2b,
    tree.MrkleTreeIterKeccak224,
    tree.MrkleTreeIterKeccak256,
    tree.MrkleTreeIterKeccak384,
    tree.MrkleTreeIterKeccak512,
    tree.MrkleTreeIterSha1,
    tree.MrkleTreeIterSha224,
    tree.MrkleTreeIterSha256,
    tree.MrkleTreeIterSha384,
    tree.MrkleTreeIterSha512,
]
