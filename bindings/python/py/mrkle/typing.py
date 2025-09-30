import sys
from typing import runtime_checkable, Protocol, TypeVar, Union, Literal
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
D = TypeVar("D", bound=Digest)
SLOT_T = tuple[Literal["_inner"], Literal["_dtype"]]

__all__ = ["SLOT_T", "D", "Buffer"]
