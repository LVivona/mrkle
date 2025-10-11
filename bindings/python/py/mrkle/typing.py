import io
import sys
from typing import Union, runtime_checkable, Protocol
from typing_extensions import TypeAlias

if sys.version_info >= (3, 12):
    # Buffer protocol is available in Python 3.12+
    from collections.abc import Buffer

    BufferLike: TypeAlias = Buffer
else:

    @runtime_checkable
    class Buffer(Protocol):
        """Protocol for objects that support the buffer protocol.

        This is a backport of collections.abc.Buffer for Python < 3.12.
        """

        def __buffer__(self, flags: int, /) -> memoryview:
            """Return a buffer object that exposes the underlying memory."""
            ...

        def __release_buffer__(self, buffer: memoryview, /) -> None:
            """Release the buffer object."""
            ...

    BufferLike: TypeAlias = Union[
        bytes,
        bytearray,
        memoryview,
        Buffer,
    ]

File = Union[io.TextIOBase, io.BufferedIOBase, io.RawIOBase]

__all__ = ["BufferLike", "File"]
