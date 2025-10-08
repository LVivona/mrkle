from typing import Protocol, runtime_checkable


@runtime_checkable
class Digest(Protocol):
    def update(self, data: bytes) -> None:
        ...

    def finalize(self) -> bytes:
        ...

    def finalize_reset(self) -> bytes:
        ...

    def reset(self) -> None:
        ...

    @staticmethod
    def new_with_prefix(data: bytes) -> "Digest":
        ...

    @staticmethod
    def output_size() -> int:
        ...

    @staticmethod
    def digest(data: bytes) -> bytes:
        ...

    @staticmethod
    def name() -> str:
        ...
