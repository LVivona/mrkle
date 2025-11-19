from collections.abc import Mapping, Sequence
from typing import Final, Union

from typing_extensions import TypeAlias, override

from mrkle.crypto.typing import Digest
from mrkle.node import MrkleNode
from mrkle.tree import MrkleTree

__all__ = [
    "MrkleProofSha1",
    "MrkleProofSha224",
    "MrkleProofSha256",
    "MrkleProofSha384",
    "MrkleProofSha512",
    "MrkleProofSha3_224",
    "MrkleProofSha3_256",
    "MrkleProofSha3_384",
    "MrkleProofSha3_512",
    "MrkleProofKeccak224",
    "MrkleProofKeccak256",
    "MrkleProofKeccak384",
    "MrkleProofKeccak512",
    "MrkleProofBlake2b",
    "MrkleProofBlake2s",
    "PROOF_MAP",
    "Proof_T",
]

# ---- Base interface for all proof classes ----

class BaseMrkleProof:
    def expected(self) -> bytes: ...
    def expected_hexdigest(self) -> str: ...
    @classmethod
    def generate(
        cls, tree: MrkleTree, leaves: Union[Sequence[int], slice]
    ) -> "Proof_T": ...
    @staticmethod
    def dtype() -> Digest: ...
    def verify(
        self,
        leaves: Union[
            Sequence[str], Sequence[bytes], Sequence[MrkleNode], str, bytes, MrkleNode
        ],
    ) -> bool: ...
    def __len__(self) -> int: ...
    @override
    def __repr__(self) -> str: ...
    @override
    def __str__(self) -> str: ...
    # UNCOMMENT: when rust impl finished
    # def dumps(
    #     self, encoding: Optional[Literal["json", "cbor"]], **kwargs: dict[str, Any]
    # ) -> bytes: ...
    # @staticmethod
    # def loads(
    #     data: Union[str, bytes], encoding: Optional[Literal["json", "cbor"]] = ...
    # ) -> "Proof_T": ...

class MrkleProofSha1(BaseMrkleProof): ...
class MrkleProofSha224(BaseMrkleProof): ...
class MrkleProofSha256(BaseMrkleProof): ...
class MrkleProofSha384(BaseMrkleProof): ...
class MrkleProofSha512(BaseMrkleProof): ...
class MrkleProofSha3_224(BaseMrkleProof): ...
class MrkleProofSha3_256(BaseMrkleProof): ...
class MrkleProofSha3_384(BaseMrkleProof): ...
class MrkleProofSha3_512(BaseMrkleProof): ...
class MrkleProofKeccak224(BaseMrkleProof): ...
class MrkleProofKeccak256(BaseMrkleProof): ...
class MrkleProofKeccak384(BaseMrkleProof): ...
class MrkleProofKeccak512(BaseMrkleProof): ...
class MrkleProofBlake2b(BaseMrkleProof): ...
class MrkleProofBlake2s(BaseMrkleProof): ...

Proof_T: TypeAlias = Union[
    MrkleProofBlake2s,
    MrkleProofBlake2b,
    MrkleProofKeccak224,
    MrkleProofKeccak256,
    MrkleProofKeccak384,
    MrkleProofKeccak512,
    MrkleProofSha1,
    MrkleProofSha224,
    MrkleProofSha256,
    MrkleProofSha384,
    MrkleProofSha512,
    MrkleProofSha3_224,
    MrkleProofSha3_256,
    MrkleProofSha3_384,
    MrkleProofSha3_512,
]

PROOF_MAP: Final[Mapping[str, Proof_T]]
