from collections.abc import Mapping
from types import MappingProxyType
from typing import Final, Union

from mrkle._mrkle_rs import proof

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

MrkleProofSha1 = proof.MrkleProofSha1

MrkleProofSha224 = proof.MrkleProofSha224
MrkleProofSha256 = proof.MrkleProofSha256
MrkleProofSha384 = proof.MrkleProofSha384
MrkleProofSha512 = proof.MrkleProofSha512

MrkleProofSha3_224 = proof.MrkleProofSha3_224
MrkleProofSha3_256 = proof.MrkleProofSha3_256
MrkleProofSha3_384 = proof.MrkleProofSha3_384
MrkleProofSha3_512 = proof.MrkleProofSha3_512

MrkleProofKeccak224 = proof.MrkleProofKeccak224
MrkleProofKeccak256 = proof.MrkleProofKeccak256
MrkleProofKeccak384 = proof.MrkleProofKeccak384
MrkleProofKeccak512 = proof.MrkleProofKeccak512

MrkleProofBlake2b = proof.MrkleProofBlake2b
MrkleProofBlake2s = proof.MrkleProofBlake2s


Proof_T = type[
    Union[
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
]

PROOF_MAP: Final[Mapping[str, Proof_T]] = MappingProxyType(
    {
        "blake2s": MrkleProofBlake2s,
        "blake2b": MrkleProofBlake2b,
        "blake2s256": MrkleProofBlake2s,
        "blake2b512": MrkleProofBlake2b,
        "keccak224": MrkleProofKeccak224,
        "keccak256": MrkleProofKeccak256,
        "keccak384": MrkleProofKeccak384,
        "keccak512": MrkleProofKeccak512,
        "sha1": MrkleProofSha1,
        "sha224": MrkleProofSha224,
        "sha256": MrkleProofSha256,
        "sha384": MrkleProofSha384,
        "sha512": MrkleProofSha512,
        "sha3_224": MrkleProofSha224,
        "sha3_256": MrkleProofSha256,
        "sha3_384": MrkleProofSha384,
        "sha3_512": MrkleProofSha512,
    }
)
