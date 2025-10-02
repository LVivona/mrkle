from mrkle._mrkle_rs import proof

from collections import Mapping
from types import MappingProxyType
from typing import Union, Final

__all__ = [
    "MrkleProofSha1",
    "MrkleProofSha224",
    "MrkleProofSha256",
    "MrkleProofSha384",
    "MrkleProofSha512",
    "MrkleProofKeccak224",
    "MrkleProofKeccak256",
    "MrkleProofKeccak384",
    "MrkleProofKeccak512",
    "MrkleProofBlake2b",
    "MrkleProofBlake2s",
    "PROOF_MAP",
    "ProofT",
]

MrkleProofSha1 = proof.MrkleProofSha1

MrkleProofSha224 = proof.MrkleProofSha224
MrkleProofSha256 = proof.MrkleProofSha256
MrkleProofSha384 = proof.MrkleProofSha384
MrkleProofSha512 = proof.MrkleProofSha512


MrkleProofKeccak224 = proof.MrkleProofKeccak224
MrkleProofKeccak256 = proof.MrkleProofKeccak256
MrkleProofKeccak384 = proof.MrkleProofKeccak384
MrkleProofKeccak512 = proof.MrkleProofKeccak512

MrkleProofBlake2b = proof.MrkleProofBlake2b
MrkleProofBlake2s = proof.MrkleProofBlake2s


ProofT = type[
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
    ]
]

PROOF_MAP: Final[Mapping[str, ProofT]] = MappingProxyType(
    {
        "blake2s": MrkleProofBlake2s,
        "blake2b": MrkleProofBlake2b,
        "keccak224": MrkleProofKeccak224,
        "keccak256": MrkleProofKeccak256,
        "keccak384": MrkleProofKeccak384,
        "keccak512": MrkleProofKeccak512,
        "sha1": MrkleProofSha1,
        "sha224": MrkleProofSha224,
        "sha256": MrkleProofSha256,
        "sha384": MrkleProofSha384,
        "sha512": MrkleProofSha512,
    }
)
