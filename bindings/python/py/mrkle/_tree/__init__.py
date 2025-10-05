"""Merkle tree implementations for various hash algorithms."""

from __future__ import annotations
from types import MappingProxyType
from typing import Final, Union

from collections.abc import Mapping

from mrkle._mrkle_rs import tree

__all__ = [
    "MrkleTreeBlake2s",
    "MrkleTreeBlake2b",
    "MrkleTreeKeccak224",
    "MrkleTreeKeccak256",
    "MrkleTreeKeccak384",
    "MrkleTreeKeccak512",
    "MrkleTreeSha1",
    "MrkleTreeSha224",
    "MrkleTreeSha256",
    "MrkleTreeSha384",
    "MrkleTreeSha512",
    "MrkleTreeIterBlake2s",
    "MrkleTreeIterBlake2b",
    "MrkleTreeIterKeccak224",
    "MrkleTreeIterKeccak256",
    "MrkleTreeIterKeccak384",
    "MrkleTreeIterKeccak512",
    "MrkleTreeIterSha1",
    "MrkleTreeIterSha224",
    "MrkleTreeIterSha256",
    "MrkleTreeIterSha384",
    "MrkleTreeIterSha512",
    "TREE_MAP",
    "NODE_MAP",
    "Node_T",
    "Tree_T",
    "Iterable_T",
]


MrkleTreeBlake2s = tree.MrkleTreeBlake2s
MrkleTreeBlake2b = tree.MrkleTreeBlake2b
MrkleTreeKeccak224 = tree.MrkleTreeKeccak224
MrkleTreeKeccak256 = tree.MrkleTreeKeccak256
MrkleTreeKeccak384 = tree.MrkleTreeKeccak384
MrkleTreeKeccak512 = tree.MrkleTreeKeccak512
MrkleTreeSha1 = tree.MrkleTreeSha1
MrkleTreeSha224 = tree.MrkleTreeSha224
MrkleTreeSha256 = tree.MrkleTreeSha256
MrkleTreeSha384 = tree.MrkleTreeSha384
MrkleTreeSha512 = tree.MrkleTreeSha512

MrkleNodeBlake2s = tree.MrkleNodeBlake2s
MrkleNodeBlake2b = tree.MrkleNodeBlake2b
MrkleNodeKeccak224 = tree.MrkleNodeKeccak224
MrkleNodeKeccak256 = tree.MrkleNodeKeccak256
MrkleNodeKeccak384 = tree.MrkleNodeKeccak384
MrkleNodeKeccak512 = tree.MrkleNodeKeccak512
MrkleNodeSha1 = tree.MrkleNodeSha1
MrkleNodeSha224 = tree.MrkleNodeSha224
MrkleNodeSha256 = tree.MrkleNodeSha256
MrkleNodeSha384 = tree.MrkleNodeSha384
MrkleNodeSha512 = tree.MrkleNodeSha512

# Re-export all iterator types
MrkleTreeIterBlake2s = tree.MrkleTreeIterBlake2s
MrkleTreeIterBlake2b = tree.MrkleTreeIterBlake2b
MrkleTreeIterKeccak224 = tree.MrkleTreeIterKeccak224
MrkleTreeIterKeccak256 = tree.MrkleTreeIterKeccak256
MrkleTreeIterKeccak384 = tree.MrkleTreeIterKeccak384
MrkleTreeIterKeccak512 = tree.MrkleTreeIterKeccak512
MrkleTreeIterSha1 = tree.MrkleTreeIterSha1
MrkleTreeIterSha224 = tree.MrkleTreeIterSha224
MrkleTreeIterSha256 = tree.MrkleTreeIterSha256
MrkleTreeIterSha384 = tree.MrkleTreeIterSha384
MrkleTreeIterSha512 = tree.MrkleTreeIterSha512

Node_T = type[
    Union[
        MrkleNodeBlake2s,
        MrkleNodeBlake2b,
        MrkleNodeKeccak224,
        MrkleNodeKeccak256,
        MrkleNodeKeccak384,
        MrkleNodeKeccak512,
        MrkleNodeSha1,
        MrkleNodeSha224,
        MrkleNodeSha256,
        MrkleNodeSha384,
        MrkleNodeSha512,
    ]
]

Tree_T = type[
    Union[
        MrkleTreeBlake2s,
        MrkleTreeBlake2b,
        MrkleTreeKeccak224,
        MrkleTreeKeccak256,
        MrkleTreeKeccak384,
        MrkleTreeKeccak512,
        MrkleTreeSha1,
        MrkleTreeSha224,
        MrkleTreeSha256,
        MrkleTreeSha384,
        MrkleTreeSha512,
    ]
]

Iterable_T = type[
    Union[
        MrkleTreeIterBlake2s,
        MrkleTreeIterBlake2b,
        MrkleTreeIterKeccak224,
        MrkleTreeIterKeccak256,
        MrkleTreeIterKeccak384,
        MrkleTreeIterKeccak512,
        MrkleTreeIterSha1,
        MrkleTreeIterSha224,
        MrkleTreeIterSha256,
        MrkleTreeIterSha384,
        MrkleTreeIterSha512,
    ]
]


TREE_MAP: Final[Mapping[str, Tree_T]] = MappingProxyType(
    {
        "blake2s": MrkleTreeBlake2s,
        "blake2b": MrkleTreeBlake2b,
        "blake2s256": MrkleTreeBlake2s,
        "blake2b512": MrkleTreeBlake2b,
        "keccak224": MrkleTreeKeccak224,
        "keccak256": MrkleTreeKeccak256,
        "keccak384": MrkleTreeKeccak384,
        "keccak512": MrkleTreeKeccak512,
        "sha1": MrkleTreeSha1,
        "sha224": MrkleTreeSha224,
        "sha256": MrkleTreeSha256,
        "sha384": MrkleTreeSha384,
        "sha512": MrkleTreeSha512,
    }
)


NODE_MAP: Final[Mapping[str, Node_T]] = MappingProxyType(
    {
        "blake2s": MrkleNodeBlake2s,
        "blake2b": MrkleNodeBlake2b,
        "blake2s256": MrkleNodeBlake2s,
        "blake2b512": MrkleNodeBlake2b,
        "keccak224": MrkleNodeKeccak224,
        "keccak256": MrkleNodeKeccak256,
        "keccak384": MrkleNodeKeccak384,
        "keccak512": MrkleNodeKeccak512,
        "sha1": MrkleNodeSha1,
        "sha224": MrkleNodeSha224,
        "sha256": MrkleNodeSha256,
        "sha384": MrkleNodeSha384,
        "sha512": MrkleNodeSha512,
    }
)
