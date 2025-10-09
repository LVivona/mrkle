"""Internal utility functions for Mrkle.

This module provides helper functions used across the Mrkle API. These
functions are *not* part of the public interface.
"""

from __future__ import annotations

from typing import Union
from mrkle.typing import BufferLike as Buffer


NestedDict = dict[str, Union[Buffer, str, "NestedDict"]]


def unflatten(state_dict: dict[str, Buffer], sep: str = ".") -> NestedDict:
    """Returns an unflattened tree.

    Args:
        state_dict (dict[str, BufferLike]): Flattened dictionary where keys
        contain depth of leaf.

    Returns:
        NestedDict: A nested dict.

    Example:
        >>> from mrkle.utils import unflatten
        >>> flatten_dict = {"a.a": b"hello", "a.c": b"world"}
        >>> tree_dict = unflatten(flatten_dict)
        >>> tree_dict
        {'a': {'a': b'hello', 'c': b'world'}}
    """
    result_dict: NestedDict = {}
    for key, value in state_dict.items():
        parts: list[str] = key.split(sep)
        d: NestedDict = result_dict
        for part in parts[:-1]:
            if part not in d or not isinstance(d[part], dict):
                d[part] = {}
            d = d[part]  # type: ignore[assignment]
        d[parts[-1]] = value  # type: ignore[index]
    return result_dict
