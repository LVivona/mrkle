from typing import Any


def unflatten(dictionary: dict[str, Any]):
    """Retrun an unflatten tree."""
    resultDict: dict[str, Any] = dict()
    for key, value in dictionary.items():
        parts = key.split(".")
        d = resultDict
        for part in parts[:-1]:
            if part not in d:
                d[part] = dict()
            if isinstance(d[part], dict):
                d = d[part]

        d.setdefault(parts[-1], value)
    return resultDict
