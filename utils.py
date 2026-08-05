# SPDX-License-Identifier: GPL-3.0-only


def require(kwargs: dict, *fields: str) -> tuple:
    """Ensure required keyword arguments are present, raising ValueError otherwise."""
    missing = [f for f in fields if not kwargs.get(f)]
    if missing:
        raise ValueError(f"Missing required parameter(s): {', '.join(missing)}")
    return tuple(kwargs[f] for f in fields)
