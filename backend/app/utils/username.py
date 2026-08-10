"""Shared username boundary validation."""

import unicodedata


def normalize_username(value: str) -> str:
    candidate = value.strip()
    if not 1 <= len(candidate) <= 100:
        raise ValueError("Username must be 1-100 characters")
    if any(unicodedata.category(character).startswith("C") for character in candidate):
        raise ValueError("Username must not contain control characters")
    return candidate
