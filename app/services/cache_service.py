"""In-memory, process-lifetime cache for metadata tool results.

A plain dict-backed cache enabled by `CACHE_ENABLED`. There is no TTL or
eviction: entries live for the process lifetime, matching the original
service's accepted staleness trade-off. Query execution results are never
cached.
"""

from __future__ import annotations

from typing import Any


class CacheService:
    """Plain in-memory cache, enabled/disabled by a single constructor flag.

    When disabled, `get`/`has` always report a miss and `set` is a no-op --
    matching the reference implementation's `CacheService`'s `enabled` guard on `get`/`set`/`has`. `clear`
    always clears the underlying store regardless of `enabled`, mirroring the
    the reference implementation (its `clear()` has no `enabled` check).
    """

    def __init__(self, enabled: bool = True) -> None:
        self._cache: dict[str, Any] = {}
        self._enabled = enabled

    def get(self, key: str) -> Any | None:
        if not self._enabled:
            return None
        return self._cache.get(key)

    def set(self, key: str, value: Any) -> None:
        if self._enabled:
            self._cache[key] = value

    def has(self, key: str) -> bool:
        return self._enabled and key in self._cache

    def clear(self) -> None:
        self._cache.clear()

    def generate_key(self, *parts: str) -> str:
        return ":".join(parts)
