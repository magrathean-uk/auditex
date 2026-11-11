"""Provider collector metadata supplied by the embedding application.

Loaders keep optional providers lazy. An engine-only process has no registered
providers and receives an empty mapping; explicit caller registries still work.
"""

from collections.abc import Callable, Mapping
from typing import Any

_loaders: dict[str, Callable[[], Mapping[str, Any]]] = {}


def register_provider(provider: str, loader: Callable[[], Mapping[str, Any]]) -> None:
    """Register or replace a provider's collector registry loader."""
    _loaders[provider] = loader


def provider_collectors(provider: str) -> Mapping[str, Any]:
    """Return current collector metadata, without caching a provider's registry."""
    loader = _loaders.get(provider)
    return loader() if loader is not None else {}
