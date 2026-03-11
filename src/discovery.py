"""GDP endpoint discovery — fetches the full API catalog from the appliance."""

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .client import GDPClient

logger = logging.getLogger(__name__)


@dataclass
class GDPEndpoint:
    """A single GDP REST API endpoint with its metadata."""

    resource_id: int
    function_name: str
    resource_name: str
    verb: str
    category: str
    version: str
    description: str
    parameters: list[dict[str, Any]] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "GDPEndpoint":
        return cls(
            resource_id=data["resource_id"],
            function_name=data["api_function_name"],
            resource_name=data["resourceName"],
            verb=data["verb"],
            category=data.get("sql_app_name", "Unknown"),
            version=data.get("version", ""),
            description=data.get("apiDescription", ""),
            parameters=data.get("parameters", []),
        )

    @property
    def required_params(self) -> list[str]:
        return [p["parameterName"] for p in self.parameters if p.get("isRequired")]


class GDPDiscovery:
    """Discovers and indexes all GDP REST API endpoints."""

    def __init__(self, client: GDPClient) -> None:
        self._client = client
        self.endpoints: dict[str, GDPEndpoint] = {}
        self._categories: dict[str, list[str]] = {}

    @property
    def loaded(self) -> bool:
        return len(self.endpoints) > 0

    async def discover(self, cache_path: Path | None = None, prefer_cache: bool = False) -> int:
        """Fetch endpoints from the live appliance; fall back to cache file.

        When prefer_cache is True, load from cache first (fast startup) and
        skip live discovery.  Returns the number of endpoints loaded.
        """
        # Fast path: use cache when available and preferred
        if prefer_cache and cache_path and cache_path.exists():
            data = json.loads(cache_path.read_text())
            self._index(data)
            logger.info(
                "Loaded %d endpoints from cache (%s)",
                len(self.endpoints),
                cache_path.name,
            )
            return len(self.endpoints)

        # Try live discovery
        try:
            data = await self._client.request(
                "GET", "restapi", {"withParameters": "1"}
            )
            if isinstance(data, list) and len(data) > 0:
                self._index(data)
                if cache_path:
                    cache_path.write_text(json.dumps(data, indent=2))
                    logger.info("Cached %d endpoints to %s", len(self.endpoints), cache_path)
                logger.info(
                    "Live discovery: %d endpoints across %d categories",
                    len(self.endpoints),
                    len(self._categories),
                )
                return len(self.endpoints)
        except Exception as exc:
            logger.warning("Live discovery failed (%s), falling back to cache", exc)

        # Fall back to cached file
        if cache_path and cache_path.exists():
            data = json.loads(cache_path.read_text())
            self._index(data)
            logger.info(
                "Loaded %d endpoints from cache (%s)",
                len(self.endpoints),
                cache_path.name,
            )
            return len(self.endpoints)

        logger.error("No endpoints available — live discovery failed and no cache found")
        return 0

    def _index(self, raw: list[dict[str, Any]]) -> None:
        """Build the in-memory index from raw discovery JSON."""
        self.endpoints.clear()
        self._categories.clear()
        for item in raw:
            ep = GDPEndpoint.from_dict(item)
            self.endpoints[ep.function_name] = ep
            self._categories.setdefault(ep.category, []).append(ep.function_name)

    # ── Search helpers ──────────────────────────────────────────

    def search(
        self,
        query: str,
        category: str | None = None,
        verb: str | None = None,
        limit: int = 25,
    ) -> list[GDPEndpoint]:
        """Search endpoints by keyword in name, description, or category."""
        q = query.lower()
        results: list[GDPEndpoint] = []
        for ep in self.endpoints.values():
            if category and ep.category.lower() != category.lower():
                continue
            if verb and ep.verb.upper() != verb.upper():
                continue
            if (
                q in ep.function_name.lower()
                or q in ep.description.lower()
                or q in ep.category.lower()
                or q in ep.resource_name.lower()
            ):
                results.append(ep)
        results.sort(key=lambda e: e.function_name)
        return results[:limit]

    @property
    def categories(self) -> dict[str, int]:
        """Return category names with their endpoint counts."""
        return {cat: len(fns) for cat, fns in sorted(self._categories.items())}
