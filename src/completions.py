"""GDP MCP Completions — auto-complete suggestions for tool arguments.

Provides completion values for:
  - category names (for gdp_search_apis category param)
  - API function names (for gdp_get_api_details / gdp_execute_api)
  - appliance names (for multi-appliance routing)
  - HTTP verbs (GET, POST, PUT, DELETE)

Supported by: Claude Desktop, Claude Code.
"""

from __future__ import annotations

import logging

from mcp.types import (
    Completion,
    CompletionArgument,
    CompletionContext,
    PromptReference,
    ResourceTemplateReference,
)

logger = logging.getLogger("gdp_mcp")


def register_completions(mcp) -> None:
    """Register the completion handler on the FastMCP instance."""

    @mcp.completion()
    async def handle_completion(
        ref: PromptReference | ResourceTemplateReference,
        argument: CompletionArgument,
        context: CompletionContext | None = None,
    ) -> Completion | None:
        """Provide auto-complete suggestions for GDP tool and prompt arguments."""

        # Only handle tool references (PromptReference for prompts)
        arg_name = argument.name
        partial = (argument.value or "").lower()

        # ── Appliance name completions ──────────────────────────
        if arg_name == "appliance":
            try:
                from .config import load_appliance_names
                names = load_appliance_names()
                if not names:
                    names = ["default"]
                matches = [n for n in names if n.lower().startswith(partial)]
                return Completion(values=matches[:20], total=len(matches))
            except Exception:
                return None

        # ── HTTP verb completions ───────────────────────────────
        if arg_name == "verb":
            verbs = ["GET", "POST", "PUT", "DELETE"]
            matches = [v for v in verbs if v.lower().startswith(partial)]
            return Completion(values=matches)

        # ── Category completions ────────────────────────────────
        if arg_name == "category":
            categories = _get_cached_categories()
            matches = [c for c in categories if partial in c.lower()]
            return Completion(
                values=matches[:50],
                total=len(matches),
                hasMore=len(matches) > 50,
            )

        # ── API function name completions ───────────────────────
        if arg_name in ("api_function_name", "query"):
            endpoints = _get_cached_endpoint_names()
            matches = [e for e in endpoints if partial in e.lower()]
            return Completion(
                values=matches[:50],
                total=len(matches),
                hasMore=len(matches) > 50,
            )

        # ── Framework completions (for compliance report) ───────
        if arg_name == "framework":
            frameworks = [
                "general", "SOX", "GDPR", "HIPAA", "PCI-DSS",
                "ISO-27001", "NIST", "SOC2",
            ]
            matches = [f for f in frameworks if f.lower().startswith(partial)]
            return Completion(values=matches)

        return None


# ── Cached data helpers ─────────────────────────────────────────
# These read from the discovery cache file to avoid needing a live connection
# just for completions. Returns empty lists if no cache is available.

_category_cache: list[str] = []
_endpoint_cache: list[str] = []


def _get_cached_categories() -> list[str]:
    """Return cached category names from discovery data."""
    global _category_cache
    if _category_cache:
        return _category_cache
    try:
        import json
        from pathlib import Path
        cache_dir = Path(__file__).resolve().parents[1]
        for cache_file in cache_dir.glob("gdp_discovery*.json"):
            data = json.loads(cache_file.read_text())
            cats = {item.get("sql_app_name", "Unknown") for item in data if isinstance(item, dict)}
            _category_cache = sorted(cats)
            return _category_cache
    except Exception:
        pass
    return []


def _get_cached_endpoint_names() -> list[str]:
    """Return cached endpoint function names from discovery data."""
    global _endpoint_cache
    if _endpoint_cache:
        return _endpoint_cache
    try:
        import json
        from pathlib import Path
        cache_dir = Path(__file__).resolve().parents[1]
        for cache_file in cache_dir.glob("gdp_discovery*.json"):
            data = json.loads(cache_file.read_text())
            names = {item.get("api_function_name", "") for item in data if isinstance(item, dict)}
            _endpoint_cache = sorted(n for n in names if n)
            return _endpoint_cache
    except Exception:
        pass
    return []
