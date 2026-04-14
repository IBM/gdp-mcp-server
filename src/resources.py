"""GDP MCP Resources — expose GDP data as readable MCP resources.

Resources provide read-only access to GDP data that MCP clients can display
directly (e.g., in Claude's resource panel or VS Code's resource viewer).

Supported by: Claude Desktop, Claude Code, VS Code Copilot, Cursor (partial),
              Cline, Roo Code.

Resources registered:
  - gdp://appliances          — list of configured appliances with status
  - gdp://categories          — API categories with endpoint counts
  - gdp://endpoints/{name}    — details for a specific endpoint (template)
  - gdp://cli/reference       — complete Guard CLI command reference (~600 commands)
  - gdp://server/info         — server version, config, capabilities
"""

from __future__ import annotations

import json
import logging



logger = logging.getLogger("gdp_mcp")


def register_resources(mcp) -> None:
    """Register all GDP MCP resources on the given FastMCP instance."""

    # ── 1. Appliance list ───────────────────────────────────────

    @mcp.resource(
        "gdp://appliances",
        name="gdp_appliances",
        title="GDP Appliances",
        description="List of configured GDP appliances with connection details.",
        mime_type="application/json",
    )
    async def get_appliances() -> str:
        ctx = mcp.get_context()
        app = ctx.request_context.lifespan_context
        appliances = []
        for name in app.names:
            appl = app.get(name)
            appliances.append({
                "name": appl.name,
                "host": appl.config.host,
                "port": appl.config.port,
                "cli_enabled": appl.cli_client is not None,
                "is_default": name == app.default_name,
                "endpoints_loaded": appl.discovery.loaded,
                "endpoint_count": len(appl.discovery.endpoints) if appl.discovery.loaded else 0,
            })
        return json.dumps({
            "appliances": appliances,
            "total": len(appliances),
            "default": app.default_name,
            "multi_appliance": app.is_multi,
        }, indent=2)

    # ── 2. API categories ───────────────────────────────────────

    @mcp.resource(
        "gdp://categories",
        name="gdp_categories",
        title="GDP API Categories",
        description="All GDP REST API categories with endpoint counts.",
        mime_type="application/json",
    )
    async def get_categories() -> str:
        ctx = mcp.get_context()
        app = ctx.request_context.lifespan_context
        appl = app.get()  # default appliance
        if not appl.discovery.loaded:
            cache = appl.config.cache_path_for(appl.name) if app.is_multi else appl.config.cache_path
            await appl.discovery.discover(cache_path=cache, prefer_cache=True)
        cats = appl.discovery.categories
        return json.dumps({
            "appliance": appl.name,
            "categories": {cat: count for cat, count in cats.items()},
            "total_categories": len(cats),
            "total_endpoints": sum(cats.values()),
        }, indent=2)

    # ── 3. Endpoint details (template) ──────────────────────────

    @mcp.resource(
        "gdp://endpoints/{endpoint_name}",
        name="gdp_endpoint_details",
        title="GDP Endpoint Details",
        description="Full details for a specific GDP REST API endpoint including parameters.",
        mime_type="application/json",
    )
    async def get_endpoint_details(endpoint_name: str) -> str:
        ctx = mcp.get_context()
        app = ctx.request_context.lifespan_context
        appl = app.get()  # default appliance
        if not appl.discovery.loaded:
            cache = appl.config.cache_path_for(appl.name) if app.is_multi else appl.config.cache_path
            await appl.discovery.discover(cache_path=cache, prefer_cache=True)
        ep = appl.discovery.endpoints.get(endpoint_name)
        if not ep:
            return json.dumps({"error": f"Endpoint '{endpoint_name}' not found"})
        info = {
            "function_name": ep.function_name,
            "http_method": ep.verb,
            "resource_path": f"/restAPI/{ep.resource_name}",
            "category": ep.category,
            "version": ep.version,
            "description": ep.description,
            "appliance": appl.name,
            "parameters": [],
        }
        for p in ep.parameters:
            param_info = {
                "name": p["parameterName"],
                "type": p["parameterType"].rsplit(".", 1)[-1],
                "required": p.get("isRequired", False),
                "description": p.get("parameterDescription", ""),
            }
            if p.get("parameterValues"):
                param_info["valid_values"] = p["parameterValues"]
            info["parameters"].append(param_info)
        return json.dumps(info, indent=2)

    # ── 4. Server info ──────────────────────────────────────────

    # ── 5. CLI command reference ──────────────────────────────────

    @mcp.resource(
        "gdp://cli/reference",
        name="gdp_cli_reference",
        title="Guard CLI Command Reference",
        description=(
            "Complete reference of ~600 Guard CLI commands organized by category. "
            "Read this before using gdp_guard_cli() to find the correct command syntax."
        ),
        mime_type="text/markdown",
    )
    async def get_cli_reference() -> str:
        import importlib.resources as pkg_resources
        from pathlib import Path

        # Try docs/cli-reference.md relative to project root
        ref_path = Path(__file__).parent.parent / "docs" / "cli-reference.md"
        if ref_path.exists():
            return ref_path.read_text(encoding="utf-8")
        return "CLI reference not found. See docs/cli-reference.md in the GDP MCP Server project."

    # ── 6. Server info ──────────────────────────────────────────

    @mcp.resource(
        "gdp://server/info",
        name="gdp_server_info",
        title="GDP MCP Server Info",
        description="Server version, capabilities, and configuration summary.",
        mime_type="application/json",
    )
    async def get_server_info() -> str:
        ctx = mcp.get_context()
        app = ctx.request_context.lifespan_context
        return json.dumps({
            "server": "GDP MCP Server",
            "version": "2.0.0",
            "protocol": "2025-11-25",
            "features": {
                "tools": 5,
                "prompts": 8,
                "resources": 5,
                "completions": True,
                "progress": True,
                "logging": True,
                "tool_annotations": True,
                "multi_appliance": app.is_multi,
            },
            "appliances": app.names,
            "default_appliance": app.default_name,
        }, indent=2)
