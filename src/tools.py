"""GDP MCP tool definitions — all @mcp.tool() functions live here."""

import json

from .discovery import GDPDiscovery


async def _ensure_discovered(discovery: GDPDiscovery, config) -> None:
    """Lazy-load endpoints on first tool call if not already loaded."""
    import logging

    logger = logging.getLogger("gdp_mcp")
    if not discovery.loaded:
        count = await discovery.discover(
            cache_path=config.cache_path, prefer_cache=True
        )
        if count == 0:
            logger.error("No GDP endpoints available — check connectivity and OAuth config")


def register_tools(mcp, config, discovery) -> None:
    """Register all GDP MCP tools on the given FastMCP server instance."""

    @mcp.tool()
    async def gdp_search_apis(
        query: str,
        category: str | None = None,
        verb: str | None = None,
    ) -> str:
        """Search GDP API endpoints by keyword.

        Use this to find available API operations. Returns matching endpoint names
        with HTTP methods, descriptions, and required parameters.

        Args:
            query: Search keyword (e.g. "datasource", "policy", "group", "report",
                   "vulnerability", "stap", "inspection")
            category: Optional — filter by category name
                      (e.g. "Datasource Builder", "Policy Builder", "Group Builder")
            verb: Optional — filter by HTTP method (GET, POST, PUT, DELETE)
        """
        await _ensure_discovered(discovery, config)
        results = discovery.search(query, category=category, verb=verb)
        if not results:
            cats = ", ".join(list(discovery.categories.keys())[:10])
            return (
                f"No endpoints matching '{query}'.\n"
                f"Try broader terms or use gdp_list_categories.\n"
                f"Sample categories: {cats}"
            )

        lines = [f"Found {len(results)} GDP API endpoint(s):\n"]
        for ep in results:
            req = ", ".join(ep.required_params) if ep.required_params else "none"
            lines.append(
                f"  {ep.verb:6s}  {ep.function_name}\n"
                f"         {ep.description[:120]}\n"
                f"         required params: {req}\n"
            )
        return "\n".join(lines)

    @mcp.tool()
    async def gdp_list_categories() -> str:
        """List all GDP API categories with endpoint counts.

        Use this to understand the scope of the GDP API and find the right
        category to search within.
        """
        await _ensure_discovered(discovery, config)
        cats = discovery.categories
        total = sum(cats.values())
        lines = [f"GDP API: {total} endpoints across {len(cats)} categories\n"]
        for cat, count in cats.items():
            lines.append(f"  {count:4d}  {cat}")
        return "\n".join(lines)

    @mcp.tool()
    async def gdp_get_api_details(api_function_name: str) -> str:
        """Get full parameter details for a specific GDP API endpoint.

        Call this before gdp_execute_api to understand what parameters are
        needed and what values are valid.

        Args:
            api_function_name: Exact function name (e.g. "list_group",
                               "create_datasource", "run_report_by_name")
        """
        await _ensure_discovered(discovery, config)
        ep = discovery.endpoints.get(api_function_name)
        if not ep:
            matches = [
                name
                for name in discovery.endpoints
                if api_function_name.lower() in name.lower()
            ]
            if matches:
                return (
                    f"Endpoint '{api_function_name}' not found. "
                    f"Similar: {', '.join(matches[:8])}"
                )
            return f"Endpoint '{api_function_name}' not found. Use gdp_search_apis to find endpoints."

        info = {
            "function_name": ep.function_name,
            "http_method": ep.verb,
            "resource_path": f"/restAPI/{ep.resource_name}",
            "category": ep.category,
            "version": ep.version,
            "description": ep.description,
            "parameters": [],
        }
        for p in ep.parameters:
            param_info: dict = {
                "name": p["parameterName"],
                "type": p["parameterType"].rsplit(".", 1)[-1],
                "required": p.get("isRequired", False),
                "description": p.get("parameterDescription", ""),
            }
            if p.get("parameterValues"):
                param_info["valid_values"] = p["parameterValues"]
            info["parameters"].append(param_info)

        return json.dumps(info, indent=2)

    @mcp.tool()
    async def gdp_execute_api(
        api_function_name: str,
        parameters: dict | None = None,
    ) -> str:
        """Execute a GDP REST API endpoint.

        Flow: gdp_search_apis → gdp_get_api_details → gdp_execute_api

        Args:
            api_function_name: Exact function name (e.g. "list_group")
            parameters: Dict of parameter key-value pairs for the API call.
                        Check gdp_get_api_details for required params.
        """
        await _ensure_discovered(discovery, config)
        ep = discovery.endpoints.get(api_function_name)
        if not ep:
            return f"Unknown endpoint '{api_function_name}'. Use gdp_search_apis to find endpoints."

        client = discovery._client
        try:
            result = await client.request(ep.verb, ep.resource_name, params=parameters)
            text = json.dumps(result, indent=2, default=str)
            # Truncate very large responses to avoid overwhelming the LLM context
            if len(text) > 30_000:
                count = len(result) if isinstance(result, list) else "N/A"
                text = (
                    f"Response truncated ({len(text):,} chars, {count} items). "
                    f"Showing first 30,000 chars:\n\n{text[:30_000]}\n\n"
                    f"... [truncated — use parameters to filter results]"
                )
            return text
        except Exception as exc:
            return (
                f"API call failed: {exc}\n\n"
                f"Endpoint: {ep.verb} /restAPI/{ep.resource_name}\n"
                f"Parameters: {parameters}\n"
                f"Check: Is the GDP appliance reachable? Is the OAuth client registered?"
            )
