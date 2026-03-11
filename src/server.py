"""GDP MCP Server — exposes IBM Guardium Data Protection APIs as MCP tools.

Supports stdio and SSE transports. SSE mode enforces API key authentication
via an admin-managed key store (per-user keys, SHA-256 hashed, revocable).
"""

import argparse
import asyncio
import logging
import os

from mcp.server.fastmcp import FastMCP
from mcp.server.sse import SseServerTransport
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Mount, Route

from . import keystore
from .auth import GDPAuth
from .client import GDPClient
from .config import GDPConfig
from .discovery import GDPDiscovery
from .tools import register_tools

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)-8s %(name)s — %(message)s",
)
logger = logging.getLogger("gdp_mcp")

# ── Bootstrap ───────────────────────────────────────────────────

config = GDPConfig()
auth = GDPAuth(config)
client = GDPClient(config, auth)
discovery = GDPDiscovery(client)

mcp = FastMCP(
    "GDP MCP Server",
    instructions=(
        "AI interface to IBM Guardium Data Protection. "
        "Provides access to all GDP REST API endpoints for querying, "
        "configuring, and managing GDP appliances. "
        "Workflow: gdp_search_apis → gdp_get_api_details → gdp_execute_api."
    ),
)

# Register all tools from tools.py
register_tools(mcp, config, discovery)


# ── SSE App with Auth + Admin ───────────────────────────────────


def _create_sse_app(host: str = "0.0.0.0", port: int = 8003) -> Starlette:
    """Create a Starlette app with SSE transport, API key auth, and admin endpoints."""
    sse = SseServerTransport("/messages/")

    # Get the underlying MCP server from FastMCP
    mcp_server = mcp._mcp_server

    def _check_key(request) -> bool:
        """Validate API key from Authorization header against key store."""
        auth_header = request.headers.get("Authorization", "")
        token = auth_header.removeprefix("Bearer ").strip()
        return keystore.validate_key(token) is not None

    _UNAUTHORIZED = JSONResponse(
        {"error": "Unauthorized", "message": "Invalid or missing API key"},
        status_code=401,
    )

    # --- MCP SSE handlers (auth checked inline — BaseHTTPMiddleware
    #     is incompatible with raw ASGI SSE streaming) ---
    async def handle_sse(request):
        if not _check_key(request):
            return _UNAUTHORIZED
        async with sse.connect_sse(
            request.scope, request.receive, request._send
        ) as (read_stream, write_stream):
            await mcp_server.run(
                read_stream,
                write_stream,
                mcp_server.create_initialization_options(),
            )

    async def health(request):
        return JSONResponse({
            "status": "ok",
            "server": "GDP MCP Server",
            "version": "1.0.0",
            "transport": "sse",
            "auth_required": True,
            "active_keys": len(keystore.list_keys()),
            "target": f"{config.host}:{config.port}",
        })

    # ── Admin endpoints (localhost only) ────────────────────────

    _ADMIN_ALLOWED_IPS = {"127.0.0.1", "::1", "localhost", "172.17.0.1"}

    def _is_localhost(request) -> bool:
        """Check if request originates from localhost or Docker host."""
        client_host = request.client.host if request.client else None
        return client_host in _ADMIN_ALLOWED_IPS

    async def admin_create_key(request):
        if not _is_localhost(request):
            return JSONResponse(
                {"error": "Forbidden", "message": "Admin endpoints are localhost only"},
                status_code=403,
            )
        try:
            body = await request.json()
            user = body.get("user", "").strip()
        except Exception:
            user = ""
        if not user:
            return JSONResponse(
                {"error": "Bad Request", "message": "'user' field is required"},
                status_code=400,
            )
        result = keystore.generate_key(user)
        return JSONResponse(result, status_code=201)

    async def admin_list_keys(request):
        if not _is_localhost(request):
            return JSONResponse(
                {"error": "Forbidden", "message": "Admin endpoints are localhost only"},
                status_code=403,
            )
        return JSONResponse(keystore.list_keys())

    async def admin_revoke_key(request):
        if not _is_localhost(request):
            return JSONResponse(
                {"error": "Forbidden", "message": "Admin endpoints are localhost only"},
                status_code=403,
            )
        key_prefix = request.path_params["key_prefix"]
        result = keystore.revoke_key(key_prefix)
        if result is None:
            return JSONResponse(
                {"error": "Not Found", "message": f"No key with prefix '{key_prefix}'"},
                status_code=404,
            )
        return JSONResponse(result)

    # ── Wire it all together ────────────────────────────────────

    logger.info("API key authentication enforced for all SSE connections (inline)")
    logger.info("Key store: %s", keystore.KEY_STORE_PATH)
    logger.info("Active keys: %d", len(keystore.list_keys()))

    return Starlette(
        debug=False,
        routes=[
            Route("/health", health),
            Route("/sse", endpoint=handle_sse),
            Mount("/messages/", app=sse.handle_post_message),
            Route("/admin/keys", admin_create_key, methods=["POST"]),
            Route("/admin/keys", admin_list_keys, methods=["GET"]),
            Route("/admin/keys/{key_prefix}", admin_revoke_key, methods=["DELETE"]),
        ],
    )


# ── Entry point ─────────────────────────────────────────────────


def main() -> None:
    """Start the GDP MCP Server (stdio or SSE transport)."""
    parser = argparse.ArgumentParser(description="GDP MCP Server")
    parser.add_argument(
        "--transport",
        choices=["stdio", "sse"],
        default=os.getenv("MCP_TRANSPORT", "stdio").lower(),
        help="Transport mode: stdio (default) or sse",
    )
    parser.add_argument(
        "--host",
        default=os.getenv("MCP_HOST", "0.0.0.0"),
        help="Host to bind SSE server (default: 0.0.0.0)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.getenv("MCP_PORT", "8003")),
        help="Port for SSE server (default: 8003)",
    )
    args = parser.parse_args()

    logger.info(
        "GDP MCP Server v1.0.0 starting — target: %s:%s (transport: %s)",
        config.host,
        config.port,
        args.transport,
    )

    if args.transport == "sse":
        import uvicorn

        logger.info("SSE mode on %s:%d", args.host, args.port)
        logger.info("Connect via: http://%s:%d/sse", args.host, args.port)
        starlette_app = _create_sse_app(args.host, args.port)
        uvicorn.run(starlette_app, host=args.host, port=args.port)
    else:
        logger.info("stdio mode — no API key auth (direct process communication)")
        mcp.run(transport="stdio")
