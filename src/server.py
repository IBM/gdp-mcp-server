"""GDP MCP Server — exposes IBM Guardium Data Protection APIs as MCP tools.

Targets MCP spec 2025-11-25:
  - Streamable HTTP transport (POST /mcp) — replaces SSE
  - stdio transport for local/IDE integration
  - API key authentication via admin-managed key store
  - Lifespan API — no global state; tools access deps via ctx
  - Multi-appliance support — manage multiple GDP appliances from one server
"""

import argparse
import logging
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field

from mcp.server.fastmcp import FastMCP
from mcp.server.sse import SseServerTransport
from mcp.server.transport_security import TransportSecuritySettings
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.responses import JSONResponse
from starlette.routing import Mount, Route

from . import keystore
from .auth import GDPAuth
from .cli import GDPCLIClient
from .client import GDPClient
from .config import GDPConfig, load_appliance_names
from .discovery import GDPDiscovery
from .prompts import register_prompts
from .completions import register_completions
from .resources import register_resources
from .tools import register_tools

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)-8s %(name)s — %(message)s",
)
logger = logging.getLogger("gdp_mcp")


# ── Per-appliance context ───────────────────────────────────────

@dataclass
class ApplianceContext:
    """Runtime deps for a single GDP appliance."""
    name: str
    config: GDPConfig
    auth: GDPAuth
    client: GDPClient
    discovery: GDPDiscovery
    cli_client: GDPCLIClient | None


@dataclass
class AppContext:
    """Top-level lifespan context holding all appliances."""
    appliances: dict[str, ApplianceContext] = field(default_factory=dict)
    default_name: str = "default"

    def get(self, name: str | None = None) -> ApplianceContext:
        """Resolve an appliance by name. Returns default when name is None."""
        key = (name or self.default_name).lower()
        if key not in self.appliances:
            available = ", ".join(sorted(self.appliances))
            raise KeyError(
                f"Appliance '{key}' not found. Available: {available}"
            )
        return self.appliances[key]

    @property
    def names(self) -> list[str]:
        return sorted(self.appliances)

    @property
    def is_multi(self) -> bool:
        return len(self.appliances) > 1


def _build_appliance(name: str, config: GDPConfig) -> ApplianceContext:
    """Create an ApplianceContext from a config."""
    auth = GDPAuth(config)
    client = GDPClient(config, auth)
    discovery = GDPDiscovery(client)
    cli_client = GDPCLIClient(config) if config.cli_pass else None
    return ApplianceContext(
        name=name,
        config=config,
        auth=auth,
        client=client,
        discovery=discovery,
        cli_client=cli_client,
    )


@asynccontextmanager
async def app_lifespan(server: FastMCP) -> AsyncIterator[AppContext]:
    """Initialize GDP appliance(s) at startup, tear down on shutdown."""
    app = AppContext()
    appliance_names = load_appliance_names()

    if appliance_names:
        # Multi-appliance mode
        app.default_name = appliance_names[0]
        for name in appliance_names:
            prefix = f"GDP_{name.upper()}"
            config = GDPConfig.from_prefix(prefix)
            ctx = _build_appliance(name, config)
            app.appliances[name] = ctx
            logger.info(
                "Appliance '%s': %s:%s (CLI: %s)",
                name, config.host, config.port,
                "enabled" if ctx.cli_client else "disabled",
            )
        logger.info(
            "GDP MCP Server v2.0.0 — %d appliances, default: %s",
            len(app.appliances), app.default_name,
        )
    else:
        # Single-appliance mode (backward compatible)
        config = GDPConfig()
        ctx = _build_appliance("default", config)
        app.appliances["default"] = ctx
        app.default_name = "default"
        logger.info(
            "GDP MCP Server v2.0.0 — target: %s:%s (CLI: %s)",
            config.host, config.port,
            "enabled" if ctx.cli_client else "disabled",
        )

    yield app
    logger.info("GDP MCP Server shutting down")


# ── FastMCP instance ───────────────────────────────────────────

mcp = FastMCP(
    "GDP MCP Server",
    instructions=(
        "AI interface to IBM Guardium Data Protection. "
        "Provides access to all GDP REST API endpoints for querying, "
        "configuring, and managing GDP appliances. "
        "Workflow: gdp_search_apis → gdp_get_api_details → gdp_execute_api. "
        "For system-level operations, use gdp_guard_cli (Guard CLI over SSH). "
        "When multiple appliances are configured, pass the 'appliance' parameter "
        "to target a specific one (omit to use the default)."
    ),
    stateless_http=True,
    streamable_http_path="/mcp",
    lifespan=app_lifespan,
    transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
)

# Register tool definitions (no runtime objects needed — tools pull deps from ctx)
register_tools(mcp)

# Register report template prompts for standardized output
register_prompts(mcp)

# Register completion handler for auto-complete suggestions
register_completions(mcp)

# Register GDP resources for client resource panels
register_resources(mcp)


# ── API Key Middleware ──────────────────────────────────────────


class APIKeyMiddleware:
    """Pure ASGI middleware for API key validation.

    Uses raw ASGI interface instead of BaseHTTPMiddleware so that
    SSE streaming connections are not buffered.
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")

        # Always allow health checks and admin endpoints without API key
        if path == "/health" or path.startswith("/admin"):
            await self.app(scope, receive, send)
            return

        # Extract Authorization header from raw ASGI headers
        headers = dict(scope.get("headers", []))
        auth_value = headers.get(b"authorization", b"").decode()
        token = auth_value.removeprefix("Bearer ").strip()

        if keystore.validate_key(token) is None:
            client = scope.get("client")
            client_host = client[0] if client else "unknown"
            logger.warning(
                "Unauthorized request from %s to %s", client_host, path,
            )
            response = JSONResponse(
                {"error": "Unauthorized", "message": "Invalid or missing API key"},
                status_code=401,
            )
            await response(scope, receive, send)
            return

        await self.app(scope, receive, send)


# ── Streamable HTTP App with Auth + Admin ───────────────────────


def _create_http_app(host: str = "0.0.0.0", port: int = 8003) -> Starlette:
    """Create a Starlette app wrapping FastMCP's Streamable HTTP transport.

    FastMCP.streamable_http_app() produces a Starlette app that registers
    the MCP endpoint at /mcp internally. We mount it at "/" so the final
    path stays /mcp, and add health + admin routes alongside it.

    IMPORTANT: Starlette does NOT propagate lifespan events to mounted
    sub-applications.  We must explicitly run the MCP session manager's
    lifespan in the outer app so the task group is initialized before
    any /mcp request arrives.
    """
    # FastMCP builds its own Streamable HTTP ASGI app with /mcp route inside
    # (also lazily creates the session manager)
    mcp_http_app = mcp.streamable_http_app()

    # SSE transport for legacy clients (e.g. IBM Bob) that don't support streamable HTTP
    sse_transport = SseServerTransport("/messages/")

    class SSEHandler:
        """Raw ASGI app for SSE connections.

        Must be a callable class (not a plain function) so Starlette's Route
        treats it as a raw ASGI app instead of wrapping it with
        request_response() — which would expect a Response return value
        and crash with 'NoneType is not callable' on the None return.
        """

        async def __call__(self, scope, receive, send):
            async with sse_transport.connect_sse(
                scope, receive, send
            ) as (read_stream, write_stream):
                init_options = mcp._mcp_server.create_initialization_options()
                await mcp._mcp_server.run(read_stream, write_stream, init_options)

    handle_sse_connection = SSEHandler()

    @asynccontextmanager
    async def lifespan(app):
        async with mcp.session_manager.run():
            # Eager discovery — populate cache at startup so first tool call
            # doesn't block for ~90s (which would exceed client timeouts).
            appliance_names = load_appliance_names()
            if appliance_names:
                for name in appliance_names:
                    prefix = f"GDP_{name.upper()}"
                    cfg = GDPConfig.from_prefix(prefix)
                    cache = cfg.cache_path_for(name)
                    auth = GDPAuth(cfg)
                    client = GDPClient(cfg, auth)
                    disc = GDPDiscovery(client)
                    try:
                        count = await disc.discover(cache_path=cache)
                        logger.info("Startup discovery '%s': %d endpoints cached", name, count)
                    except Exception as exc:
                        logger.warning("Startup discovery '%s' failed: %s", name, exc)
            else:
                cfg = GDPConfig()
                auth = GDPAuth(cfg)
                client = GDPClient(cfg, auth)
                disc = GDPDiscovery(client)
                try:
                    count = await disc.discover(cache_path=cfg.cache_path)
                    logger.info("Startup discovery: %d endpoints cached", count)
                except Exception as exc:
                    logger.warning("Startup discovery failed: %s", exc)
            yield

    async def health(request):
        names = load_appliance_names()
        if names:
            targets = {
                n: f"{GDPConfig.from_prefix(f'GDP_{n.upper()}').host}:"
                   f"{GDPConfig.from_prefix(f'GDP_{n.upper()}').port}"
                for n in names
            }
        else:
            cfg = GDPConfig()
            targets = {"default": f"{cfg.host}:{cfg.port}"}
        return JSONResponse({
            "status": "ok",
            "server": "GDP MCP Server",
            "version": "2.0.0",
            "protocol": "2025-11-25",
            "transports": {
                "streamable_http": "/mcp",
                "sse": "/sse",
            },
            "auth_required": True,
            "active_keys": len(keystore.list_keys()),
            "appliances": targets,
        })

    # ── Admin endpoints (localhost only) ────────────────────────

    _ADMIN_ALLOWED_IPS = {"127.0.0.1", "::1", "localhost", "172.17.0.1"}

    def _is_localhost(request) -> bool:
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

    middleware = [Middleware(APIKeyMiddleware)]
    logger.info("API key authentication enforced for all transport connections")
    logger.info("Key store: %s", keystore.KEY_STORE_PATH)
    logger.info("Active keys: %d", len(keystore.list_keys()))

    return Starlette(
        debug=False,
        routes=[
            Route("/health", health),
            Route("/admin/keys", admin_create_key, methods=["POST"]),
            Route("/admin/keys", admin_list_keys, methods=["GET"]),
            Route("/admin/keys/{key_prefix}", admin_revoke_key, methods=["DELETE"]),
            # SSE transport — for clients that don't support streamable HTTP
            Route("/sse", handle_sse_connection, methods=["GET"]),
            Mount("/messages/", app=sse_transport.handle_post_message),
            # Streamable HTTP transport — /mcp endpoint (must be last)
            Mount("/", app=mcp_http_app),
        ],
        middleware=middleware,
        lifespan=lifespan,
    )


# ── Entry point ─────────────────────────────────────────────────


def _resolve_ssl(args) -> tuple[str | None, str | None]:
    """Resolve SSL cert/key paths.

    Priority: CLI args > env vars > self-signed generation.
    Returns (certfile, keyfile) or (None, None) for plain HTTP.
    """
    certfile = args.ssl_certfile or os.getenv("MCP_SSL_CERTFILE")
    keyfile = args.ssl_keyfile or os.getenv("MCP_SSL_KEYFILE")

    if certfile and keyfile:
        return certfile, keyfile

    # Auto-generate self-signed cert if requested
    self_signed = (
        args.ssl_self_signed
        or os.getenv("MCP_SSL_SELF_SIGNED", "false").lower() == "true"
    )
    if self_signed:
        return _generate_self_signed_cert()

    return None, None


def _generate_self_signed_cert(
    cert_dir: str = "/certs",
) -> tuple[str, str]:
    """Generate a self-signed TLS certificate for the MCP server."""
    import subprocess
    from pathlib import Path

    cert_path = Path(cert_dir)
    cert_path.mkdir(parents=True, exist_ok=True)
    certfile = str(cert_path / "server.pem")
    keyfile = str(cert_path / "server-key.pem")

    if Path(certfile).exists() and Path(keyfile).exists():
        logger.info("Using existing self-signed cert: %s", certfile)
        return certfile, keyfile

    logger.info("Generating self-signed TLS certificate in %s", cert_dir)
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", keyfile, "-out", certfile,
            "-days", "365", "-nodes",
            "-subj", "/CN=gdp-mcp-server",
        ],
        check=True,
        capture_output=True,
    )
    logger.info("Self-signed cert generated: %s", certfile)
    return certfile, keyfile


def main() -> None:
    """Start the GDP MCP Server (stdio or streamable-http transport)."""
    parser = argparse.ArgumentParser(description="GDP MCP Server")
    parser.add_argument(
        "--transport",
        choices=["stdio", "streamable-http"],
        default=os.getenv("MCP_TRANSPORT", "stdio").lower(),
        help="Transport mode: stdio (default) or streamable-http",
    )
    parser.add_argument(
        "--host",
        default=os.getenv("MCP_HOST", "0.0.0.0"),
        help="Host to bind HTTP server (default: 0.0.0.0)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.getenv("MCP_PORT", "8003")),
        help="Port for HTTP server (default: 8003)",
    )
    parser.add_argument(
        "--ssl-certfile",
        default=None,
        help="Path to SSL certificate file (PEM). Env: MCP_SSL_CERTFILE",
    )
    parser.add_argument(
        "--ssl-keyfile",
        default=None,
        help="Path to SSL private key file (PEM). Env: MCP_SSL_KEYFILE",
    )
    parser.add_argument(
        "--ssl-self-signed",
        action="store_true",
        default=False,
        help="Auto-generate a self-signed cert if no cert files provided. Env: MCP_SSL_SELF_SIGNED=true",
    )
    args = parser.parse_args()

    cfg = GDPConfig()
    logger.info(
        "GDP MCP Server v2.0.0 starting — target: %s:%s (transport: %s)",
        cfg.host,
        cfg.port,
        args.transport,
    )

    if args.transport == "streamable-http":
        import uvicorn

        ssl_certfile, ssl_keyfile = _resolve_ssl(args)
        scheme = "https" if ssl_certfile else "http"

        logger.info("Streamable HTTP on %s:%d (%s)", args.host, args.port, scheme.upper())
        logger.info("Streamable HTTP endpoint: %s://%s:%d/mcp", scheme, args.host, args.port)
        logger.info("SSE endpoint: %s://%s:%d/sse", scheme, args.host, args.port)
        if ssl_certfile:
            logger.info("TLS enabled — cert: %s, key: %s", ssl_certfile, ssl_keyfile)

        starlette_app = _create_http_app(args.host, args.port)

        uvicorn_kwargs: dict = {
            "host": args.host,
            "port": args.port,
        }
        if ssl_certfile:
            uvicorn_kwargs["ssl_certfile"] = ssl_certfile
            uvicorn_kwargs["ssl_keyfile"] = ssl_keyfile

        uvicorn.run(starlette_app, **uvicorn_kwargs)
    else:
        logger.info("stdio mode — no API key auth (direct process communication)")
        mcp.run(transport="stdio")
