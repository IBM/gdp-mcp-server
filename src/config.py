"""Configuration management for GDP MCP Server.

Single-appliance mode (default):
    Set GDP_HOST, GDP_PORT, GDP_USERNAME, GDP_PASSWORD, etc.

Multi-appliance mode:
    Set GDP_APPLIANCES=cm01,cm02,collector01 (comma-separated names)
    Then prefix each appliance's vars:
        GDP_CM01_HOST=..., GDP_CM01_PORT=..., GDP_CM01_USERNAME=..., etc.
    The first name in the list becomes the default appliance.

    Shared credentials: If a per-appliance var is not set, falls back to the
    unprefixed GDP_* vars (so you only need to override what differs).
"""

import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv


def _load_env() -> None:
    """Load .env from project root."""
    project_root = Path(__file__).resolve().parents[1]
    load_dotenv(project_root / ".env")


_load_env()

_CACHE_DIR = Path(__file__).resolve().parents[1]


def _env(key: str, default: str = "") -> str:
    return os.getenv(key, default)


@dataclass(frozen=True)
class GDPConfig:
    """GDP connection configuration resolved from environment variables.

    Resolution order for host/port:
      1. GDP_EXTERNAL_HOST / GDP_EXTERNAL_PORT  (cloud / NAT / tunnel access)
      2. GDP_HOST / GDP_PORT                    (direct appliance access)
    """

    host: str = field(default_factory=lambda: os.getenv("GDP_EXTERNAL_HOST") or os.getenv("GDP_HOST", "localhost"))
    port: str = field(default_factory=lambda: os.getenv("GDP_EXTERNAL_PORT") or os.getenv("GDP_PORT", "8443"))
    client_id: str = field(default_factory=lambda: os.getenv("GDP_CLIENT_ID", ""))
    client_secret: str = field(default_factory=lambda: os.getenv("GDP_CLIENT_SECRET", ""))
    username: str = field(default_factory=lambda: os.getenv("GDP_USERNAME", ""))
    password: str = field(default_factory=lambda: os.getenv("GDP_PASSWORD", ""))
    verify_ssl: bool = field(default_factory=lambda: os.getenv("GDP_VERIFY_SSL", "false").lower() == "true")

    # Guard CLI (SSH) — optional, only needed for gdp_guard_cli
    cli_host: str = field(default_factory=lambda: os.getenv("GDP_CLI_HOST") or os.getenv("GDP_EXTERNAL_HOST") or os.getenv("GDP_HOST", "localhost"))
    cli_port: int = field(default_factory=lambda: int(os.getenv("GDP_CLI_PORT", "2222")))
    cli_user: str = field(default_factory=lambda: os.getenv("GDP_CLI_USER", "cli"))
    cli_pass: str = field(default_factory=lambda: os.getenv("GDP_CLI_PASS", ""))

    @property
    def base_url(self) -> str:
        return f"https://{self.host}:{self.port}/restAPI"

    @property
    def token_url(self) -> str:
        return f"https://{self.host}:{self.port}/oauth/token"

    @property
    def cache_path(self) -> Path:
        return _CACHE_DIR / "gdp_discovery_with_params.json"

    @classmethod
    def from_prefix(cls, prefix: str) -> "GDPConfig":
        """Create config from prefixed env vars, falling back to unprefixed GDP_*.

        Example: prefix="GDP_CM01" reads GDP_CM01_HOST, GDP_CM01_PORT, etc.
        If GDP_CM01_HOST is not set, falls back to GDP_HOST.
        """
        def _get(suffix: str, fallback_key: str, default: str = "") -> str:
            return os.getenv(f"{prefix}_{suffix}") or os.getenv(fallback_key, default)

        host = (
            os.getenv(f"{prefix}_EXTERNAL_HOST")
            or os.getenv(f"{prefix}_HOST")
            or os.getenv("GDP_EXTERNAL_HOST")
            or os.getenv("GDP_HOST", "localhost")
        )
        port = (
            os.getenv(f"{prefix}_EXTERNAL_PORT")
            or os.getenv(f"{prefix}_PORT")
            or os.getenv("GDP_EXTERNAL_PORT")
            or os.getenv("GDP_PORT", "8443")
        )
        cli_host = (
            os.getenv(f"{prefix}_CLI_HOST")
            or os.getenv(f"{prefix}_EXTERNAL_HOST")
            or os.getenv(f"{prefix}_HOST")
            or os.getenv("GDP_CLI_HOST")
            or os.getenv("GDP_EXTERNAL_HOST")
            or os.getenv("GDP_HOST", "localhost")
        )

        return cls(
            host=host,
            port=port,
            client_id=_get("CLIENT_ID", "GDP_CLIENT_ID"),
            client_secret=_get("CLIENT_SECRET", "GDP_CLIENT_SECRET"),
            username=_get("USERNAME", "GDP_USERNAME"),
            password=_get("PASSWORD", "GDP_PASSWORD"),
            verify_ssl=_get("VERIFY_SSL", "GDP_VERIFY_SSL", "false").lower() == "true",
            cli_host=cli_host,
            cli_port=int(_get("CLI_PORT", "GDP_CLI_PORT", "2222")),
            cli_user=_get("CLI_USER", "GDP_CLI_USER", "cli"),
            cli_pass=_get("CLI_PASS", "GDP_CLI_PASS"),
        )

    def cache_path_for(self, name: str) -> Path:
        """Return an appliance-specific discovery cache path."""
        return _CACHE_DIR / f"gdp_discovery_{name}.json"


def load_appliance_names() -> list[str]:
    """Return configured appliance names from GDP_APPLIANCES env var.

    Returns an empty list when only a single (default) appliance is configured.
    """
    raw = os.getenv("GDP_APPLIANCES", "").strip()
    if not raw:
        return []
    return [name.strip().lower() for name in raw.split(",") if name.strip()]
