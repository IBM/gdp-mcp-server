"""Configuration management for GDP MCP Server."""

import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv


def _load_env() -> None:
    """Load .env from project root."""
    project_root = Path(__file__).resolve().parents[1]
    load_dotenv(project_root / ".env")


_load_env()


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

    @property
    def base_url(self) -> str:
        return f"https://{self.host}:{self.port}/restAPI"

    @property
    def token_url(self) -> str:
        return f"https://{self.host}:{self.port}/oauth/token"

    @property
    def cache_path(self) -> Path:
        return Path(__file__).resolve().parents[1] / "gdp_discovery_with_params.json"
