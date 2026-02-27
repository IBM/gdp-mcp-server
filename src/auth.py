"""OAuth2 password-grant token management for GDP REST API."""

import logging
import time

import httpx

from .config import GDPConfig

logger = logging.getLogger(__name__)


class GDPAuth:
    """Acquires and caches OAuth2 tokens using the password grant flow."""

    def __init__(self, config: GDPConfig) -> None:
        self._config = config
        self._token: str | None = None
        self._expires_at: float = 0

    async def get_token(self) -> str:
        """Return a valid Bearer token, refreshing if expired."""
        if self._token and time.time() < self._expires_at:
            return self._token
        return await self._acquire_token()

    async def _acquire_token(self) -> str:
        """Request a new token from the GDP OAuth endpoint."""
        logger.info("Requesting OAuth token from %s", self._config.token_url)
        async with httpx.AsyncClient(verify=self._config.verify_ssl, timeout=30.0) as http:
            resp = await http.post(
                self._config.token_url,
                data={
                    "grant_type": "password",
                    "client_id": self._config.client_id,
                    "client_secret": self._config.client_secret,
                    "username": self._config.username,
                    "password": self._config.password,
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            resp.raise_for_status()
            data = resp.json()

        expires_in = data.get("expires_in", 300)
        self._token = data["access_token"]
        self._expires_at = time.time() + expires_in - 30  # refresh 30s early
        logger.info("OAuth token acquired (expires in %ds)", expires_in)
        return self._token

    def invalidate(self) -> None:
        """Force token refresh on next call."""
        self._token = None
        self._expires_at = 0
