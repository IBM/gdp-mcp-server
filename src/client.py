"""GDP REST API HTTP client with automatic Bearer-token injection."""

import logging
from typing import Any

import httpx

from .auth import GDPAuth
from .config import GDPConfig

logger = logging.getLogger(__name__)


class GDPClient:
    """Executes HTTP requests against the GDP REST API."""

    def __init__(self, config: GDPConfig, auth: GDPAuth) -> None:
        self._config = config
        self._auth = auth

    async def request(
        self,
        method: str,
        resource_name: str,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Make an authenticated request to the GDP REST API.

        GET           → parameters sent as query string
        POST/PUT/DELETE → parameters sent as JSON body
        """
        token = await self._auth.get_token()
        url = f"{self._config.base_url}/{resource_name}"
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }

        logger.debug("%s %s params=%s", method.upper(), url, params)

        async with httpx.AsyncClient(
            verify=self._config.verify_ssl, timeout=120.0
        ) as http:
            if method.upper() in ("GET",):
                resp = await http.request(
                    method.upper(), url, params=params, headers=headers
                )
            else:
                resp = await http.request(
                    method.upper(), url, json=params, headers=headers
                )

            # Retry once on 401 (token may have expired server-side)
            if resp.status_code == 401:
                logger.info("Got 401, refreshing token and retrying")
                self._auth.invalidate()
                token = await self._auth.get_token()
                headers["Authorization"] = f"Bearer {token}"
                if method.upper() in ("GET",):
                    resp = await http.request(
                        method.upper(), url, params=params, headers=headers
                    )
                else:
                    resp = await http.request(
                        method.upper(), url, json=params, headers=headers
                    )

            resp.raise_for_status()

            if resp.status_code == 204 or not resp.content:
                return {"status": "success", "http_code": resp.status_code}

            try:
                return resp.json()
            except ValueError:
                return {
                    "status": "success",
                    "http_code": resp.status_code,
                    "body": resp.text[:2000],
                }
