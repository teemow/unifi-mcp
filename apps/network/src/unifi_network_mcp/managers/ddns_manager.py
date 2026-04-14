"""Dynamic DNS management for UniFi Network MCP server.

DDNS configurations are stored in the /rest/dynamicdns API endpoint.
Each DDNS entry represents a dynamic DNS service configured on a WAN interface
(e.g., Cloudflare, DynDNS, No-IP, etc.).

The UCG Ultra and other UniFi OS gateways support DDNS natively. The controller
manages these via the standard REST API pattern: GET/POST/PUT/DELETE on
/rest/dynamicdns[/{id}].
"""

import logging
from typing import Any, Dict, List, Optional

from aiounifi.models.api import ApiRequest

from .connection_manager import ConnectionManager

logger = logging.getLogger("unifi-network-mcp")

CACHE_PREFIX_DDNS = "ddns_configs"

SENSITIVE_FIELDS = frozenset({
    "x_password",
    "x_api_token",
})


def redact_sensitive_fields(data: Dict[str, Any]) -> Dict[str, Any]:
    """Return a copy of data with sensitive credentials replaced by a placeholder."""
    return {
        k: "<REDACTED>" if k in SENSITIVE_FIELDS else v
        for k, v in data.items()
    }


class DdnsManager:
    """Manages Dynamic DNS operations on the UniFi controller."""

    def __init__(self, connection_manager: ConnectionManager):
        self._connection = connection_manager

    async def list_ddns_configs(self) -> List[Dict[str, Any]]:
        """List all Dynamic DNS configurations.

        Returns:
            List of DDNS config dicts with sensitive fields redacted.
        """
        cache_key = f"{CACHE_PREFIX_DDNS}_{self._connection.site}"
        cached_data = self._connection.get_cached(cache_key)
        if cached_data is not None:
            return cached_data

        try:
            api_request = ApiRequest(method="get", path="/rest/dynamicdns")
            response = await self._connection.request(api_request)

            if isinstance(response, dict) and "data" in response:
                configs = response["data"]
            elif isinstance(response, list):
                configs = response
            else:
                logger.warning("Unexpected dynamicdns response format: %s", type(response))
                configs = []

            configs = [redact_sensitive_fields(c) for c in configs]
            self._connection._update_cache(cache_key, configs)
            return configs

        except Exception as e:
            logger.error("Error listing DDNS configurations: %s", e)
            return []

    async def get_ddns_config(self, config_id: str) -> Optional[Dict[str, Any]]:
        """Get a single DDNS configuration by ID.

        Args:
            config_id: The _id of the DDNS configuration.

        Returns:
            DDNS config dict with sensitive fields redacted, or None.
        """
        try:
            api_request = ApiRequest(method="get", path=f"/rest/dynamicdns/{config_id}")
            response = await self._connection.request(api_request)

            if isinstance(response, dict) and "data" in response:
                items = response["data"]
            elif isinstance(response, list):
                items = response
            else:
                items = [response] if isinstance(response, dict) else []

            if not items:
                return None
            return redact_sensitive_fields(items[0])

        except Exception as e:
            logger.error("Error getting DDNS config %s: %s", config_id, e)
            return None

    async def create_ddns_config(self, config_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Create a new Dynamic DNS configuration.

        Expected fields:
            - service: DDNS provider (e.g. "cloudflare", "dyndns", "noip")
            - host_name: FQDN to update (e.g. "vpn.home.example.com")
            - login: Username/email for the DDNS service
            - x_password: API token or password (sensitive)
            - interface: WAN interface identifier (e.g. "wan", "wan2", "wan3")
            - server: Optional custom server/API endpoint
            - enabled: bool (default true)

        Args:
            config_data: Dict with DDNS configuration fields.

        Returns:
            Created config dict (sensitive fields redacted), or None on failure.
        """
        try:
            api_request = ApiRequest(
                method="post",
                path="/rest/dynamicdns",
                data=config_data,
            )
            response = await self._connection.request(api_request)

            if isinstance(response, dict) and "data" in response:
                items = response["data"]
            elif isinstance(response, list):
                items = response
            else:
                items = [response] if isinstance(response, dict) else []

            self._invalidate_cache()

            if not items:
                logger.error("Empty response when creating DDNS config")
                return None

            config = items[0]
            logger.info(
                "Created DDNS config '%s' for host '%s'",
                config.get("_id"),
                config.get("host_name"),
            )
            return redact_sensitive_fields(config)

        except Exception as e:
            logger.error("Error creating DDNS config: %s", e)
            return None

    async def update_ddns_config(self, config_id: str, update_data: Dict[str, Any]) -> bool:
        """Update an existing DDNS configuration (fetch-merge-put).

        Args:
            config_id: The _id of the config to update.
            update_data: Dict of fields to update.

        Returns:
            True on success, False on failure.
        """
        try:
            api_request = ApiRequest(method="get", path=f"/rest/dynamicdns/{config_id}")
            response = await self._connection.request(api_request)

            if isinstance(response, dict) and "data" in response:
                items = response["data"]
            elif isinstance(response, list):
                items = response
            else:
                items = [response] if isinstance(response, dict) else []

            if not items:
                logger.error("DDNS config %s not found for update", config_id)
                return False

            merged = dict(items[0])
            merged.update(update_data)

            put_request = ApiRequest(
                method="put",
                path=f"/rest/dynamicdns/{config_id}",
                data=merged,
            )
            await self._connection.request(put_request)

            self._invalidate_cache()
            logger.info("Updated DDNS config %s", config_id)
            return True

        except Exception as e:
            logger.error("Error updating DDNS config %s: %s", config_id, e)
            return False

    async def delete_ddns_config(self, config_id: str) -> bool:
        """Delete a DDNS configuration.

        Args:
            config_id: The _id of the config to delete.

        Returns:
            True on success, False on failure.
        """
        try:
            api_request = ApiRequest(method="delete", path=f"/rest/dynamicdns/{config_id}")
            await self._connection.request(api_request)
            self._invalidate_cache()
            logger.info("Deleted DDNS config %s", config_id)
            return True

        except Exception as e:
            logger.error("Error deleting DDNS config %s: %s", config_id, e)
            return False

    def _invalidate_cache(self) -> None:
        self._connection._invalidate_cache(f"{CACHE_PREFIX_DDNS}_{self._connection.site}")
