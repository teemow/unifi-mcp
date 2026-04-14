"""VPN management for UniFi Network MCP server.

VPN configurations are stored in the networkconf API endpoint alongside regular
networks. They're identified by the 'purpose' field (vpn-client, vpn-server,
remote-user-vpn) and/or 'vpn_type' field (wireguard-client, openvpn-server, etc).

WireGuard peers are managed via the /rest/wireguardpeer API endpoint, separate
from the networkconf endpoint used for VPN server/client configurations.

Note: UniFi is developing a dedicated VPN API but it's not yet complete.
This implementation uses the networkconf endpoint which is the reliable approach.
"""

import logging
from typing import Any, Dict, List, Optional, Tuple

from aiounifi.models.api import ApiRequest

from unifi_core.merge import deep_merge

from .connection_manager import ConnectionManager

logger = logging.getLogger("unifi-network-mcp")

CACHE_PREFIX_VPN_CONFIGS = "vpn_configs"
CACHE_PREFIX_NETWORKS = "networks"
CACHE_PREFIX_WG_PEERS = "wg_peers"

SENSITIVE_FIELDS = frozenset({
    "x_wireguard_private_key",
    "x_wireguard_preshared_key",
    "x_openvpn_key",
    "x_openvpn_ca",
    "x_openvpn_cert",
    "x_psk",
})


def redact_sensitive_fields(data: Dict[str, Any]) -> Dict[str, Any]:
    """Return a copy of data with sensitive key material replaced by a placeholder."""
    return {
        k: "<REDACTED>" if k in SENSITIVE_FIELDS else v
        for k, v in data.items()
    }


def is_vpn_network(network: Dict[str, Any]) -> bool:
    """Check if a network configuration represents a VPN entity.

    Args:
        network: Network configuration dictionary

    Returns:
        True if this is a VPN configuration
    """
    purpose = str(network.get("purpose", "")).lower()
    vpn_type = str(network.get("vpn_type", "")).lower()

    return (
        purpose.startswith("vpn")
        or purpose in {"remote-user-vpn", "vpn-client", "vpn-server"}
        or "vpn" in vpn_type
        or "wireguard" in vpn_type
        or "openvpn" in vpn_type
    )


def classify_vpn_type(purpose: str, vpn_type: str) -> Tuple[bool, bool]:
    """Classify VPN configuration as client or server.

    Args:
        purpose: The purpose field from VPN config
        vpn_type: The vpn_type field from VPN config

    Returns:
        Tuple of (is_client, is_server)
    """
    purpose = str(purpose).lower() if purpose else ""
    vpn_type = str(vpn_type).lower() if vpn_type else ""

    is_client = purpose == "vpn-client" or "client" in vpn_type or vpn_type in {"wireguard-client", "openvpn-client"}

    is_server = (
        purpose in {"vpn-server", "remote-user-vpn"}
        or "server" in vpn_type
        or vpn_type in {"wireguard-server", "openvpn-server"}
    )

    return is_client, is_server


class VpnManager:
    """Manages VPN-related operations on the Unifi Controller.

    VPN configurations are retrieved from the networkconf API and filtered
    based on purpose and vpn_type fields.
    """

    def __init__(self, connection_manager: ConnectionManager):
        """Initialize the VPN Manager.

        Args:
            connection_manager: The shared ConnectionManager instance.
        """
        self._connection = connection_manager

    async def _get_all_network_configs(self) -> List[Dict[str, Any]]:
        """Get all network configurations from the controller.

        Returns:
            List of network configuration dictionaries
        """
        cache_key = f"{CACHE_PREFIX_NETWORKS}_{self._connection.site}"
        cached_data = self._connection.get_cached(cache_key)
        if cached_data is not None:
            return cached_data

        try:
            api_request = ApiRequest(method="get", path="/rest/networkconf")
            response = await self._connection.request(api_request)

            # Handle various response formats
            if isinstance(response, dict) and "data" in response:
                networks = response["data"]
            elif isinstance(response, list):
                networks = response
            else:
                logger.warning("Unexpected networkconf response format: %s", type(response))
                networks = []

            self._connection._update_cache(cache_key, networks)
            return networks
        except Exception as e:
            logger.error("Error fetching network configurations: %s", e)
            return []

    async def get_vpn_configs(self, include_clients: bool = True, include_servers: bool = True) -> List[Dict[str, Any]]:
        """Get VPN configurations from the controller.

        Args:
            include_clients: Whether to include VPN client configurations
            include_servers: Whether to include VPN server configurations

        Returns:
            List of VPN configuration dictionaries
        """
        cache_key = f"{CACHE_PREFIX_VPN_CONFIGS}_{self._connection.site}_{include_clients}_{include_servers}"
        cached_data = self._connection.get_cached(cache_key)
        if cached_data is not None:
            return cached_data

        try:
            networks = await self._get_all_network_configs()
            vpn_configs = []

            for network in networks:
                if not is_vpn_network(network):
                    continue

                purpose = network.get("purpose", "")
                vpn_type = network.get("vpn_type", "")
                is_client, is_server = classify_vpn_type(purpose, vpn_type)

                if (include_clients and is_client) or (include_servers and is_server):
                    vpn_configs.append(network)
                    logger.debug(
                        "Found VPN config: %s (purpose=%s, vpn_type=%s, client=%s, server=%s)",
                        network.get("name", "unnamed"),
                        purpose,
                        vpn_type,
                        is_client,
                        is_server,
                    )

            logger.debug("Found %s VPN configurations", len(vpn_configs))
            vpn_configs = [redact_sensitive_fields(c) for c in vpn_configs]
            self._connection._update_cache(cache_key, vpn_configs)
            return vpn_configs

        except Exception as e:
            logger.error("Error getting VPN configurations: %s", e)
            return []

    async def get_vpn_clients(self) -> List[Dict[str, Any]]:
        """Get list of VPN client configurations for the current site.

        Returns:
            List of VPN client configuration dictionaries
        """
        return await self.get_vpn_configs(include_clients=True, include_servers=False)

    async def get_vpn_servers(self) -> List[Dict[str, Any]]:
        """Get list of VPN server configurations for the current site.

        Returns:
            List of VPN server configuration dictionaries
        """
        return await self.get_vpn_configs(include_clients=False, include_servers=True)

    async def get_vpn_client_details(self, client_id: str) -> Optional[Dict[str, Any]]:
        """Get detailed information for a specific VPN client.

        Args:
            client_id: ID of the VPN client to get details for

        Returns:
            VPN client details (sensitive fields redacted) if found, None otherwise
        """
        vpn_clients = await self.get_vpn_clients()
        client = next((c for c in vpn_clients if c.get("_id") == client_id), None)
        if not client:
            logger.warning("VPN client %s not found", client_id)
            return None
        return redact_sensitive_fields(client)

    async def get_vpn_server_details(self, server_id: str) -> Optional[Dict[str, Any]]:
        """Get detailed information for a specific VPN server.

        Args:
            server_id: ID of the VPN server to get details for

        Returns:
            VPN server details (sensitive fields redacted) if found, None otherwise
        """
        vpn_servers = await self.get_vpn_servers()
        server = next((s for s in vpn_servers if s.get("_id") == server_id), None)
        if not server:
            logger.warning("VPN server %s not found", server_id)
            return None
        return redact_sensitive_fields(server)

    async def _update_vpn_config(self, config_id: str, update_data: Dict[str, Any]) -> bool:
        """Update a VPN configuration.

        Args:
            config_id: ID of the VPN configuration to update
            update_data: Dictionary of fields to update (will be merged with existing)

        Returns:
            True if successful, False otherwise
        """
        try:
            # Fetch existing config to merge with updates
            networks = await self._get_all_network_configs()
            existing = next((n for n in networks if n.get("_id") == config_id), None)

            if not existing:
                logger.error("VPN configuration %s not found", config_id)
                return False

            # Merge updates into existing config (deep merge preserves nested sub-objects)
            merged_data = deep_merge(existing, update_data)

            api_request = ApiRequest(
                method="put",
                path=f"/rest/networkconf/{config_id}",
                data=merged_data,
            )
            await self._connection.request(api_request)

            logger.info("Updated VPN configuration %s", config_id)

            # Invalidate caches
            self._connection._invalidate_cache(f"{CACHE_PREFIX_NETWORKS}_{self._connection.site}")
            # Also invalidate VPN-specific caches
            for suffix in ["_True_True", "_True_False", "_False_True"]:
                self._connection._invalidate_cache(f"{CACHE_PREFIX_VPN_CONFIGS}_{self._connection.site}{suffix}")

            return True

        except Exception as e:
            logger.error("Error updating VPN configuration %s: %s", config_id, e)
            return False

    async def update_vpn_client_state(self, client_id: str, enabled: bool) -> bool:
        """Update the enabled state of a VPN client.

        Args:
            client_id: ID of the VPN client to update
            enabled: Whether the client should be enabled or disabled

        Returns:
            True if successful, False otherwise
        """
        client = await self.get_vpn_client_details(client_id)
        if not client:
            logger.error("VPN client %s not found, cannot update state", client_id)
            return False

        result = await self._update_vpn_config(client_id, {"enabled": enabled})
        if result:
            logger.info("VPN client %s %s", client.get("name", client_id), "enabled" if enabled else "disabled")
        return result

    async def update_vpn_server_state(self, server_id: str, enabled: bool) -> bool:
        """Update the enabled state of a VPN server.

        Args:
            server_id: ID of the VPN server to update
            enabled: Whether the server should be enabled or disabled

        Returns:
            True if successful, False otherwise
        """
        server = await self.get_vpn_server_details(server_id)
        if not server:
            logger.error("VPN server %s not found, cannot update state", server_id)
            return False

        result = await self._update_vpn_config(server_id, {"enabled": enabled})
        if result:
            logger.info("VPN server %s %s", server.get("name", server_id), "enabled" if enabled else "disabled")
        return result

    async def toggle_vpn_config(self, config_id: str) -> bool:
        """Toggle a VPN configuration's enabled state.

        Args:
            config_id: ID of the VPN configuration to toggle

        Returns:
            True if successful, False otherwise
        """
        networks = await self._get_all_network_configs()
        config = next((n for n in networks if n.get("_id") == config_id), None)

        if not config or not is_vpn_network(config):
            logger.error("VPN configuration %s not found", config_id)
            return False

        new_state = not config.get("enabled", True)
        return await self._update_vpn_config(config_id, {"enabled": new_state})

    # ------------------------------------------------------------------
    # WireGuard peer management
    # ------------------------------------------------------------------

    async def list_wireguard_peers(self, server_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """List WireGuard peers, optionally filtered by server ID.

        Args:
            server_id: If provided, only return peers belonging to this server.

        Returns:
            List of peer dictionaries with sensitive fields redacted.
        """
        cache_key = f"{CACHE_PREFIX_WG_PEERS}_{self._connection.site}_{server_id or 'all'}"
        cached = self._connection.get_cached(cache_key)
        if cached is not None:
            return cached

        try:
            api_request = ApiRequest(method="get", path="/rest/wireguardpeer")
            response = await self._connection.request(api_request)

            if isinstance(response, dict) and "data" in response:
                peers = response["data"]
            elif isinstance(response, list):
                peers = response
            else:
                logger.warning("Unexpected wireguardpeer response format: %s", type(response))
                peers = []

            if server_id:
                peers = [p for p in peers if p.get("wireguard_server_id") == server_id]

            peers = [redact_sensitive_fields(p) for p in peers]
            self._connection._update_cache(cache_key, peers)
            return peers

        except Exception as e:
            logger.error("Error listing WireGuard peers: %s", e)
            return []

    async def get_wireguard_peer(self, peer_id: str) -> Optional[Dict[str, Any]]:
        """Get a single WireGuard peer by ID.

        Returns:
            Peer dict with sensitive fields redacted, or None.
        """
        try:
            api_request = ApiRequest(method="get", path=f"/rest/wireguardpeer/{peer_id}")
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
            logger.error("Error getting WireGuard peer %s: %s", peer_id, e)
            return None

    async def create_wireguard_peer(self, server_id: str, name: str) -> Optional[Dict[str, Any]]:
        """Create a new WireGuard peer on a server.

        The UniFi controller generates the keypair and assigns an IP from
        the server's DHCP range automatically.

        Args:
            server_id: _id of the WireGuard server (from list_vpn_servers).
            name: Display name for the peer (e.g. 'teemow-laptop').

        Returns:
            The created peer dict (with sensitive fields redacted) or None on failure.
        """
        server = await self.get_vpn_server_details(server_id)
        if not server:
            logger.error("WireGuard server %s not found", server_id)
            return None
        if server.get("vpn_type") != "wireguard-server":
            logger.error("Server %s is not a WireGuard server (type=%s)", server_id, server.get("vpn_type"))
            return None

        payload = {
            "name": name,
            "wireguard_server_id": server_id,
        }

        try:
            api_request = ApiRequest(
                method="post",
                path="/rest/wireguardpeer",
                data=payload,
            )
            response = await self._connection.request(api_request)

            if isinstance(response, dict) and "data" in response:
                items = response["data"]
            elif isinstance(response, list):
                items = response
            else:
                items = [response] if isinstance(response, dict) else []

            self._invalidate_peer_cache()

            if not items:
                logger.error("Empty response when creating WireGuard peer")
                return None

            peer = items[0]
            logger.info("Created WireGuard peer '%s' (id=%s) on server %s", name, peer.get("_id"), server_id)
            return redact_sensitive_fields(peer)

        except Exception as e:
            logger.error("Error creating WireGuard peer '%s': %s", name, e)
            return None

    async def delete_wireguard_peer(self, peer_id: str) -> bool:
        """Delete a WireGuard peer.

        Args:
            peer_id: _id of the peer to delete.

        Returns:
            True if deleted successfully.
        """
        try:
            api_request = ApiRequest(method="delete", path=f"/rest/wireguardpeer/{peer_id}")
            await self._connection.request(api_request)
            self._invalidate_peer_cache()
            logger.info("Deleted WireGuard peer %s", peer_id)
            return True
        except Exception as e:
            logger.error("Error deleting WireGuard peer %s: %s", peer_id, e)
            return False

    def _invalidate_peer_cache(self) -> None:
        self._connection._invalidate_cache(f"{CACHE_PREFIX_WG_PEERS}_{self._connection.site}")
