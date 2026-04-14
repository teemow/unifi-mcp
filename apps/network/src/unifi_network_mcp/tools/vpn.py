"""
VPN configuration tools for Unifi Network MCP server.

This module provides MCP tools to interact with a Unifi Network Controller's VPN functions,
including managing VPN clients, servers, and WireGuard peers.
"""

import logging
from typing import Annotated, Any, Dict, Optional

from mcp.types import ToolAnnotations
from pydantic import Field

from unifi_mcp_shared.confirmation import create_preview, preview_response
from unifi_network_mcp.runtime import server, vpn_manager

logger = logging.getLogger(__name__)


@server.tool(
    name="unifi_list_vpn_clients",
    description="List all configured VPN clients (Wireguard, OpenVPN, etc).",
    annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False),
)
async def list_vpn_clients() -> Dict[str, Any]:
    """Implementation for listing VPN clients."""
    try:
        clients = await vpn_manager.get_vpn_clients()
        return {
            "success": True,
            "site": vpn_manager._connection.site,
            "count": len(clients),
            "vpn_clients": clients,
        }
    except Exception as e:
        logger.error("Error listing VPN clients: %s", e, exc_info=True)
        return {"success": False, "error": f"Failed to list VPN clients: {e}"}


@server.tool(
    name="unifi_get_vpn_client_details",
    description="Get details for a specific VPN client by ID.",
    annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False),
)
async def get_vpn_client_details(
    client_id: Annotated[
        str, Field(description="Unique identifier (_id) of the VPN client (from unifi_list_vpn_clients)")
    ],
) -> Dict[str, Any]:
    """Implementation for getting VPN client details."""
    try:
        client = await vpn_manager.get_vpn_client_details(client_id)
        if client:
            return {
                "success": True,
                "site": vpn_manager._connection.site,
                "client_id": client_id,
                "details": client,
            }
        else:
            return {"success": False, "error": f"VPN client '{client_id}' not found."}
    except Exception as e:
        logger.error("Error getting VPN client details for %s: %s", client_id, e, exc_info=True)
        return {"success": False, "error": f"Failed to get VPN client details for {client_id}: {e}"}


@server.tool(
    name="unifi_update_vpn_client_state",
    description="Enable or disable a specific VPN client by ID.",
    permission_category="vpn_clients",
    permission_action="update",
    annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=True, openWorldHint=False),
)
async def update_vpn_client_state(
    client_id: Annotated[
        str, Field(description="Unique identifier (_id) of the VPN client to update (from unifi_list_vpn_clients)")
    ],
    enabled: Annotated[bool, Field(description="Set to true to enable the VPN client, false to disable it")],
) -> Dict[str, Any]:
    """Implementation for updating VPN client state."""
    try:
        success = await vpn_manager.update_vpn_client_state(client_id, enabled)
        if success:
            client_details = await vpn_manager.get_vpn_client_details(client_id)
            name = client_details.get("name", client_id) if client_details else client_id
            state = "enabled" if enabled else "disabled"
            return {
                "success": True,
                "message": f"VPN client '{name}' ({client_id}) {state}.",
            }
        else:
            client_details = await vpn_manager.get_vpn_client_details(client_id)
            name = client_details.get("name", client_id) if client_details else client_id
            return {
                "success": False,
                "error": f"Failed to update state for VPN client '{name}'.",
            }
    except Exception as e:
        logger.error("Error updating state for VPN client %s: %s", client_id, e, exc_info=True)
        return {"success": False, "error": f"Failed to update state for VPN client {client_id}: {e}"}


@server.tool(
    name="unifi_list_vpn_servers",
    description="List all configured VPN servers (Wireguard, OpenVPN, L2TP, etc).",
    annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False),
)
async def list_vpn_servers() -> Dict[str, Any]:
    """Implementation for listing VPN servers."""
    try:
        servers = await vpn_manager.get_vpn_servers()
        return {
            "success": True,
            "site": vpn_manager._connection.site,
            "count": len(servers),
            "vpn_servers": servers,
        }
    except Exception as e:
        logger.error("Error listing VPN servers: %s", e, exc_info=True)
        return {"success": False, "error": f"Failed to list VPN servers: {e}"}


@server.tool(
    name="unifi_get_vpn_server_details",
    description="Get details for a specific VPN server by ID.",
    annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False),
)
async def get_vpn_server_details(
    server_id: Annotated[
        str, Field(description="Unique identifier (_id) of the VPN server (from unifi_list_vpn_servers)")
    ],
) -> Dict[str, Any]:
    """Implementation for getting VPN server details."""
    try:
        server = await vpn_manager.get_vpn_server_details(server_id)
        if server:
            return {
                "success": True,
                "site": vpn_manager._connection.site,
                "server_id": server_id,
                "details": server,
            }
        else:
            return {"success": False, "error": f"VPN server '{server_id}' not found."}
    except Exception as e:
        logger.error("Error getting VPN server details for %s: %s", server_id, e, exc_info=True)
        return {"success": False, "error": f"Failed to get VPN server details for {server_id}: {e}"}


@server.tool(
    name="unifi_update_vpn_server_state",
    description="Enable or disable a specific VPN server by ID.",
    permission_category="vpn_servers",
    permission_action="update",
    annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=True, openWorldHint=False),
)
async def update_vpn_server_state(
    server_id: Annotated[
        str, Field(description="Unique identifier (_id) of the VPN server to update (from unifi_list_vpn_servers)")
    ],
    enabled: Annotated[bool, Field(description="Set to true to enable the VPN server, false to disable it")],
) -> Dict[str, Any]:
    """Implementation for updating VPN server state."""
    try:
        success = await vpn_manager.update_vpn_server_state(server_id, enabled)
        if success:
            server_details = await vpn_manager.get_vpn_server_details(server_id)
            name = server_details.get("name", server_id) if server_details else server_id
            state = "enabled" if enabled else "disabled"
            return {
                "success": True,
                "message": f"VPN server '{name}' ({server_id}) {state}.",
            }
        else:
            server_details = await vpn_manager.get_vpn_server_details(server_id)
            name = server_details.get("name", server_id) if server_details else server_id
            return {
                "success": False,
                "error": f"Failed to update state for VPN server '{name}'.",
            }
    except Exception as e:
        logger.error("Error updating state for VPN server %s: %s", server_id, e, exc_info=True)
        return {"success": False, "error": f"Failed to update state for VPN server {server_id}: {e}"}


# ---------------------------------------------------------------------------
# WireGuard Peer Management
# ---------------------------------------------------------------------------


@server.tool(
    name="unifi_list_wireguard_peers",
    description=(
        "List WireGuard peers (VPN clients). Optionally filter by server_id to list "
        "peers for a specific WireGuard server. Returns peer name, ID, assigned IP, "
        "and public key. Private keys are redacted."
    ),
    annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False),
)
async def list_wireguard_peers(
    server_id: Annotated[
        Optional[str],
        Field(
            default=None,
            description=(
                "Optional WireGuard server _id to filter peers (from unifi_list_vpn_servers). "
                "If omitted, returns peers across all WireGuard servers."
            ),
        ),
    ] = None,
) -> Dict[str, Any]:
    try:
        peers = await vpn_manager.list_wireguard_peers(server_id=server_id)
        return {
            "success": True,
            "site": vpn_manager._connection.site,
            "count": len(peers),
            "server_id": server_id,
            "peers": peers,
        }
    except Exception as e:
        logger.error("Error listing WireGuard peers: %s", e, exc_info=True)
        return {"success": False, "error": f"Failed to list WireGuard peers: {e}"}


@server.tool(
    name="unifi_get_wireguard_peer",
    description="Get details for a specific WireGuard peer by ID. Private keys are redacted.",
    annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False),
)
async def get_wireguard_peer(
    peer_id: Annotated[
        str, Field(description="Unique identifier (_id) of the WireGuard peer (from unifi_list_wireguard_peers)")
    ],
) -> Dict[str, Any]:
    try:
        peer = await vpn_manager.get_wireguard_peer(peer_id)
        if peer:
            return {
                "success": True,
                "site": vpn_manager._connection.site,
                "peer_id": peer_id,
                "details": peer,
            }
        return {"success": False, "error": f"WireGuard peer '{peer_id}' not found."}
    except Exception as e:
        logger.error("Error getting WireGuard peer %s: %s", peer_id, e, exc_info=True)
        return {"success": False, "error": f"Failed to get WireGuard peer {peer_id}: {e}"}


@server.tool(
    name="unifi_create_wireguard_peer",
    description=(
        "Create a new WireGuard peer on a WireGuard server. The UniFi controller "
        "generates the keypair and assigns an IP automatically. Requires confirmation. "
        "After creation the peer config (public key, assigned IP) is returned; "
        "private keys are redacted -- download the full client config from the UniFi UI."
    ),
    permission_category="vpn_servers",
    permission_action="create",
    annotations=ToolAnnotations(
        readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=False
    ),
)
async def create_wireguard_peer(
    server_id: Annotated[
        str,
        Field(description="WireGuard server _id to add the peer to (from unifi_list_vpn_servers)"),
    ],
    name: Annotated[
        str,
        Field(description="Display name for the peer (e.g. 'teemow-laptop', 'teemow-phone')"),
    ],
    confirm: Annotated[
        bool,
        Field(description="When true, creates the peer. When false (default), returns a preview"),
    ] = False,
) -> Dict[str, Any]:
    try:
        srv = await vpn_manager.get_vpn_server_details(server_id)
        if not srv:
            return {"success": False, "error": f"WireGuard server '{server_id}' not found."}
        if srv.get("vpn_type") != "wireguard-server":
            return {
                "success": False,
                "error": f"Server '{server_id}' is not a WireGuard server (type={srv.get('vpn_type')}).",
            }

        if not confirm:
            return create_preview(
                resource_type="wireguard_peer",
                resource_data={
                    "name": name,
                    "wireguard_server_id": server_id,
                    "wireguard_server_name": srv.get("name", server_id),
                    "server_subnet": srv.get("ip_subnet"),
                },
                resource_name=name,
            )

        peer = await vpn_manager.create_wireguard_peer(server_id, name)
        if peer:
            return {
                "success": True,
                "message": f"WireGuard peer '{name}' created on server '{srv.get('name', server_id)}'.",
                "peer_id": peer.get("_id"),
                "details": peer,
            }
        return {
            "success": False,
            "error": f"Failed to create WireGuard peer '{name}'. Check server logs.",
        }
    except Exception as e:
        logger.error("Error creating WireGuard peer '%s': %s", name, e, exc_info=True)
        return {"success": False, "error": f"Failed to create WireGuard peer '{name}': {e}"}


@server.tool(
    name="unifi_delete_wireguard_peer",
    description="Delete a WireGuard peer by ID. Requires confirmation.",
    permission_category="vpn_servers",
    permission_action="delete",
    annotations=ToolAnnotations(
        readOnlyHint=False, destructiveHint=True, idempotentHint=True, openWorldHint=False
    ),
)
async def delete_wireguard_peer(
    peer_id: Annotated[
        str,
        Field(description="Unique identifier (_id) of the WireGuard peer to delete (from unifi_list_wireguard_peers)"),
    ],
    confirm: Annotated[
        bool,
        Field(description="When true, deletes the peer. When false (default), returns a preview"),
    ] = False,
) -> Dict[str, Any]:
    try:
        peer = await vpn_manager.get_wireguard_peer(peer_id)
        if not peer:
            return {"success": False, "error": f"WireGuard peer '{peer_id}' not found."}

        peer_name = peer.get("name", peer_id)

        if not confirm:
            return preview_response(
                action="delete",
                resource_type="wireguard_peer",
                resource_id=peer_id,
                resource_name=peer_name,
                current_state={
                    "name": peer_name,
                    "ip": peer.get("ip"),
                    "wireguard_server_id": peer.get("wireguard_server_id"),
                },
                proposed_changes={"action": "permanently delete this peer"},
                warnings=["This action cannot be undone. The peer keypair will be destroyed."],
            )

        success = await vpn_manager.delete_wireguard_peer(peer_id)
        if success:
            return {
                "success": True,
                "message": f"WireGuard peer '{peer_name}' ({peer_id}) deleted.",
            }
        return {
            "success": False,
            "error": f"Failed to delete WireGuard peer '{peer_name}'. Check server logs.",
        }
    except Exception as e:
        logger.error("Error deleting WireGuard peer %s: %s", peer_id, e, exc_info=True)
        return {"success": False, "error": f"Failed to delete WireGuard peer {peer_id}: {e}"}
