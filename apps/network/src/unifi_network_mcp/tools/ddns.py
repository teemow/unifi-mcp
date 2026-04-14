"""
Dynamic DNS configuration tools for UniFi Network MCP server.

Provides tools to list, inspect, create, update, and delete Dynamic DNS
entries on the UniFi controller. Supports providers like Cloudflare,
DynDNS, No-IP, etc.
"""

import logging
from typing import Annotated, Any, Dict, Optional

from mcp.types import ToolAnnotations
from pydantic import Field

from unifi_mcp_shared.confirmation import create_preview, preview_response, update_preview
from unifi_network_mcp.runtime import ddns_manager, server

logger = logging.getLogger(__name__)


@server.tool(
    name="unifi_list_ddns",
    description=(
        "List all Dynamic DNS configurations. Returns service provider, hostname, "
        "interface, and enabled state for each entry. Credentials are redacted."
    ),
    annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False),
)
async def list_ddns() -> Dict[str, Any]:
    """List all Dynamic DNS configurations."""
    try:
        configs = await ddns_manager.list_ddns_configs()
        formatted = [
            {
                "id": c.get("_id"),
                "service": c.get("service"),
                "host_name": c.get("host_name"),
                "login": c.get("login"),
                "interface": c.get("interface"),
                "server": c.get("server"),
                "enabled": c.get("enabled", True),
            }
            for c in configs
        ]
        return {
            "success": True,
            "site": ddns_manager._connection.site,
            "count": len(formatted),
            "ddns_configs": formatted,
        }
    except Exception as e:
        logger.error("Error listing DDNS configs: %s", e, exc_info=True)
        return {"success": False, "error": f"Failed to list DDNS configurations: {e}"}


@server.tool(
    name="unifi_get_ddns_details",
    description="Get full details for a specific Dynamic DNS configuration by ID. Credentials are redacted.",
    annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False),
)
async def get_ddns_details(
    config_id: Annotated[
        str,
        Field(description="Unique identifier (_id) of the DDNS configuration (from unifi_list_ddns)"),
    ],
) -> Dict[str, Any]:
    """Get details for a specific DDNS configuration."""
    try:
        config = await ddns_manager.get_ddns_config(config_id)
        if config:
            return {
                "success": True,
                "site": ddns_manager._connection.site,
                "config_id": config_id,
                "details": config,
            }
        return {"success": False, "error": f"DDNS configuration '{config_id}' not found."}
    except Exception as e:
        logger.error("Error getting DDNS config %s: %s", config_id, e, exc_info=True)
        return {"success": False, "error": f"Failed to get DDNS configuration {config_id}: {e}"}


@server.tool(
    name="unifi_create_ddns",
    description=(
        "Create a new Dynamic DNS configuration. "
        "Required: service (provider name, e.g. 'cloudflare', 'dyndns', 'noip'), "
        "host_name (FQDN to update, e.g. 'vpn.home.example.com'), "
        "login (username or email for the DDNS provider), "
        "x_password (API token or password for the DDNS provider). "
        "Optional: interface (WAN interface, e.g. 'wan', 'wan2'), "
        "server (custom API endpoint), enabled (bool, default true). "
        "Requires confirmation."
    ),
    permission_category="ddns",
    permission_action="create",
    annotations=ToolAnnotations(
        readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=False
    ),
)
async def create_ddns(
    service: Annotated[
        str,
        Field(description="DDNS provider name (e.g. 'cloudflare', 'dyndns', 'noip', 'freedns', 'namecheap')"),
    ],
    host_name: Annotated[
        str,
        Field(description="Fully qualified domain name to update (e.g. 'vpn.home.example.com')"),
    ],
    login: Annotated[
        str,
        Field(description="Username or email for the DDNS service"),
    ],
    x_password: Annotated[
        str,
        Field(description="API token or password for the DDNS service"),
    ],
    interface: Annotated[
        Optional[str],
        Field(
            default=None,
            description="WAN interface to bind to (e.g. 'wan', 'wan2', 'wan3'). Omit for default WAN.",
        ),
    ] = None,
    custom_server: Annotated[
        Optional[str],
        Field(
            default=None,
            description="Custom API server/endpoint for the DDNS provider. Usually not needed.",
        ),
    ] = None,
    enabled: Annotated[
        bool,
        Field(description="Whether the DDNS entry should be enabled (default true)"),
    ] = True,
    confirm: Annotated[
        bool,
        Field(description="When true, creates the entry. When false (default), returns a preview"),
    ] = False,
) -> Dict[str, Any]:
    """Create a new Dynamic DNS configuration."""
    config_data: Dict[str, Any] = {
        "service": service,
        "host_name": host_name,
        "login": login,
        "x_password": x_password,
        "enabled": enabled,
    }
    if interface:
        config_data["interface"] = interface
    if custom_server:
        config_data["server"] = custom_server

    if not confirm:
        preview_data = dict(config_data)
        preview_data["x_password"] = "<REDACTED>"
        return create_preview(
            resource_type="ddns_config",
            resource_data=preview_data,
            resource_name=f"{service}:{host_name}",
        )

    try:
        result = await ddns_manager.create_ddns_config(config_data)
        if result:
            return {
                "success": True,
                "message": f"DDNS configuration for '{host_name}' ({service}) created successfully.",
                "config_id": result.get("_id"),
                "details": result,
            }
        return {
            "success": False,
            "error": f"Failed to create DDNS configuration for '{host_name}'.",
        }
    except Exception as e:
        logger.error("Error creating DDNS config: %s", e, exc_info=True)
        return {"success": False, "error": f"Failed to create DDNS configuration: {e}"}


@server.tool(
    name="unifi_update_ddns",
    description=(
        "Update an existing Dynamic DNS configuration. "
        "Pass only the fields you want to change -- current values are preserved. "
        "Updatable fields: service (str), host_name (str), login (str), "
        "x_password (str), interface (str), server (str), enabled (bool). "
        "Requires confirmation."
    ),
    permission_category="ddns",
    permission_action="update",
    annotations=ToolAnnotations(
        readOnlyHint=False, destructiveHint=False, idempotentHint=True, openWorldHint=False
    ),
)
async def update_ddns(
    config_id: Annotated[
        str,
        Field(description="The ID of the DDNS configuration to update (from unifi_list_ddns)"),
    ],
    update_data: Annotated[
        Dict[str, Any],
        Field(description="Dictionary of fields to update. See tool description for supported fields."),
    ],
    confirm: Annotated[
        bool,
        Field(description="When true, applies the update. When false (default), returns a preview"),
    ] = False,
) -> Dict[str, Any]:
    """Update an existing DDNS configuration."""
    if not update_data:
        return {"success": False, "error": "No fields provided to update."}

    try:
        current = await ddns_manager.get_ddns_config(config_id)
        if not current:
            return {"success": False, "error": f"DDNS configuration '{config_id}' not found."}

        if not confirm:
            safe_updates = dict(update_data)
            if "x_password" in safe_updates:
                safe_updates["x_password"] = "<REDACTED>"
            return update_preview(
                resource_type="ddns_config",
                resource_id=config_id,
                resource_name=current.get("host_name", config_id),
                current_state=current,
                updates=safe_updates,
            )

        success = await ddns_manager.update_ddns_config(config_id, update_data)
        if success:
            return {
                "success": True,
                "message": f"DDNS configuration '{current.get('host_name', config_id)}' updated successfully.",
            }
        return {
            "success": False,
            "error": f"Failed to update DDNS configuration '{config_id}'.",
        }
    except Exception as e:
        logger.error("Error updating DDNS config %s: %s", config_id, e, exc_info=True)
        return {"success": False, "error": f"Failed to update DDNS configuration {config_id}: {e}"}


@server.tool(
    name="unifi_delete_ddns",
    description="Delete a Dynamic DNS configuration. Use unifi_list_ddns to find IDs. Requires confirmation.",
    permission_category="ddns",
    permission_action="delete",
    annotations=ToolAnnotations(
        readOnlyHint=False, destructiveHint=True, idempotentHint=True, openWorldHint=False
    ),
)
async def delete_ddns(
    config_id: Annotated[
        str,
        Field(description="The ID of the DDNS configuration to delete (from unifi_list_ddns)"),
    ],
    confirm: Annotated[
        bool,
        Field(description="When true, deletes the entry. When false (default), returns a preview"),
    ] = False,
) -> Dict[str, Any]:
    """Delete a DDNS configuration."""
    try:
        config = await ddns_manager.get_ddns_config(config_id)
        if not config:
            return {"success": False, "error": f"DDNS configuration '{config_id}' not found."}

        host_name = config.get("host_name", config_id)

        if not confirm:
            return preview_response(
                action="delete",
                resource_type="ddns_config",
                resource_id=config_id,
                resource_name=host_name,
                current_state={
                    "service": config.get("service"),
                    "host_name": host_name,
                    "interface": config.get("interface"),
                    "enabled": config.get("enabled", True),
                },
                proposed_changes={"action": "permanently delete this DDNS configuration"},
                warnings=["The DDNS provider will no longer be updated with IP changes."],
            )

        success = await ddns_manager.delete_ddns_config(config_id)
        if success:
            return {
                "success": True,
                "message": f"DDNS configuration '{host_name}' ({config_id}) deleted.",
            }
        return {
            "success": False,
            "error": f"Failed to delete DDNS configuration '{host_name}'.",
        }
    except Exception as e:
        logger.error("Error deleting DDNS config %s: %s", config_id, e, exc_info=True)
        return {"success": False, "error": f"Failed to delete DDNS configuration {config_id}: {e}"}


@server.tool(
    name="unifi_update_ddns_state",
    description="Enable or disable a specific Dynamic DNS configuration by ID.",
    permission_category="ddns",
    permission_action="update",
    annotations=ToolAnnotations(
        readOnlyHint=False, destructiveHint=False, idempotentHint=True, openWorldHint=False
    ),
)
async def update_ddns_state(
    config_id: Annotated[
        str,
        Field(description="Unique identifier (_id) of the DDNS configuration to update (from unifi_list_ddns)"),
    ],
    enabled: Annotated[
        bool,
        Field(description="Set to true to enable the DDNS entry, false to disable it"),
    ],
) -> Dict[str, Any]:
    """Enable or disable a DDNS configuration."""
    try:
        current = await ddns_manager.get_ddns_config(config_id)
        if not current:
            return {"success": False, "error": f"DDNS configuration '{config_id}' not found."}

        host_name = current.get("host_name", config_id)
        success = await ddns_manager.update_ddns_config(config_id, {"enabled": enabled})
        if success:
            state = "enabled" if enabled else "disabled"
            return {
                "success": True,
                "message": f"DDNS configuration '{host_name}' ({config_id}) {state}.",
            }
        return {
            "success": False,
            "error": f"Failed to update state for DDNS configuration '{host_name}'.",
        }
    except Exception as e:
        logger.error("Error updating DDNS state for %s: %s", config_id, e, exc_info=True)
        return {"success": False, "error": f"Failed to update DDNS state for {config_id}: {e}"}
