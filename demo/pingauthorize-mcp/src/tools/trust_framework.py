"""Trust Framework tools: attributes, services, conditions, and generic definitions."""
from __future__ import annotations

from typing import Any

from ..pap_client import (
    TF_ATTRIBUTES, TF_CONDITIONS, TF_SERVICES, TF_DOMAINS,
    TF_IDENTITY_PROVIDERS, TF_ACTIONS, PAPError,
)

# Map the tool's semantic definition_type enum to the REST type token.
DEFINITION_TYPE_TOKEN = {
    "ATTRIBUTE": TF_ATTRIBUTES,
    "CONDITION": TF_CONDITIONS,
    "SERVICE": TF_SERVICES,
    "DOMAIN": TF_DOMAINS,
    "IDENTITY_PROVIDER": TF_IDENTITY_PROVIDERS,
    "ACTION": TF_ACTIONS,
}


def register(mcp, ctx, dump):
    pap = ctx.pap

    @mcp.tool()
    def list_attributes(branch_id: str) -> str:
        """List all Trust Framework attribute definitions on a branch."""
        return dump(pap.tf_list(TF_ATTRIBUTES, ctx.branch(branch_id)))

    @mcp.tool()
    def list_services(branch_id: str) -> str:
        """List all Trust Framework service definitions on a branch."""
        return dump(pap.tf_list(TF_SERVICES, ctx.branch(branch_id)))

    @mcp.tool()
    def list_trust_framework_definitions(branch_id: str, definition_type: str) -> str:
        """List Trust Framework definitions of a given type.

        definition_type is one of: ATTRIBUTE, CONDITION, SERVICE, DOMAIN,
        IDENTITY_PROVIDER, ACTION.
        """
        token = DEFINITION_TYPE_TOKEN.get(definition_type.upper())
        if not token:
            raise ValueError(f"unsupported definition_type: {definition_type}")
        return dump(pap.tf_list(token, ctx.branch(branch_id)))

    @mcp.tool()
    def get_trust_framework_definition(branch_id: str, definition_id: str) -> str:
        """Get a full Trust Framework definition by ID (needed for its version field)."""
        return dump(pap.tf_get(definition_id, ctx.branch(branch_id)))

    @mcp.tool()
    def create_trust_framework_definition(
        branch_id: str, definition_type: str, name: str, description: str = "",
        resolvers: Any = None, value_type: str = None, cache_config: Any = None,
    ) -> str:
        """Create a new root Trust Framework definition (attribute, condition, service, etc.)."""
        token = DEFINITION_TYPE_TOKEN.get(definition_type.upper())
        if not token:
            raise ValueError(f"unsupported definition_type: {definition_type}")
        body: dict = {"name": name, "description": description or ""}
        if resolvers is not None:
            body["resolvers"] = resolvers
        if value_type:
            body["valueType"] = value_type
        if cache_config is not None:
            body["cacheConfig"] = cache_config
        return dump(pap.tf_create(token, ctx.branch(branch_id), body))

    @mcp.tool()
    def update_trust_framework_definition(branch_id: str, definition_id: str,
                                          definition: Any) -> str:
        """Update a Trust Framework definition. `definition` must include the current version."""
        return dump(pap.tf_update(definition_id, ctx.branch(branch_id), definition))

    @mcp.tool()
    def batch_create_attributes(branch_id: str, attributes: Any) -> str:
        """Create multiple attribute definitions in one call.

        Each item: {name, description?, value_type?, parent_id?, resolvers?, cache_config?}.
        Returns {created:[...], failed:[...]} with the new IDs to use in rule conditions.
        """
        b = ctx.branch(branch_id)
        created, failed = [], []
        for item in attributes or []:
            body: dict = {
                "name": item.get("name"),
                "description": item.get("description", ""),
            }
            if item.get("value_type"):
                body["valueType"] = item["value_type"]
            if item.get("parent_id"):
                body["parentId"] = item["parent_id"]
            if item.get("resolvers") is not None:
                body["resolvers"] = item["resolvers"]
            if item.get("cache_config") is not None:
                body["cacheConfig"] = item["cache_config"]
            try:
                res = pap.tf_create(TF_ATTRIBUTES, b, body)
                created.append({"name": body["name"], "id": (res or {}).get("id"), "result": res})
            except PAPError as e:
                failed.append({"name": body.get("name"), "error": e.kind, "message": e.message})
        return dump({"created": created, "failed": failed,
                     "summary": {"created": len(created), "failed": len(failed)}})
