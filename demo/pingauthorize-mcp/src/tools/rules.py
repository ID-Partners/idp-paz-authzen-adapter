"""Policy-manager rule tools."""
from __future__ import annotations

from typing import Any

from ..pap_client import PM_RULES, PAPError


def _rule_body(name: str, description: str, condition: Any, effect_settings: Any,
               shared: bool = False, disabled: bool = False) -> dict:
    return {
        "name": name,
        "description": description or "",
        "shared": shared,
        "disabled": disabled,
        "condition": condition if condition is not None else {"empty": {}},
        "effectSettings": effect_settings or {"type": "unconditionalDeny"},
    }


def register(mcp, ctx, dump):
    pap = ctx.pap

    @mcp.tool()
    def list_rules(branch_id: str) -> str:
        """List all rules on a branch."""
        return dump(pap.pm_list(PM_RULES, ctx.branch(branch_id)))

    @mcp.tool()
    def get_rule(branch_id: str, rule_id: str) -> str:
        """Get full rule details, including conditions and effect settings."""
        return dump(pap.pm_get(PM_RULES, rule_id, ctx.branch(branch_id)))

    @mcp.tool()
    def create_rule(branch_id: str, name: str, description: str = "",
                    effect_settings: Any = None, condition: Any = None,
                    shared: bool = False, disabled: bool = False) -> str:
        """Create a rule. effect_settings e.g. {"type":"unconditionalPermit"} or
        {"type":"conditionalPermitElseDeny","condition":{...}}."""
        body = _rule_body(name, description, condition, effect_settings, shared, disabled)
        return dump(pap.pm_create(PM_RULES, ctx.branch(branch_id), body))

    @mcp.tool()
    def update_rule(branch_id: str, rule_id: str, rule_definition: Any) -> str:
        """Update a rule. rule_definition must include the current version."""
        return dump(pap.pm_update(PM_RULES, rule_id, ctx.branch(branch_id), rule_definition))

    @mcp.tool()
    def delete_rule(branch_id: str, rule_id: str) -> str:
        """Delete a rule by ID."""
        return dump(pap.pm_delete(PM_RULES, rule_id, ctx.branch(branch_id)))

    @mcp.tool()
    def batch_create_rules(branch_id: str, rules: Any) -> str:
        """Create multiple rules in one call. Each item: {name, description?, condition?,
        effect_settings}. Returns {created:[...], failed:[...]}."""
        b = ctx.branch(branch_id)
        created, failed = [], []
        for item in rules or []:
            body = _rule_body(item.get("name"), item.get("description", ""),
                              item.get("condition"), item.get("effect_settings"),
                              item.get("shared", False), item.get("disabled", False))
            try:
                res = pap.pm_create(PM_RULES, b, body)
                created.append({"name": body["name"], "id": (res or {}).get("id"), "result": res})
            except PAPError as e:
                failed.append({"name": body.get("name"), "error": e.kind, "message": e.message})
        return dump({"created": created, "failed": failed,
                     "summary": {"created": len(created), "failed": len(failed)}})
