"""Policy-manager policy tools, including the compound create_policy_with_rules."""
from __future__ import annotations

from typing import Any

from ..pap_client import PM_POLICIES, PM_RULES, PM_STATEMENTS, PAPError
from .rules import _rule_body


def _policy_body(name: str, description: str, combining_algorithm: str,
                 target: Any, child_ids: list[str], child_type: str = "Rule") -> dict:
    return {
        "name": name,
        "description": description or "",
        "shared": False,
        "disabled": False,
        "combiningAlgorithm": {"algorithm": combining_algorithm or "DenyOverrides"},
        "condition": target if target is not None else {"empty": {}},
        # 11.0: children are typed DecisionNode references.
        "children": [{"id": cid, "type": child_type} for cid in child_ids],
    }


def register(mcp, ctx, dump):
    pap = ctx.pap

    @mcp.tool()
    def list_policies(branch_id: str) -> str:
        """List all policies on a branch."""
        return dump(pap.pm_list(PM_POLICIES, ctx.branch(branch_id)))

    @mcp.tool()
    def get_policy(branch_id: str, policy_id: str) -> str:
        """Get full policy details (needed for its version field before updates)."""
        return dump(pap.pm_get(PM_POLICIES, policy_id, ctx.branch(branch_id)))

    @mcp.tool()
    def list_statements(branch_id: str) -> str:
        """List all statements (advice/obligations) on a branch."""
        return dump(pap.pm_list(PM_STATEMENTS, ctx.branch(branch_id)))

    @mcp.tool()
    def create_policy(branch_id: str, name: str, description: str = "",
                      combining_algorithm: str = "DenyOverrides",
                      target: Any = None, rules: Any = None) -> str:
        """Create a policy. `rules` may be a list of existing rule IDs to attach."""
        child_ids = list(rules or [])
        body = _policy_body(name, description, combining_algorithm, target, child_ids)
        return dump(pap.pm_create(PM_POLICIES, ctx.branch(branch_id), body))

    @mcp.tool()
    def update_policy(branch_id: str, policy_id: str, policy_definition: Any) -> str:
        """Update a policy. policy_definition must include the current version."""
        return dump(pap.pm_update(PM_POLICIES, policy_id, ctx.branch(branch_id), policy_definition))

    @mcp.tool()
    def delete_policy(branch_id: str, policy_id: str) -> str:
        """Delete a policy by ID."""
        return dump(pap.pm_delete(PM_POLICIES, policy_id, ctx.branch(branch_id)))

    @mcp.tool()
    def create_policy_with_rules(branch_id: str, policy_name: str,
                                 policy_description: str = "",
                                 combining_algorithm: str = "DenyOverrides",
                                 target: Any = None, rules: Any = None) -> str:
        """Compound tool: create the rules, then create the policy with them attached.

        `rules` is an array of {name, description?, condition?, effect_settings}.
        Returns {policy_id, created_rules:[{name,id}], policy}.
        """
        b = ctx.branch(branch_id)
        if not rules:
            raise ValueError("rules array must not be empty")
        created_rules = []
        for item in rules:
            body = _rule_body(item.get("name"), item.get("description", ""),
                              item.get("condition"), item.get("effect_settings"),
                              item.get("shared", False), item.get("disabled", False))
            res = pap.pm_create(PM_RULES, b, body)
            created_rules.append({"name": body["name"], "id": (res or {}).get("id")})
        child_ids = [r["id"] for r in created_rules if r["id"]]
        policy = pap.pm_create(
            PM_POLICIES, b,
            _policy_body(policy_name, policy_description, combining_algorithm, target, child_ids))
        return dump({"policy_id": (policy or {}).get("id"),
                     "created_rules": created_rules, "policy": policy})
