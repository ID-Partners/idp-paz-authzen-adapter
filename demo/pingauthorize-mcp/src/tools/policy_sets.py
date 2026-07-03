"""Policy-manager policy-set tools, including create_policy_set_with_policies."""
from __future__ import annotations

from typing import Any

from ..pap_client import PM_POLICY_SETS


def _policy_set_body(name: str, description: str, combining_algorithm: str,
                     condition: Any, child_ids: list[str], shared: bool = False,
                     disabled: bool = False, child_type: str = "Policy") -> dict:
    return {
        "name": name,
        "description": description or "",
        "shared": shared,
        "disabled": disabled,
        "combiningAlgorithm": {"algorithm": combining_algorithm or "DenyOverrides"},
        "condition": condition if condition is not None else {"empty": {}},
        # 11.0: children are typed DecisionNode references (policies / policy-sets).
        "children": [{"id": cid, "type": child_type} for cid in child_ids],
    }


def register(mcp, ctx, dump):
    pap = ctx.pap

    @mcp.tool()
    def list_policy_sets(branch_id: str) -> str:
        """List all policy sets on a branch."""
        return dump(pap.pm_list(PM_POLICY_SETS, ctx.branch(branch_id)))

    @mcp.tool()
    def get_policy_set(branch_id: str, policy_set_id: str) -> str:
        """Get full policy-set details (needed for its version field before updates)."""
        return dump(pap.pm_get(PM_POLICY_SETS, policy_set_id, ctx.branch(branch_id)))

    @mcp.tool()
    def create_policy_set(branch_id: str, name: str, description: str = "",
                          combining_algorithm: str = "DenyOverrides",
                          children: Any = None, condition: Any = None,
                          shared: bool = False, disabled: bool = False) -> str:
        """Create a policy set. `children` is a list of policy/policy-set IDs to include."""
        body = _policy_set_body(name, description, combining_algorithm, condition,
                                list(children or []), shared, disabled)
        return dump(pap.pm_create(PM_POLICY_SETS, ctx.branch(branch_id), body))

    @mcp.tool()
    def create_policy_set_with_policies(branch_id: str, name: str, description: str = "",
                                        combining_algorithm: str = "DenyOverrides",
                                        condition: Any = None, policy_ids: Any = None) -> str:
        """Compound tool: create a policy set and attach existing policies by ID."""
        body = _policy_set_body(name, description, combining_algorithm, condition,
                                list(policy_ids or []))
        return dump(pap.pm_create(PM_POLICY_SETS, ctx.branch(branch_id), body))

    @mcp.tool()
    def update_policy_set(branch_id: str, policy_set_id: str, policy_set_definition: Any) -> str:
        """Update a policy set. policy_set_definition must include the current version."""
        return dump(pap.pm_update(PM_POLICY_SETS, policy_set_id, ctx.branch(branch_id),
                                  policy_set_definition))

    @mcp.tool()
    def delete_policy_set(branch_id: str, policy_set_id: str) -> str:
        """Delete a policy set by ID."""
        return dump(pap.pm_delete(PM_POLICY_SETS, policy_set_id, ctx.branch(branch_id)))
