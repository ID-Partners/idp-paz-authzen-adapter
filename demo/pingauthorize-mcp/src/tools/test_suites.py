"""Test-suite and test-runner tools.

Test-suite entities (suites, scenarios, cases, assertions) form a tree served by
/api/test-suite; test execution is driven through /api/test-runner. The write-shape
bodies here follow the tool schemas; adjust definition payloads to your PAP version if
it rejects a field.
"""
from __future__ import annotations

from typing import Any


def register(mcp, ctx, dump):
    pap = ctx.pap

    # ---- test-suite tree --------------------------------------------------
    @mcp.tool()
    def list_root_test_suites(branch_id: str, test_suite_type: str) -> str:
        """List root test-suite entities of a type (e.g. POLICY, TEST_SCENARIO)."""
        return dump(pap.ts_roots(test_suite_type, ctx.branch(branch_id)))

    @mcp.tool()
    def list_test_suites(branch_id: str, test_suite_type: str) -> str:
        """List all test-suite entities of a type on a branch."""
        return dump(pap.ts_list(test_suite_type, ctx.branch(branch_id)))

    @mcp.tool()
    def get_test_suite(branch_id: str, entity_id: str) -> str:
        """Get a test-suite entity by ID."""
        return dump(pap.ts_get(entity_id, ctx.branch(branch_id)))

    @mcp.tool()
    def get_test_suite_children(branch_id: str, entity_id: str) -> str:
        """List the child entities of a test-suite node."""
        return dump(pap.ts_children(entity_id, ctx.branch(branch_id)))

    @mcp.tool()
    def create_test_suite(branch_id: str, test_suite_type: str, name: str,
                          description: str = "", definition: Any = None) -> str:
        """Create a root test-suite entity of a type."""
        body = dict(definition or {})
        body.setdefault("name", name)
        body.setdefault("description", description or "")
        return dump(pap.ts_create_root(test_suite_type, ctx.branch(branch_id), body))

    @mcp.tool()
    def create_child_test_suite(branch_id: str, parent_id: str, name: str,
                                description: str = "", definition: Any = None) -> str:
        """Create a child test-suite entity under an existing parent."""
        body = dict(definition or {})
        body.setdefault("name", name)
        body.setdefault("description", description or "")
        return dump(pap.ts_create_child(parent_id, ctx.branch(branch_id), body))

    @mcp.tool()
    def update_test_suite(branch_id: str, entity_id: str, definition: Any) -> str:
        """Update a test-suite entity. definition must include the current version."""
        return dump(pap.ts_update(entity_id, ctx.branch(branch_id), definition))

    @mcp.tool()
    def delete_test_suite(branch_id: str, entity_id: str) -> str:
        """Delete a test-suite entity by ID."""
        return dump(pap.ts_delete(entity_id, ctx.branch(branch_id)))

    # ---- test cases (test-suite entities of type TEST_CASE) ---------------
    @mcp.tool()
    def list_test_cases(branch_id: str) -> str:
        """List all test cases on a branch."""
        return dump(pap.ts_list("TEST_CASE", ctx.branch(branch_id)))

    @mcp.tool()
    def get_test_case(branch_id: str, test_case_id: str) -> str:
        """Get a test case by ID."""
        return dump(pap.ts_get(test_case_id, ctx.branch(branch_id)))

    @mcp.tool()
    def create_test_case(
        branch_id: str, name: str, parent_id: str = "", description: str = "",
        tested_entity_id: str = "", tested_entity_type: str = "", domain_id: str = "",
        service_id: str = "", identity_provider_id: str = "", action_id: str = "",
        request_attributes: Any = None, attribute_overrides: Any = None,
        service_overrides: Any = None, assertions: Any = None,
    ) -> str:
        """Create a test case (optionally under a parent test suite)."""
        body: dict = {
            "objectType": "TestCase",
            "name": name,
            "description": description or "",
            "testedEntityId": tested_entity_id or None,
            "testedEntityType": tested_entity_type or None,
            "request": {
                "domainId": domain_id or None,
                "serviceId": service_id or None,
                "identityProviderId": identity_provider_id or None,
                "actionId": action_id or None,
                "attributes": request_attributes or {},
            },
            "attributeOverrides": attribute_overrides or {},
            "serviceOverrides": service_overrides or {},
            "assertions": assertions or [],
        }
        b = ctx.branch(branch_id)
        if parent_id:
            return dump(pap.ts_create_child(parent_id, b, body))
        return dump(pap.ts_create_root("TEST_CASE", b, body))

    @mcp.tool()
    def update_test_case(
        branch_id: str, test_case_id: str, version: str = "", name: str = "",
        description: str = "", tested_entity_id: str = "", tested_entity_type: str = "",
        domain_id: str = "", service_id: str = "", identity_provider_id: str = "",
        action_id: str = "", request_attributes: Any = None, attribute_overrides: Any = None,
        service_overrides: Any = None, assertions: Any = None,
    ) -> str:
        """Update a test case. Provide the current version for optimistic locking."""
        body: dict = {"id": test_case_id, "objectType": "TestCase"}
        if version:
            body["version"] = version
        if name:
            body["name"] = name
        body["description"] = description or ""
        if tested_entity_id:
            body["testedEntityId"] = tested_entity_id
        if tested_entity_type:
            body["testedEntityType"] = tested_entity_type
        body["request"] = {
            "domainId": domain_id or None, "serviceId": service_id or None,
            "identityProviderId": identity_provider_id or None, "actionId": action_id or None,
            "attributes": request_attributes or {},
        }
        body["attributeOverrides"] = attribute_overrides or {}
        body["serviceOverrides"] = service_overrides or {}
        body["assertions"] = assertions or []
        return dump(pap.ts_update(test_case_id, ctx.branch(branch_id), body))

    @mcp.tool()
    def delete_test_case(branch_id: str, test_case_id: str) -> str:
        """Delete a test case by ID."""
        return dump(pap.ts_delete(test_case_id, ctx.branch(branch_id)))

    # ---- test runner ------------------------------------------------------
    @mcp.tool()
    def create_test_run(branch_id: str, snapshot_id: str = "", description: str = "",
                        test_case_ids: Any = None) -> str:
        """Start a test run over a snapshot (or the branch), optionally limited to test cases."""
        body: dict = {"description": description or ""}
        if snapshot_id:
            body["snapshotId"] = snapshot_id
        if test_case_ids:
            body["testCaseIds"] = list(test_case_ids)
        return dump(pap.runner_create(ctx.branch(branch_id), body))

    @mcp.tool()
    def end_test_run(test_run_id: str) -> str:
        """End / tear down a running test run."""
        return dump(pap.runner_end(test_run_id))

    @mcp.tool()
    def read_full_test_result(test_run_id: str, test_case_id: str) -> str:
        """Read the full result of one test case within a test run."""
        return dump(pap.runner_result(test_run_id, test_case_id))
