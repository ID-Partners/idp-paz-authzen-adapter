"""Thin, typed client for the PingAuthorize Policy Editor (PAP) REST API.

Endpoint contract is documented in ../reference/API.md. Every entity operation goes
through one of three resource families:

* version-control  -> branches, snapshots
* policy-manager    -> policies, rules, policysets, statements   (``/api/v2/policy-manager``)
* trust-framework   -> attributes, conditions, services, domains, identity-providers, actions

plus snapshot import/export/merge, the test-suite / test-runner API, and the
``/governance-engine`` decision endpoint.
"""
from __future__ import annotations

from typing import Any, Iterable
from urllib.parse import quote

import httpx

from .config import Config


class PAPError(RuntimeError):
    """Raised when the PAP returns a non-2xx response."""

    def __init__(self, status: int, kind: str, message: str, path: str):
        self.status = status
        self.kind = kind
        self.message = message
        self.path = path
        super().__init__(f"PAP {status} {kind} on {path}: {message}")


# Confirmed policy-manager type tokens (see reference/API.md).
PM_POLICIES = "policies"
PM_RULES = "rules"
PM_POLICY_SETS = "policysets"   # note: no hyphen
PM_STATEMENTS = "statements"

# Confirmed trust-framework type tokens.
TF_ATTRIBUTES = "attributes"
TF_CONDITIONS = "conditions"
TF_SERVICES = "services"
TF_DOMAINS = "domains"
TF_IDENTITY_PROVIDERS = "identity-providers"
TF_ACTIONS = "actions"

# --- PingAuthorize 11.0 write-body discriminators --------------------------
# 11.0 requires a Jackson type discriminator in every create/update body that
# the 10.3-era API inferred from the URL. Policy-manager entities use ``type``;
# trust-framework definitions use ``objectType`` (+ an uppercase ``type``).
PM_TYPE = {
    "policies": "Policy", "rules": "Rule", "policysets": "PolicySet",
    "statements": "Statement", "targets": "Target",
}
TF_OBJECT_TYPE = {
    "attributes": "AttributeDefinition", "conditions": "ConditionDefinition",
    "services": "ServiceDefinition", "domains": "DomainDefinition",
    "actions": "ActionDefinition", "identity-providers": "IdentityProviderDefinition",
}
TF_TYPE = {
    "attributes": "ATTRIBUTE", "conditions": "CONDITION", "services": "SERVICE",
    "domains": "DOMAIN", "actions": "ACTION", "identity-providers": "IDENTITY_PROVIDER",
}


class PAPClient:
    def __init__(self, cfg: Config):
        self._cfg = cfg
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if cfg.pap_auth_method == "header":
            headers["x-user-id"] = cfg.pap_username
        auth = None
        if cfg.pap_auth_method == "basic":
            auth = (cfg.pap_username, cfg.pap_password)
        self._http = httpx.Client(
            base_url=cfg.pap_url,
            headers=headers,
            auth=auth,
            verify=cfg.pap_verify_tls,
            timeout=httpx.Timeout(30.0),
        )
        self._pdp = httpx.Client(
            base_url=cfg.resolved_pdp_url(),
            headers=dict(headers),
            auth=auth,
            verify=cfg.pap_verify_tls,
            timeout=httpx.Timeout(30.0),
        )

    def close(self) -> None:
        self._http.close()
        self._pdp.close()

    # ---- low level ---------------------------------------------------------
    def _request(self, method: str, path: str, *, client: httpx.Client | None = None,
                 params: dict | None = None, json: Any | None = None) -> Any:
        client = client or self._http
        resp = client.request(method, path, params=params, json=json)
        if resp.status_code >= 400:
            kind, message = "HTTPError", resp.text
            try:
                body = resp.json()
                kind = body.get("error", kind)
                message = body.get("message", message)
            except Exception:
                pass
            raise PAPError(resp.status_code, kind, message, path)
        if not resp.content:
            return None
        try:
            return resp.json()
        except Exception:
            return resp.text

    @staticmethod
    def _branch(branch_id: str) -> dict:
        return {"branch": branch_id}

    # ---- version control: branches ----------------------------------------
    def list_branches(self) -> Any:
        return self._request("GET", "/api/version-control/branches")

    def get_branch(self, branch_id: str) -> Any:
        # The list endpoint carries full branch objects; filter client-side since
        # the PAP has no single-branch GET.
        data = self.list_branches().get("data", [])
        for b in data:
            if b.get("id") == branch_id:
                return b
        raise PAPError(404, "NotFound", f"branch {branch_id} not found", "/api/version-control/branches")

    def create_branch(self, name: str, parent_branch_id: str) -> Any:
        return self._request("POST", "/api/version-control/branches",
                             json={"name": name, "parentId": parent_branch_id})

    def commit_branch(self, branch_id: str, message: str) -> Any:
        return self._request("POST", f"/api/version-control/branches/{quote(branch_id)}/commit",
                             json={"message": message})

    # ---- version control: snapshots ---------------------------------------
    def list_snapshots(self, branch_id: str) -> Any:
        return self._request("GET", f"/api/version-control/branches/{quote(branch_id)}/snapshots")

    def create_snapshot(self, branch_id: str, message: str) -> Any:
        return self._request("POST", f"/api/version-control/branches/{quote(branch_id)}/snapshots",
                             json={"message": message})

    def export_snapshot(self, snapshot_id: str, entities: Any | None = None) -> Any:
        return self._request("POST", f"/api/snapshot/{quote(snapshot_id)}/export",
                             json={"entities": entities} if entities is not None else None)

    def import_snapshot(self, snapshot_id: str, snapshot_data: Any) -> Any:
        return self._request("POST", f"/api/snapshot/{quote(snapshot_id)}/import",
                             json=snapshot_data)

    def merge_snapshot(self, snapshot_id: str, snapshot_data: Any,
                       conflict_resolutions: Any | None = None) -> Any:
        body = {"snapshot": snapshot_data}
        if conflict_resolutions is not None:
            body["conflictResolutions"] = conflict_resolutions
        return self._request("POST", f"/api/snapshot/{quote(snapshot_id)}/merge", json=body)

    # ---- policy manager (policies / rules / policysets / statements) -------
    def pm_list(self, type_token: str, branch_id: str) -> Any:
        return self._request("GET", f"/api/v2/policy-manager/{type_token}",
                             params=self._branch(branch_id))

    def pm_get(self, type_token: str, entity_id: str, branch_id: str) -> Any:
        return self._request("GET", f"/api/v2/policy-manager/{type_token}/{quote(entity_id)}",
                             params=self._branch(branch_id))

    def pm_create(self, type_token: str, branch_id: str, body: dict) -> Any:
        body = {**body, "type": body.get("type") or PM_TYPE.get(type_token)}
        return self._request("POST", f"/api/v2/policy-manager/{type_token}",
                             params=self._branch(branch_id), json=body)

    def pm_update(self, type_token: str, entity_id: str, branch_id: str, body: dict) -> Any:
        body = {**body, "type": body.get("type") or PM_TYPE.get(type_token)}
        return self._request("PUT", f"/api/v2/policy-manager/{type_token}/{quote(entity_id)}",
                             params=self._branch(branch_id), json=body)

    def pm_delete(self, type_token: str, entity_id: str, branch_id: str) -> Any:
        return self._request("DELETE", f"/api/v2/policy-manager/{type_token}/{quote(entity_id)}",
                             params=self._branch(branch_id))

    # ---- trust framework ---------------------------------------------------
    def tf_list(self, type_token: str, branch_id: str) -> Any:
        return self._request("GET", f"/api/trust-framework/list/{type_token}",
                             params=self._branch(branch_id))

    def tf_roots(self, type_token: str, branch_id: str) -> Any:
        return self._request("GET", f"/api/trust-framework/roots/{type_token}",
                             params=self._branch(branch_id))

    def tf_get(self, entity_id: str, branch_id: str) -> Any:
        return self._request("GET", f"/api/trust-framework/{quote(entity_id)}",
                             params=self._branch(branch_id))

    def tf_children(self, entity_id: str, branch_id: str) -> Any:
        return self._request("GET", f"/api/trust-framework/{quote(entity_id)}/children",
                             params=self._branch(branch_id))

    def tf_create(self, type_token: str, branch_id: str, body: dict) -> Any:
        body = {**body,
                "objectType": body.get("objectType") or TF_OBJECT_TYPE.get(type_token),
                "type": body.get("type") or TF_TYPE.get(type_token)}
        return self._request("POST", f"/api/trust-framework/{type_token}",
                             params=self._branch(branch_id), json=body)

    def tf_update(self, entity_id: str, branch_id: str, body: dict, type_token: str | None = None) -> Any:
        if type_token:
            body = {**body,
                    "objectType": body.get("objectType") or TF_OBJECT_TYPE.get(type_token),
                    "type": body.get("type") or TF_TYPE.get(type_token)}
        return self._request("PUT", f"/api/trust-framework/{quote(entity_id)}",
                             params=self._branch(branch_id), json=body)

    def tf_delete(self, entity_id: str, branch_id: str) -> Any:
        return self._request("DELETE", f"/api/trust-framework/{quote(entity_id)}",
                             params=self._branch(branch_id))

    # ---- test suites / runner ---------------------------------------------
    def ts_roots(self, test_suite_type: str, branch_id: str) -> Any:
        return self._request("GET", f"/api/test-suite/roots/{test_suite_type}",
                             params=self._branch(branch_id))

    def ts_list(self, test_suite_type: str, branch_id: str) -> Any:
        return self._request("GET", f"/api/test-suite/list/{test_suite_type}",
                             params=self._branch(branch_id))

    def ts_get(self, entity_id: str, branch_id: str) -> Any:
        return self._request("GET", f"/api/test-suite/{quote(entity_id)}",
                             params=self._branch(branch_id))

    def ts_children(self, entity_id: str, branch_id: str) -> Any:
        return self._request("GET", f"/api/test-suite/{quote(entity_id)}/children",
                             params=self._branch(branch_id))

    def ts_create_child(self, parent_id: str, branch_id: str, body: dict) -> Any:
        return self._request("POST", f"/api/test-suite/{quote(parent_id)}/children",
                             params=self._branch(branch_id), json=body)

    def ts_create_root(self, test_suite_type: str, branch_id: str, body: dict) -> Any:
        return self._request("POST", f"/api/test-suite/roots/{test_suite_type}",
                             params=self._branch(branch_id), json=body)

    def ts_update(self, entity_id: str, branch_id: str, body: dict) -> Any:
        return self._request("PUT", f"/api/test-suite/{quote(entity_id)}",
                             params=self._branch(branch_id), json=body)

    def ts_delete(self, entity_id: str, branch_id: str) -> Any:
        return self._request("DELETE", f"/api/test-suite/{quote(entity_id)}",
                             params=self._branch(branch_id))

    def runner_list(self, branch_id: str | None = None, snapshot_id: str | None = None) -> Any:
        params = {}
        if branch_id:
            params["branch"] = branch_id
        if snapshot_id:
            params["snapshot"] = snapshot_id
        return self._request("GET", "/api/test-runner", params=params)

    def runner_create(self, branch_id: str, body: dict) -> Any:
        return self._request("POST", "/api/test-runner",
                             params=self._branch(branch_id), json=body)

    def runner_get(self, run_id: str) -> Any:
        return self._request("GET", f"/api/test-runner/{quote(run_id)}")

    def runner_end(self, run_id: str) -> Any:
        return self._request("DELETE", f"/api/test-runner/{quote(run_id)}")

    def runner_result(self, run_id: str, test_case_id: str) -> Any:
        return self._request("GET",
                             f"/api/test-runner/{quote(run_id)}/results/{quote(test_case_id)}")

    # ---- decision (PDP) ----------------------------------------------------
    def decide(self, domain: str, action: str, service: str, attributes: dict) -> Any:
        body = {"domain": domain, "action": action, "service": service,
                "attributes": attributes or {}}
        return self._request("POST", "/governance-engine", client=self._pdp, json=body)

    def decide_batch(self, requests: Iterable[dict]) -> Any:
        return self._request("POST", "/governance-engine/batch", client=self._pdp,
                             json={"requests": list(requests)})
