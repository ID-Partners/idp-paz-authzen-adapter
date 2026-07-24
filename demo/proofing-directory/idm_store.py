"""Identity Object Model backing for the proofing directory.

The proofing directory was three bespoke Postgres tables (proofing_activities, scim_users,
payment_consents). This module makes it a FAÇADE over the ID Partners Identity Object Model
(~/Source/idp-scim-service, spec/identity-object-model.sql): every record becomes an `idm.entry`
row (object_classes[] + JSONB attrs), so the persisted data lives in the directory's own object
model instead of ad-hoc tables — while the service's REST API is unchanged.

Each store below matches the method signature of the bespoke store it replaces, so the FastAPI
route handlers are untouched. The mapping is bidirectional and explicit: REST row -> model entry
on write, model entry -> REST row on read. The primary key of each store (proofing id / user id /
consent transaction id) is carried as attrs.correlationId, which the model realises as the indexed
generated column `correlation_id` — giving an O(1) upsert-by-key without a bespoke unique index.

One-structural-class rule: consentRecord and intentRecord are BOTH structural, so a payment
authorisation is a single `consentRecord` entry (the consent given), with the payment/intent
detail in attrs; a distinct intentRecord entry can be added later if the signed intent is modelled
separately. mDL proofing is an `identityProofingRecord` with the presentation folded into attrs as
`verifiablePresentationEvidence`-shaped fields.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any


def _iso(v: Any) -> str | None:
    if v is None:
        return None
    if isinstance(v, datetime):
        return v.isoformat()
    return str(v)


class _Idm:
    """Shared psycopg3 access to idm.entry. One connection per call, matching the bespoke stores."""

    def __init__(self, dsn: str) -> None:
        import psycopg
        from psycopg.types.json import Jsonb
        self._psycopg = psycopg
        self._Jsonb = Jsonb
        self._dsn = dsn

    def _conn(self):
        return self._psycopg.connect(self._dsn, autocommit=False)

    def _upsert(self, object_classes: list[str], subject_id: str, subject_type: str,
                corr: str, attrs: dict, *, expires_at=None, record_status: str = "active") -> None:
        """Insert or update the entry keyed by attrs.correlationId (== corr)."""
        attrs = dict(attrs)
        attrs["correlationId"] = corr
        with self._conn() as conn:
            cur = conn.execute(
                "SELECT entry_uuid FROM idm.entry WHERE correlation_id = %s "
                "AND %s = ANY(object_classes) LIMIT 1",
                (corr, object_classes[0]))
            existing = cur.fetchone()
            if existing:
                conn.execute(
                    "UPDATE idm.entry SET attrs = %s, record_status = %s, expires_at = %s, "
                    "modified_at = now() WHERE entry_uuid = %s",
                    (self._Jsonb(attrs), record_status, expires_at, existing[0]))
            else:
                conn.execute(
                    "INSERT INTO idm.entry (object_classes, subject_id, subject_type, "
                    "record_status, expires_at, attrs) VALUES (%s, %s, %s, %s, %s, %s)",
                    (object_classes, subject_id, subject_type, record_status,
                     expires_at, self._Jsonb(attrs)))
            conn.commit()

    def _row(self, cur) -> list[dict]:
        cols = [d.name for d in cur.description]
        return [dict(zip(cols, r)) for r in cur.fetchall()]


# ---------------------------------------------------------------------------
# proofing_activities  ->  identityProofingRecord (mDL presentation folded in)
# ---------------------------------------------------------------------------
class IdmProofingStore(_Idm):
    OC = ["identityProofingRecord"]

    def _to_row(self, e: dict) -> dict:
        a = e["attrs"]
        return {
            "id": a.get("correlationId"),
            "subject": e.get("subject_id"),
            "activity_type": a.get("proofingScheme") and a.get("activityType") or a.get("activityType"),
            "doctype": a.get("documentType") or a.get("doctype"),
            "method": a.get("method"),
            "claims": a.get("claims") or {},
            "verified_at": a.get("verifiedAt"),
            "expires_at": _iso(e.get("expires_at")),
            "session_id": a.get("sessionId"),
            "account": a.get("account"),
            "consumed_at": a.get("consumedAt"),
            "consumed_by_account": a.get("consumedByAccount"),
        }

    def insert(self, row: dict) -> None:
        attrs = {
            # identityProofingRecord MUST + authorisationRecord MUST
            "proofingScheme": row.get("method") or "oid4vp",
            "ipLevelAchieved": "IAL2",
            "eventTimestamp": _iso(row.get("verified_at")),
            "outcome": "verified",
            # verifiablePresentationEvidence-shaped (mDL presentation)
            "presentationFormat": "mso_mdoc",
            "credentialType": row.get("doctype"),
            "credentialIssuer": (row.get("claims") or {}).get("issuing_authority"),
            # round-trip / REST fields
            "activityType": row.get("activity_type"),
            "documentType": row.get("doctype"),
            "method": row.get("method"),
            "claims": row.get("claims") or {},
            "verifiedAt": _iso(row.get("verified_at")),
            "sessionId": row.get("session_id"),
            "account": row.get("account"),
            "consumedAt": None,
            "consumedByAccount": None,
        }
        self._upsert(self.OC, row["subject"], "person", row["id"], attrs,
                     expires_at=row.get("expires_at"))

    def list_by_subject(self, subject: str) -> list[dict]:
        with self._conn() as conn:
            cur = conn.execute(
                "SELECT subject_id, expires_at, attrs FROM idm.entry "
                "WHERE %s = ANY(object_classes) AND subject_id = %s",
                (self.OC[0], subject))
            return [self._to_row(e) for e in self._row(cur)]

    def get(self, rid: str) -> dict | None:
        with self._conn() as conn:
            cur = conn.execute(
                "SELECT subject_id, expires_at, attrs FROM idm.entry "
                "WHERE %s = ANY(object_classes) AND correlation_id = %s LIMIT 1",
                (self.OC[0], rid))
            rows = self._row(cur)
            return self._to_row(rows[0]) if rows else None

    def consume(self, subject: str, account: str, account_id: str) -> dict | None:
        """Atomically spend the newest unconsumed, unexpired proofing for (subject, account).

        Single statement so concurrent originations can't double-spend: the sub-select picks
        the row (FOR UPDATE SKIP LOCKED) and the UPDATE only lands if still unconsumed."""
        with self._conn() as conn:
            cur = conn.execute(
                """
                UPDATE idm.entry SET
                  attrs = attrs || jsonb_build_object('consumedAt', to_char(now(),'YYYY-MM-DD"T"HH24:MI:SSOF'),
                                                      'consumedByAccount', %s::text),
                  record_status = 'superseded', modified_at = now()
                WHERE entry_uuid = (
                    SELECT entry_uuid FROM idm.entry
                    WHERE %s = ANY(object_classes) AND subject_id = %s
                      AND coalesce(attrs->>'account','') = %s
                      AND attrs->>'consumedAt' IS NULL AND expires_at > now()
                    ORDER BY attrs->>'verifiedAt' DESC
                    LIMIT 1 FOR UPDATE SKIP LOCKED
                )
                RETURNING subject_id, expires_at, attrs
                """,
                (account_id, self.OC[0], subject, account))
            rows = self._row(cur)
            conn.commit()
            return self._to_row(rows[0]) if rows else None

    def reset(self) -> None:
        with self._conn() as conn:
            conn.execute("DELETE FROM idm.entry WHERE %s = ANY(object_classes)", (self.OC[0],))
            conn.commit()


# ---------------------------------------------------------------------------
# scim_users  ->  identity + involvedParty
# ---------------------------------------------------------------------------
class IdmUserStore(_Idm):
    OC = ["identity", "involvedParty"]

    def _to_row(self, e: dict) -> dict:
        a = e["attrs"]
        return {
            "id": a.get("correlationId"),
            "user_name": a.get("cn"),
            "display_name": a.get("displayName") or "",
            "active": a.get("active", True),
            "pingone_user_id": a.get("pingoneUserId"),
            "device_paired": a.get("devicePaired", False),
            "paired_at": a.get("pairedAt"),
            "attributes": a.get("attributes") or {},
            "created_at": _iso(e.get("created_at")),
            "updated_at": _iso(e.get("modified_at")),
        }

    def upsert(self, row: dict) -> None:
        attrs = {
            # identity MUST: cn, identityID, identityType, identityDescriptor, internalKey
            "cn": row["user_name"],
            "identityID": row["id"],
            "identityType": "person",
            "identityDescriptor": row.get("display_name") or row["user_name"],
            "internalKey": row["id"],
            # round-trip / REST fields
            "displayName": row.get("display_name") or "",
            "active": bool(row.get("active", True)),
            "pingoneUserId": row.get("pingone_user_id"),
            "devicePaired": bool(row.get("device_paired", False)),
            "pairedAt": _iso(row.get("paired_at")),
            "attributes": row.get("attributes") or {},
        }
        self._upsert(self.OC, row["id"], "person", row["id"], attrs,
                     record_status="active" if row.get("active", True) else "suspended")

    def list(self) -> list[dict]:
        with self._conn() as conn:
            cur = conn.execute(
                "SELECT created_at, modified_at, attrs FROM idm.entry "
                "WHERE %s = ANY(object_classes) ORDER BY attrs->>'cn'", (self.OC[0],))
            return [self._to_row(e) for e in self._row(cur)]

    def get(self, uid: str) -> dict | None:
        with self._conn() as conn:
            cur = conn.execute(
                "SELECT created_at, modified_at, attrs FROM idm.entry "
                "WHERE %s = ANY(object_classes) AND correlation_id = %s LIMIT 1",
                (self.OC[0], uid))
            rows = self._row(cur)
            return self._to_row(rows[0]) if rows else None

    def by_username(self, user_name: str) -> dict | None:
        with self._conn() as conn:
            cur = conn.execute(
                "SELECT created_at, modified_at, attrs FROM idm.entry "
                "WHERE %s = ANY(object_classes) AND LOWER(attrs->>'cn') = LOWER(%s) LIMIT 1",
                (self.OC[0], user_name))
            rows = self._row(cur)
            return self._to_row(rows[0]) if rows else None


# ---------------------------------------------------------------------------
# payment_consents  ->  consentRecord (payment/intent detail folded in)
# ---------------------------------------------------------------------------
class IdmConsentStore(_Idm):
    OC = ["consentRecord"]

    def _to_row(self, e: dict) -> dict:
        a = e["attrs"]
        return {
            "transaction_id": a.get("correlationId"),
            "subject": e.get("subject_id"),
            "actor": a.get("actor"),
            "channel": a.get("consentType"),
            "status": a.get("statusRaw"),
            "amount": a.get("amount"),
            "currency": a.get("currency"),
            "debtor_account": a.get("debtorAccount"),
            "creditor_account": a.get("creditorAccount"),
            "code": a.get("code"),
            "authorization_details": a.get("authorizationDetails") or [],
            "payment_result": a.get("paymentResult"),
            "created_at": _iso(e.get("created_at")),
            "updated_at": _iso(e.get("modified_at")),
        }

    def upsert(self, row: dict) -> None:
        amount, creditor = row.get("amount"), row.get("creditor_account")
        purpose = "payment authorisation"
        if amount is not None:
            purpose = f"Pay {amount} {row.get('currency') or ''} to {creditor or ''}".strip()
        attrs = {
            # consentRecord MUST: consentType, purpose, presentedArtefactHash
            "consentType": row.get("channel") or "payment_authorisation",
            "purpose": purpose,
            "presentedArtefactHash": "sha256:" + row["transaction_id"],
            # authorisationRecord MUST: eventTimestamp, outcome
            "eventTimestamp": _iso(row.get("created_at")),
            "outcome": "granted" if row.get("status") == "authorized" else (row.get("status") or "requested"),
            # round-trip / REST fields
            "statusRaw": row.get("status"),
            "actor": row.get("actor"),
            "amount": float(row["amount"]) if row.get("amount") is not None else None,
            "currency": row.get("currency"),
            "debtorAccount": row.get("debtor_account"),
            "creditorAccount": row.get("creditor_account"),
            "code": row.get("code"),
            "authorizationDetails": row.get("authorization_details") or [],
            "paymentResult": row.get("payment_result"),
        }
        rs = {"authorized": "active", "revoked": "revoked", "expired": "expired"}.get(
            row.get("status"), "active")
        self._upsert(self.OC, row["subject"], "person", row["transaction_id"], attrs,
                     record_status=rs)

    def get(self, txn: str) -> dict | None:
        with self._conn() as conn:
            cur = conn.execute(
                "SELECT subject_id, created_at, modified_at, attrs FROM idm.entry "
                "WHERE %s = ANY(object_classes) AND correlation_id = %s LIMIT 1",
                (self.OC[0], txn))
            rows = self._row(cur)
            return self._to_row(rows[0]) if rows else None

    def list(self, subject: str | None = None, status: str | None = None) -> list[dict]:
        q = ("SELECT subject_id, created_at, modified_at, attrs FROM idm.entry "
             "WHERE %s = ANY(object_classes)")
        params: list[Any] = [self.OC[0]]
        if subject:
            q += " AND subject_id = %s"; params.append(subject)
        if status:
            q += " AND attrs->>'statusRaw' = %s"; params.append(status)
        q += " ORDER BY created_at DESC LIMIT 200"
        with self._conn() as conn:
            return [self._to_row(e) for e in self._row(conn.execute(q, tuple(params)))]


# ---------------------------------------------------------------------------
# OAuth clients (projected from PingFederate)  ->  oauthClientRegistration
# ---------------------------------------------------------------------------
class IdmClientStore(_Idm):
    """The demo's OAuth clients, mirrored into the directory as oauthClientRegistration entries.
    PF remains the config source of truth; this is the directory's read-model of the clients."""
    OC = ["oauthClientRegistration"]

    def _to_row(self, e: dict) -> dict:
        a = e["attrs"]
        return {
            "client_id": a.get("clientId"),
            "name": a.get("name"),
            "status": a.get("clientStatus"),
            "token_endpoint_auth_method": a.get("tokenEndpointAuthMethod"),
            "grant_types": a.get("grantTypes") or [],
            "subject_type": e.get("subject_type"),
            "created_at": _iso(e.get("created_at")),
            "updated_at": _iso(e.get("modified_at")),
        }

    def upsert(self, row: dict) -> None:
        attrs = {
            # oauthClientRegistration MUST: clientId, clientStatus, tokenEndpointAuthMethod
            "clientId": row["client_id"],
            "clientStatus": row.get("status") or ("active" if row.get("enabled", True) else "inactive"),
            "tokenEndpointAuthMethod": row.get("token_endpoint_auth_method") or "none",
            # MAY
            "name": row.get("name") or row["client_id"],
            "grantTypes": row.get("grant_types") or [],
        }
        self._upsert(self.OC, row["client_id"], row.get("subject_type") or "workload",
                     row["client_id"], attrs)

    def list(self) -> list[dict]:
        with self._conn() as conn:
            cur = conn.execute(
                "SELECT subject_type, created_at, modified_at, attrs FROM idm.entry "
                "WHERE %s = ANY(object_classes) ORDER BY attrs->>'clientId'", (self.OC[0],))
            return [self._to_row(e) for e in self._row(cur)]

    def get(self, client_id: str) -> dict | None:
        with self._conn() as conn:
            cur = conn.execute(
                "SELECT subject_type, created_at, modified_at, attrs FROM idm.entry "
                "WHERE %s = ANY(object_classes) AND correlation_id = %s LIMIT 1",
                (self.OC[0], client_id))
            rows = self._row(cur)
            return self._to_row(rows[0]) if rows else None


# ---------------------------------------------------------------------------
# Delegation grants (projected when the delegation happens)  ->  oauthGrant + agentDelegation
# ---------------------------------------------------------------------------
class IdmGrantStore(_Idm):
    """A delegation grant, projected into the directory at the moment the agent acts on the
    principal's behalf (the RFC 8693 exchange: sub=principal, act=agent). oauthGrant carries the
    grant; the agentDelegation auxiliary carries principal->agent. Linked to the consent that
    authorised it (consentRef) when known — the consent->grant->token->action audit chain."""
    OC = ["oauthGrant", "agentDelegation"]

    def _to_row(self, e: dict) -> dict:
        a = e["attrs"]
        return {
            "grant_guid": a.get("grantGuid"),
            "client_id": a.get("clientId"),
            "grant_type": a.get("grantType"),
            "issued_timestamp": a.get("issuedTimestamp"),
            "principal_id": a.get("principalId"),
            "agent_id": a.get("agentId"),
            "agent_operator_id": a.get("agentOperatorId"),
            "scope": a.get("scope"),
            "consent_ref": a.get("consentRef"),
            "subject": e.get("subject_id"),
            "created_at": _iso(e.get("created_at")),
            "updated_at": _iso(e.get("modified_at")),
        }

    def upsert(self, row: dict) -> None:
        attrs = {
            # oauthGrant MUST: grantGuid, clientId, grantType, issuedTimestamp
            "grantGuid": row["grant_guid"],
            "clientId": row.get("client_id"),
            "grantType": row.get("grant_type") or "urn:ietf:params:oauth:grant-type:token-exchange",
            "issuedTimestamp": _iso(row.get("issued_timestamp")),
            # agentDelegation MUST: principalId, agentId
            "principalId": row["principal_id"],
            "agentId": row["agent_id"],
            # MAY
            "agentOperatorId": row.get("agent_operator_id"),
            "scope": row.get("scope"),
            "consentRef": row.get("consent_ref"),
        }
        self._upsert(self.OC, row["principal_id"], "person", row["grant_guid"], attrs,
                     expires_at=row.get("expires_at"))

    def list(self, principal: str | None = None) -> list[dict]:
        q = ("SELECT subject_id, created_at, modified_at, attrs FROM idm.entry "
             "WHERE %s = ANY(object_classes)")
        params: list[Any] = [self.OC[0]]
        if principal:
            q += " AND subject_id = %s"; params.append(principal)
        q += " ORDER BY created_at DESC LIMIT 200"
        with self._conn() as conn:
            return [self._to_row(e) for e in self._row(conn.execute(q, tuple(params)))]

    def get(self, grant_guid: str) -> dict | None:
        with self._conn() as conn:
            cur = conn.execute(
                "SELECT subject_id, created_at, modified_at, attrs FROM idm.entry "
                "WHERE %s = ANY(object_classes) AND correlation_id = %s LIMIT 1",
                (self.OC[0], grant_guid))
            rows = self._row(cur)
            return self._to_row(rows[0]) if rows else None
