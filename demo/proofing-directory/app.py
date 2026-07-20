"""
Proofing Directory — the identity directory for the demo.

A minimal, SCIM-flavoured record store for **identity-proofing activities**: when a
customer presents a verifiable credential (an mDL, ISO 18013-5) and a verifier
validates it, the result is written here as a proofing activity keyed by subject
(the account/customer being proofed). The account-origination PDP gate then reads
this directory — via the AuthZEN adapter, which injects `identity_proofing_present`
— so an account can only be opened once a valid proofing activity exists for it.

This is deliberately small: it is the "new record type in the identity directory"
the mDL-proofing feature needs, not a full SCIM server. It backs onto Postgres
when `DATABASE_URL` is set, and falls back to an in-memory store otherwise (local
dev / tests).

    POST /proofing              record a verified proofing activity
    GET  /proofing?subject=…    list active (non-expired) activities for a subject
                                (also accepts a SCIM `filter=subject eq "…"`)
    GET  /proofing/{id}         one activity
    POST /admin/reset           clear all activities (demo convenience)
    GET  /health

    SCIM 2.0 Users (the bank's identities — alice, bob — persisted in Postgres so the
    iOS approver / BFF can switch identities and track device pairing + PingOne linkage):
    GET  /scim/v2/Users                     list (supports filter=userName eq "…")
    GET  /scim/v2/Users/{id}                one user
    POST /scim/v2/Users                     create
    PUT  /scim/v2/Users/{id}                replace (full object)
    PATCH /scim/v2/Users/{id}               partial update (add/replace simple paths)

Record shape (SCIM-flavoured):
    { id, schemas, subject, activityType, doctype, method, claims,
      verifiedAt, expiresAt, sessionId, active }
"""
from __future__ import annotations

import logging
import os
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import FastAPI, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger("proofing-directory")

app = FastAPI(title="Northwind Proofing Directory")

SCHEMA_URN = "urn:idpartners:proofing:1.0:IdentityProofingActivity"
DEFAULT_TTL_SECONDS = int(os.environ.get("PROOFING_TTL_SECONDS", str(30 * 24 * 3600)))
DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Storage backends: Postgres (when DATABASE_URL is set) or in-memory fallback.
# Both expose the same insert() / list_by_subject() / get() / reset() surface.
# ---------------------------------------------------------------------------
class MemoryStore:
    def __init__(self) -> None:
        self._rows: dict[str, dict] = {}

    def insert(self, row: dict) -> None:
        self._rows[row["id"]] = row

    def list_by_subject(self, subject: str) -> list[dict]:
        return [r for r in self._rows.values() if r["subject"] == subject]

    def get(self, rid: str) -> dict | None:
        return self._rows.get(rid)

    def consume(self, subject: str, account: str, account_id: str) -> dict | None:
        """Spend the newest unconsumed, unexpired proofing for (subject, account)."""
        cands = [r for r in self._rows.values()
                 if r["subject"] == subject
                 and (r.get("account") or "") == account
                 and not r.get("consumed_at")
                 and _as_dt(r["expires_at"]) > _now()]
        if not cands:
            return None
        row = max(cands, key=lambda r: _as_dt(r["verified_at"]))
        row["consumed_at"] = _now()
        row["consumed_by_account"] = account_id
        return row

    def reset(self) -> None:
        self._rows.clear()


class PostgresStore:
    """Postgres backend using psycopg3. Table is created on first use."""

    def __init__(self, dsn: str) -> None:
        import psycopg
        from psycopg.types.json import Jsonb

        self._psycopg = psycopg
        self._Jsonb = Jsonb
        self._dsn = dsn
        with self._conn() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS proofing_activities (
                    id            TEXT PRIMARY KEY,
                    subject       TEXT NOT NULL,
                    activity_type TEXT NOT NULL,
                    doctype       TEXT NOT NULL,
                    method        TEXT NOT NULL,
                    claims        JSONB NOT NULL DEFAULT '{}'::jsonb,
                    verified_at   TIMESTAMPTZ NOT NULL,
                    expires_at    TIMESTAMPTZ NOT NULL,
                    session_id    TEXT,
                    account       TEXT
                )
                """
            )
            # Migration for tables created before account-scoped proofing.
            conn.execute(
                "ALTER TABLE proofing_activities ADD COLUMN IF NOT EXISTS account TEXT"
            )
            # Single-use proofing: a proofing is SPENT by the origination it authorises, and
            # records which account spent it — so the record is the proofing for THAT account,
            # and a second origination needs a fresh one.
            conn.execute(
                "ALTER TABLE proofing_activities ADD COLUMN IF NOT EXISTS consumed_at TIMESTAMPTZ"
            )
            conn.execute(
                "ALTER TABLE proofing_activities ADD COLUMN IF NOT EXISTS consumed_by_account TEXT"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS ix_proofing_subject "
                "ON proofing_activities (subject)"
            )
            conn.commit()

    def _conn(self):
        return self._psycopg.connect(self._dsn, autocommit=False)

    def insert(self, row: dict) -> None:
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO proofing_activities
                    (id, subject, activity_type, doctype, method, claims,
                     verified_at, expires_at, session_id, account)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (row["id"], row["subject"], row["activity_type"], row["doctype"],
                 row["method"], self._Jsonb(row["claims"]),
                 row["verified_at"], row["expires_at"], row["session_id"],
                 row.get("account")),
            )
            conn.commit()

    def list_by_subject(self, subject: str) -> list[dict]:
        with self._conn() as conn:
            cur = conn.execute(
                """
                SELECT id, subject, activity_type, doctype, method, claims,
                       verified_at, expires_at, session_id, account,
                       consumed_at, consumed_by_account
                FROM proofing_activities WHERE subject = %s
                """,
                (subject,),
            )
            cols = [d.name for d in cur.description]
            return [dict(zip(cols, r)) for r in cur.fetchall()]

    def get(self, rid: str) -> dict | None:
        with self._conn() as conn:
            cur = conn.execute(
                """
                SELECT id, subject, activity_type, doctype, method, claims,
                       verified_at, expires_at, session_id, account
                FROM proofing_activities WHERE id = %s
                """,
                (rid,),
            )
            row = cur.fetchone()
            if row is None:
                return None
            cols = [d.name for d in cur.description]
            return dict(zip(cols, row))

    def consume(self, subject: str, account: str, account_id: str) -> dict | None:
        """Atomically spend the newest unconsumed, unexpired proofing for (subject, account).

        Done in ONE statement so two concurrent originations can't spend the same proofing —
        the sub-select picks the row and the UPDATE only lands if it is still unconsumed."""
        with self._conn() as conn:
            cur = conn.execute(
                """
                UPDATE proofing_activities SET consumed_at = now(), consumed_by_account = %s
                WHERE id = (
                    SELECT id FROM proofing_activities
                    WHERE subject = %s AND coalesce(account, '') = %s
                      AND consumed_at IS NULL AND expires_at > now()
                    ORDER BY verified_at DESC
                    LIMIT 1
                    FOR UPDATE SKIP LOCKED
                )
                RETURNING id, subject, activity_type, doctype, method, claims,
                          verified_at, expires_at, session_id, account,
                          consumed_at, consumed_by_account
                """,
                (account_id, subject, account),
            )
            row = cur.fetchone()
            conn.commit()
            if row is None:
                return None
            cols = [d.name for d in cur.description]
            return dict(zip(cols, row))

    def reset(self) -> None:
        with self._conn() as conn:
            conn.execute("DELETE FROM proofing_activities")
            conn.commit()


class UserMemoryStore:
    def __init__(self) -> None:
        self._rows: dict[str, dict] = {}

    def upsert(self, row: dict) -> None:
        self._rows[row["id"]] = row

    def list(self) -> list[dict]:
        return list(self._rows.values())

    def get(self, uid: str) -> dict | None:
        return self._rows.get(uid)

    def by_username(self, user_name: str) -> dict | None:
        for r in self._rows.values():
            if r["user_name"].lower() == user_name.lower():
                return r
        return None


class UserPostgresStore:
    """SCIM Users in Postgres. Table created on first use."""

    def __init__(self, dsn: str) -> None:
        import psycopg
        from psycopg.types.json import Jsonb

        self._psycopg = psycopg
        self._Jsonb = Jsonb
        self._dsn = dsn
        with self._conn() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS scim_users (
                    id              TEXT PRIMARY KEY,
                    user_name       TEXT NOT NULL UNIQUE,
                    display_name    TEXT NOT NULL DEFAULT '',
                    active          BOOLEAN NOT NULL DEFAULT TRUE,
                    pingone_user_id TEXT,
                    device_paired   BOOLEAN NOT NULL DEFAULT FALSE,
                    paired_at       TIMESTAMPTZ,
                    attributes      JSONB NOT NULL DEFAULT '{}'::jsonb,
                    created_at      TIMESTAMPTZ NOT NULL,
                    updated_at      TIMESTAMPTZ NOT NULL
                )
                """
            )
            conn.commit()

    def _conn(self):
        return self._psycopg.connect(self._dsn, autocommit=False)

    _COLS = ("id", "user_name", "display_name", "active", "pingone_user_id",
             "device_paired", "paired_at", "attributes", "created_at", "updated_at")

    def upsert(self, row: dict) -> None:
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO scim_users (id, user_name, display_name, active, pingone_user_id,
                                        device_paired, paired_at, attributes, created_at, updated_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (id) DO UPDATE SET
                    user_name = EXCLUDED.user_name, display_name = EXCLUDED.display_name,
                    active = EXCLUDED.active, pingone_user_id = EXCLUDED.pingone_user_id,
                    device_paired = EXCLUDED.device_paired, paired_at = EXCLUDED.paired_at,
                    attributes = EXCLUDED.attributes, updated_at = EXCLUDED.updated_at
                """,
                (row["id"], row["user_name"], row["display_name"], row["active"],
                 row["pingone_user_id"], row["device_paired"], row["paired_at"],
                 self._Jsonb(row["attributes"]), row["created_at"], row["updated_at"]),
            )
            conn.commit()

    def _rows_from(self, cur) -> list[dict]:
        cols = [d.name for d in cur.description]
        return [dict(zip(cols, r)) for r in cur.fetchall()]

    def list(self) -> list[dict]:
        with self._conn() as conn:
            return self._rows_from(conn.execute("SELECT * FROM scim_users ORDER BY user_name"))

    def get(self, uid: str) -> dict | None:
        with self._conn() as conn:
            rows = self._rows_from(conn.execute("SELECT * FROM scim_users WHERE id = %s", (uid,)))
            return rows[0] if rows else None

    def by_username(self, user_name: str) -> dict | None:
        with self._conn() as conn:
            rows = self._rows_from(conn.execute(
                "SELECT * FROM scim_users WHERE LOWER(user_name) = LOWER(%s)", (user_name,)))
            return rows[0] if rows else None



# ---------------------------------------------------------------------------
# Payment authorization consents. Every payment authorization — Alice's RFC 9396
# RAR step-up at PingFederate, or Bob's CIBA staff approval — is recorded here,
# keyed by a minted TRANSACTION ID that rides inside the authorization_details of
# the issued token, so the executed payment links back to the consent that
# authorized it (consent -> grant -> token -> action, the audit/dispute chain).
# ---------------------------------------------------------------------------
class ConsentMemoryStore:
    def __init__(self) -> None:
        self._rows: dict[str, dict] = {}

    def upsert(self, row: dict) -> None:
        self._rows[row["transaction_id"]] = row

    def get(self, txn: str) -> dict | None:
        return self._rows.get(txn)

    def list(self, subject: str | None = None, status: str | None = None) -> list[dict]:
        rows = list(self._rows.values())
        if subject:
            rows = [r for r in rows if r.get("subject") == subject]
        if status:
            rows = [r for r in rows if r.get("status") == status]
        return sorted(rows, key=lambda r: r.get("created_at") or "", reverse=True)


class ConsentPostgresStore:
    def __init__(self, dsn: str) -> None:
        import psycopg
        from psycopg.types.json import Jsonb

        self._psycopg = psycopg
        self._Jsonb = Jsonb
        self._dsn = dsn
        with self._conn() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS payment_consents (
                    transaction_id        TEXT PRIMARY KEY,
                    subject               TEXT NOT NULL,
                    actor                 TEXT,
                    channel               TEXT NOT NULL,
                    status                TEXT NOT NULL,
                    amount                NUMERIC,
                    currency              TEXT,
                    debtor_account        TEXT,
                    creditor_account      TEXT,
                    code                  TEXT,
                    authorization_details JSONB NOT NULL DEFAULT '[]'::jsonb,
                    payment_result        JSONB,
                    created_at            TIMESTAMPTZ NOT NULL,
                    updated_at            TIMESTAMPTZ NOT NULL
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS ix_consents_subject "
                "ON payment_consents (subject)"
            )
            conn.commit()

    def _conn(self):
        return self._psycopg.connect(self._dsn, autocommit=False)

    _COLS = ("transaction_id, subject, actor, channel, status, amount, currency, "
             "debtor_account, creditor_account, code, authorization_details, "
             "payment_result, created_at, updated_at")

    def upsert(self, row: dict) -> None:
        with self._conn() as conn:
            conn.execute(
                f"""
                INSERT INTO payment_consents ({self._COLS})
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (transaction_id) DO UPDATE SET
                    status = EXCLUDED.status,
                    authorization_details = EXCLUDED.authorization_details,
                    payment_result = EXCLUDED.payment_result,
                    updated_at = EXCLUDED.updated_at
                """,
                (row["transaction_id"], row["subject"], row.get("actor"),
                 row["channel"], row["status"], row.get("amount"), row.get("currency"),
                 row.get("debtor_account"), row.get("creditor_account"), row.get("code"),
                 self._Jsonb(row.get("authorization_details") or []),
                 self._Jsonb(row["payment_result"]) if row.get("payment_result") is not None else None,
                 row["created_at"], row["updated_at"]),
            )
            conn.commit()

    def get(self, txn: str) -> dict | None:
        with self._conn() as conn:
            cur = conn.execute(
                f"SELECT {self._COLS} FROM payment_consents WHERE transaction_id = %s",
                (txn,))
            row = cur.fetchone()
            if row is None:
                return None
            cols = [d.name for d in cur.description]
            return dict(zip(cols, row))

    def list(self, subject: str | None = None, status: str | None = None) -> list[dict]:
        q = f"SELECT {self._COLS} FROM payment_consents"
        conds, params = [], []
        if subject:
            conds.append("subject = %s"); params.append(subject)
        if status:
            conds.append("status = %s"); params.append(status)
        if conds:
            q += " WHERE " + " AND ".join(conds)
        q += " ORDER BY created_at DESC LIMIT 200"
        with self._conn() as conn:
            cur = conn.execute(q, tuple(params))
            cols = [d.name for d in cur.description]
            return [dict(zip(cols, r)) for r in cur.fetchall()]


# IDM_DATABASE_URL points this service at the ID Partners Identity Object Model directory
# (idm.entry). When set, all three stores become a FAÇADE over that object model — same REST API,
# storage repointed from the bespoke tables to model entries (consentRecord / identityProofingRecord
# / identity+involvedParty). Opt-in and reversible: unset it to fall back to the bespoke tables.
IDM_DATABASE_URL = os.environ.get("IDM_DATABASE_URL", "").strip()

if IDM_DATABASE_URL:
    logger.info("Proofing directory using Identity Object Model backend (idm.entry)")
    from idm_store import IdmProofingStore, IdmUserStore, IdmConsentStore
    store = IdmProofingStore(IDM_DATABASE_URL)
    user_store = IdmUserStore(IDM_DATABASE_URL)
    consent_store = IdmConsentStore(IDM_DATABASE_URL)
    from idm_store import IdmClientStore, IdmGrantStore
    client_store = IdmClientStore(IDM_DATABASE_URL)   # oauthClientRegistration (projected from PF)
    grant_store = IdmGrantStore(IDM_DATABASE_URL)      # oauthGrant + agentDelegation (projected on delegation)
elif DATABASE_URL:
    logger.info("Proofing directory using Postgres backend")
    store = PostgresStore(DATABASE_URL)
    user_store = UserPostgresStore(DATABASE_URL)
    consent_store = ConsentPostgresStore(DATABASE_URL)
    client_store = grant_store = None   # client/grant registries live only in the idm model
else:
    logger.info("Proofing directory using in-memory backend (no DATABASE_URL)")
    store = MemoryStore()
    user_store = UserMemoryStore()
    consent_store = ConsentMemoryStore()
    client_store = grant_store = None


# Seed the demo identities so the approver/BFF can list them from day one.
def _seed_users() -> None:
    for uname, display in (("alice", "Alice"), ("bob", "Bob")):
        if user_store.by_username(uname) is None:
            now = _now()
            user_store.upsert({
                "id": f"usr_{uuid.uuid4().hex}", "user_name": uname, "display_name": display,
                "active": True, "pingone_user_id": None, "device_paired": False,
                "paired_at": None, "attributes": {}, "created_at": now, "updated_at": now,
            })
            logger.info("seeded SCIM user %s", uname)


_seed_users()


# The demo's OAuth clients, projected into the directory as oauthClientRegistration entries. PF is
# the config source of truth; this is the directory's read-model, so the identity store holds the
# full authority graph (identities + clients + grants + consents + proofings) in one place.
_DEMO_CLIENTS = [
    {"client_id": "northwind-webapp", "name": "Northwind Web App (BFF)", "subject_type": "workload",
     "token_endpoint_auth_method": "client_secret_basic",
     "grant_types": ["authorization_code", "urn:ietf:params:oauth:grant-type:token-exchange"]},
    {"client_id": "urn:agent:northwind-concierge:v1", "name": "Concierge Agent", "subject_type": "agent",
     "token_endpoint_auth_method": "attest_jwt_client_auth", "grant_types": ["urn:ietf:params:oauth:grant-type:token-exchange"]},
    {"client_id": "urn:agent:northwind-account:v1", "name": "Account Agent", "subject_type": "agent",
     "token_endpoint_auth_method": "attest_jwt_client_auth", "grant_types": ["urn:ietf:params:oauth:grant-type:token-exchange"]},
    {"client_id": "urn:agent:northwind-payments:v1", "name": "Payments Agent", "subject_type": "agent",
     "token_endpoint_auth_method": "attest_jwt_client_auth", "grant_types": ["urn:ietf:params:oauth:grant-type:token-exchange"]},
    {"client_id": "urn:agent:northwind-autonomous:v1", "name": "Autonomous Agent", "subject_type": "agent",
     "token_endpoint_auth_method": "private_key_jwt", "grant_types": ["urn:openid:params:grant-type:ciba"]},
]


def _seed_clients() -> None:
    if client_store is None:
        return
    for c in _DEMO_CLIENTS:
        if client_store.get(c["client_id"]) is None:
            client_store.upsert({**c, "status": "active", "enabled": True})
            logger.info("seeded oauthClientRegistration %s", c["client_id"])


_seed_clients()


def _as_dt(v) -> datetime:
    """Stored timestamps come back as datetimes from postgres and strings from memory."""
    return datetime.fromisoformat(v) if isinstance(v, str) else v


def _to_resource(row: dict) -> dict:
    """Render a stored row as a SCIM-flavoured resource, computing `active`.

    A CONSUMED proofing is not active: it was spent by the origination it authorised, so it can
    never satisfy the gate again (single-use). That is what makes it the proofing for one
    specific account rather than a standing permit for that account type."""
    expires_at = _as_dt(row["expires_at"])
    verified_at = _as_dt(row["verified_at"])
    active = expires_at > _now() and not row.get("consumed_at")
    return {
        "id": row["id"],
        "schemas": [SCHEMA_URN],
        "subject": row["subject"],
        "activityType": row["activity_type"],
        "doctype": row["doctype"],
        "method": row["method"],
        "claims": row["claims"],
        "verifiedAt": _iso(verified_at),
        "expiresAt": _iso(expires_at),
        "sessionId": row["session_id"],
        "account": row.get("account"),
        "active": active,
        "consumedAt": _iso(_as_dt(row["consumed_at"])) if row.get("consumed_at") else None,
        "consumedByAccount": row.get("consumed_by_account"),
    }


class ConsumeBody(BaseModel):
    subject: str
    account: str = ""
    account_id: str = ""


@app.post("/proofing/consume")
def consume_proofing(body: ConsumeBody):
    """Spend the proofing that authorised an origination, binding it to the account it opened.

    Called by the accounts domain once the account actually EXISTS, so the record becomes the
    proofing for THAT account (`consumedByAccount`) and can never satisfy the gate again — the
    next origination needs a fresh mDL. Consuming only on a real open (not on the PDP permit)
    means a permitted-but-failed origination doesn't burn the customer's proofing.
    404 when there is nothing to spend, so the caller can tell a no-op from a spend."""
    row = store.consume(body.subject.strip().lower(),
                        (body.account or "").strip().lower(),
                        body.account_id)
    if row is None:
        return JSONResponse(status_code=404, content={
            "error": "no_proofing_to_consume",
            "detail": f"no active unconsumed proofing for {body.subject}/{body.account}"})
    logger.info("Proofing %s spent by account %s (subject=%s account=%s)",
                row["id"], body.account_id, body.subject, body.account)
    return _to_resource(row)


@app.get("/health")
def health():
    backend = "idm" if IDM_DATABASE_URL else ("postgres" if DATABASE_URL else "memory")
    return {"status": "ok", "backend": backend}


class ProofingBody(BaseModel):
    subject: str
    doctype: str = "org.iso.18013.5.1.mDL"
    method: str = "oid4vp"
    claims: dict = Field(default_factory=dict)
    session_id: str | None = None
    ttl_seconds: int | None = None
    # The specific account the proofing was performed FOR (e.g. the account type being
    # originated, "savings") — account-scoped proofing rather than a subject-wide pass.
    account: str | None = None


@app.post("/proofing")
def record_proofing(body: ProofingBody):
    """Record a verified identity-proofing activity for a subject."""
    now = _now()
    ttl = body.ttl_seconds if body.ttl_seconds is not None else DEFAULT_TTL_SECONDS
    row = {
        "id": f"prf_{uuid.uuid4().hex}",
        "subject": body.subject,
        "activity_type": "identity_proofing",
        "doctype": body.doctype,
        "method": body.method,
        "claims": body.claims,
        "verified_at": now,
        "expires_at": now + timedelta(seconds=ttl),
        "session_id": body.session_id,
        "account": (body.account or "").strip().lower() or None,
    }
    store.insert(row)
    logger.info("recorded identity_proofing subject=%s doctype=%s method=%s (expires %s)",
                body.subject, body.doctype, body.method, _iso(row["expires_at"]))
    return _to_resource(row)


@app.get("/proofing")
def list_proofing(subject: str | None = Query(default=None),
                  filter: str | None = Query(default=None),
                  active: bool = Query(default=True),
                  account: str | None = Query(default=None)):
    """List proofing activities for a subject. Accepts either `?subject=…` or a
    minimal SCIM `?filter=subject eq "…"`. By default returns only active
    (non-expired) activities — this is what the PDP gate cares about."""
    subj = subject
    if subj is None and filter:
        # minimal SCIM filter: subject eq "value"
        import re
        m = re.search(r'subject\s+eq\s+"([^"]+)"', filter)
        if m:
            subj = m.group(1)
    if not subj:
        return JSONResponse(status_code=400, content={
            "error": "missing_subject",
            "detail": 'provide ?subject=… or ?filter=subject eq "…"'})
    resources = [_to_resource(r) for r in store.list_by_subject(subj)]
    if active:
        resources = [r for r in resources if r["active"]]
    if account:
        # Account-scoped gate: only proofings performed FOR this account count — a
        # proofing for a different account (or an unscoped legacy record) does not.
        acc = account.strip().lower()
        resources = [r for r in resources if (r.get("account") or "") == acc]
    # SCIM ListResponse shape
    return {
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
        "totalResults": len(resources),
        "Resources": resources,
    }


@app.get("/proofing/present")
def proofing_present(subject: str = Query(...), account: str | None = Query(default=None)):
    """The PDP gate's question, answered where the DATA lives (keeps the adapter thin).

    present = the customer has, for this account type, EITHER
        - an ACTIVE (fresh, unconsumed, unexpired) proofing — a new origination is authorised; OR
        - a CONSUMED-but-unexpired proofing — they ALREADY proofed and opened this account type,
          so re-running open_account in the same flow (a resume replay) must NOT re-challenge.
    EXPIRED proofings never count either way.

    This is what makes a full-prompt resume safe in any tool order: replaying a completed
    open_account finds the consumed record and passes, instead of looping on the identity gate."""
    subj = subject.strip().lower()
    acc = (account or "").strip().lower()
    now = _now()
    active = consumed = False
    for r in store.list_by_subject(subj):
        if acc and (r.get("account") or "").strip().lower() != acc:
            continue
        if _as_dt(r["expires_at"]) <= now:
            continue                      # expired: never counts
        if r.get("consumed_at"):
            consumed = True
        else:
            active = True
    reason = "active" if active else ("consumed" if consumed else "none")
    return {"present": active or consumed, "reason": reason,
            "subject": subj, "account": acc}


@app.get("/proofing/{rid}")
def get_proofing(rid: str):
    row = store.get(rid)
    if row is None:
        return JSONResponse(status_code=404, content={"error": "not_found"})
    return _to_resource(row)


@app.post("/admin/reset")
def admin_reset():
    store.reset()
    logger.info("Proofing directory reset")
    return {"status": "reset"}


# ---------------------------------------------------------------------------
# SCIM 2.0 Users — the bank's identities (alice, bob), persisted in Postgres.
# The iOS approver's identity switcher and the BFF's enrolment flow read/write
# these records: userName/displayName plus a bank extension carrying the PingOne
# user linkage and device-pairing state.
# ---------------------------------------------------------------------------
USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
BANK_EXT = "urn:idpartners:scim:1.0:BankUser"


def _user_resource(row: dict) -> dict:
    def iso(v):
        if v is None:
            return None
        return _iso(v if isinstance(v, datetime) else datetime.fromisoformat(str(v)))
    return {
        "schemas": [USER_SCHEMA, BANK_EXT],
        "id": row["id"],
        "userName": row["user_name"],
        "displayName": row["display_name"],
        "active": row["active"],
        BANK_EXT: {
            "pingOneUserId": row["pingone_user_id"],
            "devicePaired": row["device_paired"],
            "pairedAt": iso(row["paired_at"]),
            **(row["attributes"] or {}),
        },
        "meta": {"resourceType": "User",
                 "created": iso(row["created_at"]), "lastModified": iso(row["updated_at"])},
    }


def _apply_user_payload(row: dict, body: dict) -> dict:
    """Fold a SCIM User payload (full or partial) onto a stored row."""
    if "userName" in body:
        row["user_name"] = str(body["userName"])
    if "displayName" in body:
        row["display_name"] = str(body["displayName"])
    if "active" in body:
        row["active"] = bool(body["active"])
    ext = body.get(BANK_EXT) or {}
    if "pingOneUserId" in ext:
        row["pingone_user_id"] = ext["pingOneUserId"]
    if "devicePaired" in ext:
        row["device_paired"] = bool(ext["devicePaired"])
        row["paired_at"] = _now() if row["device_paired"] else None
    extra = {k: v for k, v in ext.items()
             if k not in ("pingOneUserId", "devicePaired", "pairedAt")}
    if extra:
        row["attributes"] = {**(row["attributes"] or {}), **extra}
    row["updated_at"] = _now()
    return row


@app.put("/passkey/{user_name}")
def store_passkey(user_name: str, body: dict):
    """Store a WebAuthn credential (credential_id, public_key, sign_count) for a user, so
    the BFF (the WebAuthn RP) can verify sign-in assertions later. Kept in the user's
    attributes JSONB alongside their SCIM record."""
    row = user_store.by_username(user_name)
    if row is None:
        # auto-provision minimal record
        now = _now()
        row = {"id": f"usr_{uuid.uuid4().hex[:12]}", "user_name": user_name.lower(),
               "display_name": user_name.title(), "active": True, "pingone_user_id": None,
               "device_paired": False, "paired_at": None, "attributes": {},
               "created_at": now, "updated_at": now}
    attrs = dict(row.get("attributes") or {})
    creds = list(attrs.get("passkeys") or [])
    creds = [c for c in creds if c.get("credential_id") != body.get("credential_id")]
    creds.append({"credential_id": body.get("credential_id"),
                  "public_key": body.get("public_key"),
                  "sign_count": int(body.get("sign_count") or 0),
                  "pingone_device_id": body.get("pingone_device_id")})
    attrs["passkeys"] = creds
    row["attributes"] = attrs
    row["updated_at"] = _now()
    user_store.upsert(row)
    return {"user": user_name, "credentials": len(creds)}


@app.get("/passkey/{user_name}")
def get_passkeys(user_name: str):
    row = user_store.by_username(user_name)
    creds = (row.get("attributes") or {}).get("passkeys") or [] if row else []
    return {"user": user_name, "exists": row is not None, "credentials": creds}


@app.get("/scim/v2/Users")
def scim_list_users(filter: str | None = Query(default=None)):
    rows = user_store.list()
    if filter:
        import re
        m = re.search(r'userName\s+eq\s+"([^"]+)"', filter)
        if m:
            r = user_store.by_username(m.group(1))
            rows = [r] if r else []
    resources = [_user_resource(r) for r in rows]
    return {"schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
            "totalResults": len(resources), "Resources": resources}


@app.get("/scim/v2/Users/{uid}")
def scim_get_user(uid: str):
    row = user_store.get(uid)
    if row is None:
        return JSONResponse(status_code=404, content={"error": "not_found"})
    return _user_resource(row)


@app.post("/scim/v2/Users", status_code=201)
def scim_create_user(body: dict):
    uname = str(body.get("userName") or "").strip()
    if not uname:
        return JSONResponse(status_code=400, content={"error": "userName required"})
    if user_store.by_username(uname):
        return JSONResponse(status_code=409, content={"error": "uniqueness", "detail": uname})
    now = _now()
    row = {"id": f"usr_{uuid.uuid4().hex}", "user_name": uname,
           "display_name": str(body.get("displayName") or uname.title()), "active": True,
           "pingone_user_id": None, "device_paired": False, "paired_at": None,
           "attributes": {}, "created_at": now, "updated_at": now}
    row = _apply_user_payload(row, body)
    user_store.upsert(row)
    logger.info("SCIM user created: %s", uname)
    return _user_resource(row)


@app.put("/scim/v2/Users/{uid}")
def scim_replace_user(uid: str, body: dict):
    row = user_store.get(uid)
    if row is None:
        return JSONResponse(status_code=404, content={"error": "not_found"})
    row = _apply_user_payload(row, body)
    user_store.upsert(row)
    return _user_resource(row)


@app.patch("/scim/v2/Users/{uid}")
def scim_patch_user(uid: str, body: dict):
    """Minimal SCIM PatchOp: supports add/replace of simple paths and the bank extension."""
    row = user_store.get(uid)
    if row is None:
        return JSONResponse(status_code=404, content={"error": "not_found"})
    for op in body.get("Operations", []):
        if str(op.get("op", "")).lower() not in ("add", "replace"):
            continue
        path, value = op.get("path"), op.get("value")
        if not path:
            row = _apply_user_payload(row, value or {})
        else:
            # translate a dotted/scoped path into a one-key payload
            key = path.split(":")[-1].split(".")[-1]
            if key in ("userName", "displayName", "active"):
                row = _apply_user_payload(row, {key: value})
            else:
                row = _apply_user_payload(row, {BANK_EXT: {key: value}})
    user_store.upsert(row)
    return _user_resource(row)


# ---------------------------------------------------------------------------
# Payment authorization consents REST
# ---------------------------------------------------------------------------
CONSENT_SCHEMA_URN = "urn:idpartners:consent:1.0:PaymentAuthorizationConsent"


class ConsentBody(BaseModel):
    subject: str                          # the principal whose money moves (alice)
    channel: str                          # rar-stepup | ciba-staff
    actor: str | None = None              # who authorized (alice, bob)
    amount: float | None = None
    currency: str | None = None
    debtor_account: str | None = None
    creditor_account: str | None = None
    code: str | None = None               # CIBA binding code, when applicable
    authorization_details: list = Field(default_factory=list)
    transaction_id: str | None = None     # caller-minted; generated if absent
    status: str = "requested"


class ConsentPatch(BaseModel):
    status: str | None = None
    authorization_details: list | None = None
    payment_result: dict | None = None


def _consent_resource(row: dict) -> dict:
    created = row["created_at"]; updated = row["updated_at"]
    if isinstance(created, str):
        created = datetime.fromisoformat(created)
    if isinstance(updated, str):
        updated = datetime.fromisoformat(updated)
    return {
        "schemas": [CONSENT_SCHEMA_URN],
        "transactionId": row["transaction_id"],
        "subject": row["subject"],
        "actor": row.get("actor"),
        "channel": row["channel"],
        "status": row["status"],
        "amount": float(row["amount"]) if row.get("amount") is not None else None,
        "currency": row.get("currency"),
        "debtorAccount": row.get("debtor_account"),
        "creditorAccount": row.get("creditor_account"),
        "code": row.get("code"),
        "authorizationDetails": row.get("authorization_details") or [],
        "paymentResult": row.get("payment_result"),
        "createdAt": _iso(created),
        "updatedAt": _iso(updated),
    }


@app.post("/consents")
def record_consent(body: ConsentBody):
    """Record a payment authorization consent, minting the transaction id that rides in
    the token's authorization_details so the executed payment links back to it."""
    now = _now()
    txn = (body.transaction_id or "").strip() or f"txn_{uuid.uuid4().hex[:12]}"
    row = {
        "transaction_id": txn,
        "subject": body.subject,
        "actor": body.actor,
        "channel": body.channel,
        "status": body.status,
        "amount": body.amount,
        "currency": body.currency,
        "debtor_account": body.debtor_account,
        "creditor_account": body.creditor_account,
        "code": body.code,
        "authorization_details": body.authorization_details,
        "payment_result": None,
        "created_at": now,
        "updated_at": now,
    }
    consent_store.upsert(row)
    logger.info("recorded payment consent txn=%s subject=%s channel=%s status=%s amount=%s",
                txn, body.subject, body.channel, body.status, body.amount)
    return _consent_resource(row)


@app.get("/consents/check")
def check_consent(subject: str = Query(...), creditor: str = Query(default=""),
                  amount: float = Query(default=0.0), currency: str = Query(default="")):
    """Does an AUTHORIZED consent on record cover this payment? The PDP's policy information
    provider calls this; it answers with a plain boolean so the policy doesn't have to iterate.

    Match = same subject, status authorized, creditor equal (case-insensitive), and the requested
    amount WITHIN the consented amount. The consent is the ceiling, so a payment for less than was
    consented is covered and a payment for more is not.

    ⚠️  ASSURANCE: this proves a consent was RECORDED, not that the user cryptographically
    authorised THIS payment. The consent is asserted by the application (the passkey signs a random
    challenge, not the transaction), so a PERMIT from here is NOT non-repudiable and would not
    satisfy PSD2 RTS Art.5 dynamic linking. See demo/TRANSACTION-AUTHORIZATION.md §2. Replace with
    a signature over the instruction (CIBA+RAR, or a wallet-bound presentation) before this is
    anything more than a demo."""
    rows = consent_store.list(subject=subject, status="authorized")
    cred = (creditor or "").strip().lower()
    matches = []
    for r in rows:
        if cred and str(r.get("creditor_account") or "").strip().lower() != cred:
            continue
        try:
            consented = float(r.get("amount") or 0)
        except (TypeError, ValueError):
            continue
        if amount and amount > consented:
            continue
        if currency and str(r.get("currency") or "").upper() != currency.upper():
            continue
        matches.append(r)
    covered = bool(matches)
    newest = matches[0] if matches else None

    # The assurance ACTUALLY ACHIEVED for this consent — not a fixed label. The policy reads
    # it so a weak path cannot silently stand in for a strong one:
    #   device-signed    a paired device signed over the transaction hash → dynamically
    #                    linked, the artefact is retained, defensible in a dispute
    #   device-approved  a paired device approved, but sent no signature → the tap is
    #                    evidence of presence, NOT of what was agreed
    #   app-asserted     browser passkey signed a RANDOM challenge; the app asserts the
    #                    rest. NOT non-repudiable, would not satisfy PSD2 RTS Art.5.
    assurance = "app-asserted"
    if newest:
        for d in (newest.get("authorization_details") or []):
            if isinstance(d, dict) and d.get("assurance"):
                assurance = str(d["assurance"])
                break
        else:
            if str(newest.get("channel") or "") == "ciba-device":
                assurance = "device-approved"

    logger.info("consent check subject=%s creditor=%s amount=%s -> covered=%s assurance=%s "
                "(%d candidate(s))", subject, creditor, amount, covered, assurance, len(rows))
    return {
        "covered": covered,                       # the attribute the policy reads
        "transactionId": (newest or {}).get("transaction_id"),
        "consentedAmount": (newest or {}).get("amount"),
        "creditorAccount": (newest or {}).get("creditor_account"),
        "channel": (newest or {}).get("channel"),
        "assurance": assurance,                   # the level achieved, carried to the policy
        "nonRepudiable": assurance == "device-signed",
    }


@app.get("/consents")
def list_consents(subject: str | None = Query(default=None),
                  status: str | None = Query(default=None)):
    rows = consent_store.list(subject=subject, status=status)
    return {
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
        "totalResults": len(rows),
        "Resources": [_consent_resource(r) for r in rows],
    }


@app.get("/consents/{txn}")
def get_consent(txn: str):
    row = consent_store.get(txn)
    if row is None:
        return JSONResponse(status_code=404, content={"error": "not_found"})
    return _consent_resource(row)


@app.patch("/consents/{txn}")
def patch_consent(txn: str, body: ConsentPatch):
    """Advance a consent through its lifecycle: requested → authorized (token issued)
    → executed (payment performed) / declined / failed."""
    row = consent_store.get(txn)
    if row is None:
        return JSONResponse(status_code=404, content={"error": "not_found"})
    if body.status:
        row["status"] = body.status
    if body.authorization_details is not None:
        row["authorization_details"] = body.authorization_details
    if body.payment_result is not None:
        row["payment_result"] = body.payment_result
    row["updated_at"] = _now()
    consent_store.upsert(row)
    logger.info("consent txn=%s -> status=%s", txn, row["status"])
    return _consent_resource(row)


# ---------------------------------------------------------------------------
# OAuth clients (oauthClientRegistration) — the directory's read-model of PF's clients
# ---------------------------------------------------------------------------
@app.get("/clients")
def list_clients():
    if client_store is None:
        return JSONResponse(status_code=501, content={"error": "client registry needs the idm backend"})
    return {"totalResults": len(client_store.list()), "resources": client_store.list()}


@app.get("/clients/{client_id:path}")
def get_client(client_id: str):
    if client_store is None:
        return JSONResponse(status_code=501, content={"error": "client registry needs the idm backend"})
    row = client_store.get(client_id)
    if row is None:
        return JSONResponse(status_code=404, content={"error": f"Unknown client {client_id}"})
    return row


# ---------------------------------------------------------------------------
# Delegation grants (oauthGrant + agentDelegation) — projected when the delegation happens
# ---------------------------------------------------------------------------
class GrantBody(BaseModel):
    grant_guid: str | None = None       # PF's agid when known; generated if absent
    principal_id: str                   # the human whose authority is exercised (sub)
    agent_id: str                       # the agent actually acting (act.sub)
    client_id: str | None = None        # the agent operator / registered client
    agent_operator_id: str | None = None
    grant_type: str | None = None
    scope: str | None = None
    consent_ref: str | None = None      # the consent transaction_id that authorised this


@app.post("/grants")
def record_grant(body: GrantBody):
    """Project a delegation grant into the directory at the moment the agent acts on the
    principal's behalf (the RFC 8693 exchange). Upserts by grant_guid, so re-projecting the
    same delegation is idempotent."""
    if grant_store is None:
        return JSONResponse(status_code=501, content={"error": "grant registry needs the idm backend"})
    guid = (body.grant_guid or "").strip() or f"g_{uuid.uuid4().hex[:16]}"
    grant_store.upsert({
        "grant_guid": guid, "principal_id": body.principal_id, "agent_id": body.agent_id,
        "client_id": body.client_id, "agent_operator_id": body.agent_operator_id or body.client_id,
        "grant_type": body.grant_type, "scope": body.scope, "consent_ref": body.consent_ref,
        "issued_timestamp": _now(),
    })
    logger.info("projected oauthGrant guid=%s principal=%s agent=%s", guid, body.principal_id, body.agent_id)
    return grant_store.get(guid)


@app.get("/grants")
def list_grants(principal: str | None = Query(default=None)):
    if grant_store is None:
        return JSONResponse(status_code=501, content={"error": "grant registry needs the idm backend"})
    rows = grant_store.list(principal=principal)
    return {"totalResults": len(rows), "resources": rows}


@app.get("/grants/{grant_guid}")
def get_grant(grant_guid: str):
    if grant_store is None:
        return JSONResponse(status_code=501, content={"error": "grant registry needs the idm backend"})
    row = grant_store.get(grant_guid)
    if row is None:
        return JSONResponse(status_code=404, content={"error": f"Unknown grant {grant_guid}"})
    return row


if __name__ == "__main__":
    import socket
    import uvicorn

    port = int(os.environ.get("PORT", "8075"))
    host = os.environ.get("HOST", "::")
    logger.info("Starting Proofing Directory on %s:%s", host, port)

    if ":" in host or host in ("", "::"):
        sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        except (AttributeError, OSError):
            pass
        sock.bind((host or "::", port))
        sock.listen(128)
        sock.set_inheritable(True)
        uvicorn.run(app, fd=sock.fileno())
    else:
        uvicorn.run(app, host=host, port=port)
