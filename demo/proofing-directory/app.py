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
                       verified_at, expires_at, session_id, account
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


if DATABASE_URL:
    logger.info("Proofing directory using Postgres backend")
    store = PostgresStore(DATABASE_URL)
    user_store = UserPostgresStore(DATABASE_URL)
else:
    logger.info("Proofing directory using in-memory backend (no DATABASE_URL)")
    store = MemoryStore()
    user_store = UserMemoryStore()


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


def _to_resource(row: dict) -> dict:
    """Render a stored row as a SCIM-flavoured resource, computing `active`."""
    expires_at = row["expires_at"]
    if isinstance(expires_at, str):
        expires_at = datetime.fromisoformat(expires_at)
    verified_at = row["verified_at"]
    if isinstance(verified_at, str):
        verified_at = datetime.fromisoformat(verified_at)
    active = expires_at > _now()
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
    }


@app.get("/health")
def health():
    return {"status": "ok", "backend": "postgres" if DATABASE_URL else "memory"}


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
