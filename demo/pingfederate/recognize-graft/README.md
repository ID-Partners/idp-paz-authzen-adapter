# Grafting the Recognize ATM into a live PingFederate archive

## Why this exists instead of "just deploy our data.zip"

**Production PF's live config matches no on-disk context.** Prod is the *agentic* build;
`demo/pingfederate/` has drifted ahead of it (extra agent clients, the RAR-PAZ plugin, MFA kit
4.0). Deploying our archive there would not add the Recognize ATM — it would **replace prod's
config with a different one**, silently dropping whatever exists only on the live server.

That is not hypothetical. The same trap hit staging on 2026-08-05: a straight export would have
reverted the Entra client's `entraUserToAgentTE` policy back to `userToAgentTE`, because the
container's baked archive was older than the live config. It was caught by diffing before deploy.

So the rule for any prod content change is **extract from live, graft, deploy** — never push an
on-disk archive over the top.

## Use

```sh
# 1. export the archive FROM the live server (admin API, needs a tunnel / admin TCP proxy)
curl -sk -u administrator:$PW -H 'X-XSRF-Header: PingFederate' \
  -o live-export.zip https://<pf-admin>:9999/pf-admin-api/v1/configArchive/export

# 2. graft
python3 graft.py live-export.zip grafted.zip

# 3. deploy — see the caveats below
```

`graft.py --check grafted.zip` re-verifies an archive without modifying it.

## What it changes — exactly three things

| File | Change |
|---|---|
| `bearer-access-token-management-plugins/recognizeUserAuthATM.xml` | added (the ATM instance) |
| `config-store/bearer-access-token-management-plugins.xml` | one entry in **each** of two maps (id→hash, id→plugin class) |
| `oauth-authz-server-settings.xml` | one `UserKeyToAccessTokenMapping` appended |

Entry count goes up by exactly 1. It refuses to run against an archive that already contains the
ATM, so re-running is safe.

## Verified

Grafted into the committed archive (229 → 230 entries) and imported into PF 13.0.3:

```
recognizeUserAuthATM LOADED: True
mapping LOADED: urn:ietf:params:oauth:grant-type:token-exchange|signupTE|recognizeUserAuthATM
```

A file-by-file diff confirmed only the three files above differ.

## Deploy caveats (these cost a day once)

- **`railway up` from an agent sandbox times out** on the ~15 MB context. Run it from your own
  terminal.
- **`--no-gitignore` is required**: `overlay/pf.jwk`, the system keys and the 9.5 MB MFA kit are
  gitignored, so a normal upload fails at `COPY`. Warm layer caching has masked this once —
  a green build that is actually broken.
- **A PF redeploy wipes in-memory persistent grants.** Anyone mid-approval loses it.
- Prod PF is otherwise **restart-only** (`railway redeploy`), which is also how the DevOps eval
  licence gets renewed on its ~7-day cadence.

## Source of truth

The readable source for this config is `../terraform/recognize-user-auth.tf`. The fragments in
`fragments/` were extracted from an archive PF had already accepted and loaded, so they are known
good rather than hand-authored.
