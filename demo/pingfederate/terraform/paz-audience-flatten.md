# Flatten: TEPP/OGNL vs Ping Authorize

The event-endpoint exchange (`flatten.tf`) needs the **root actor** (innermost `act.sub`) promoted
into `sub`. Two ways to get that value:

## A. In the TEPP (what `flatten.tf` does now)

An `EXPRESSION` mapping walks the `act` JSON string to the **last** `"sub":"…"`:

```
(#a = (#this.get("act") == null ? "" : #this.get("act").getValue()),
 #k = "\"sub\":\"", #i = #a.lastIndexOf(#k),
 #i < 0 ? "" : #a.substring(#i + #k.length(), #a.indexOf("\"", #i + #k.length())))
```

Works for the fixed act shape, `terraform validate`s (it's just a string), but it is **brittle**
string-parsing — sensitive to whitespace/escaping in the act claim and to any change in the chain
serialization. This is exactly the "too complicated in the TEPP" case.

## B. In Ping Authorize (the robust alternative — use the paz-copilot tool)

Move the logic to the **audience policy** that already governs this exchange:

- PF invokes PingAuthorize for the events-audience exchange (the "special policy based on the
  audience" — the original ask). PAZ receives the incoming token / act chain + the requested
  audience.
- The policy (authored declaratively via **paz-copilot**) parses the chain properly, decides
  PERMIT/DENY for the flatten, and **returns the root actor** as an attribute/obligation.
- The access-token mapping sources `sub` from the policy response instead of the OGNL string-walk.

This keeps the fragile parsing out of OGNL and puts the audience decision where it belongs (policy).
Integration point: the PF→PAZ hook for token issuance (the `pf-rar-paz-plugin` governance-engine
call) returns the actor value; the mapping consumes it. Author the policy with paz-copilot, test it
with `pap_test_decision`, export the deployment package (config-as-code), then wire the mapping.

**Decision:** ship A for now (written + validated); switch `te_events`'s `sub` source to B if the
OGNL doesn't hold at apply, or if you want the audience decision governed by policy rather than baked
into the mapping.

## B is authored + tested (2026-07-09)

The Ping Authorize policy for B is built and verified (via paz-copilot), committed to the policy repo
`dphhyland/idp-paz-simplifid-policy`:
- `pap-profile/policies/AuthZEN.snapshot` — adds a **TokenExchange** trust-framework domain + the
  **"Event-endpoint flatten governance"** policy: `DenyUnlessPermit`, condition
  `requestedAudience == https://events.northwind.example`, rule permits when
  `requestingClient == urn:agent:northwind-payments:v1`.
- `deployment-packages/authzen-with-flatten.deploymentpackage` — the PDP artifact.

`pap_test_decision` confirmed: events+payments → **PERMIT**, events+account → **DENY**, a normal
banking request (no audience) → **NOT_APPLICABLE** (thanks to `defaultValue=""` on the audience attr,
so it can't regress the gateway plane under `DenyOverrides`).

Model: the agent **proposes** the root actor (decoding its own token to the innermost `act.sub` is
trivial in code), and PAZ **governs/authorizes** the flatten by audience. To wire it, PF calls this
policy for the events-audience exchange (pf-rar-paz-plugin governance hook) and, on PERMIT, mints
`sub` = the PAZ-authorized proposed root actor — replacing `te_events`'s OGNL `sub` source.
