# ── PingFederate as the Authorization Server for PingOne Recognize "User Authorization" ──────
#
# Recognize supports an OPTIONAL first factor supplied by the integrator: before ANY biometric
# processing, the Authentication Service validates a short-lived JWT that WE mint, against a JWKS
# that WE publish. This file is our side of that contract.
#
# Direction of trust (there are two, and they are easy to swap by mistake):
#
#   THIS FILE:  PF is the AS.  Keyless fetches PF's JWKS and validates a token PF minted.
#               Tenant config, which ONLY Keyless staff can set:
#                 User Authorization Type      = "RemoteJWKSet"
#                 User Authorization JWKs URI  = <the jwks_uri output below>
#
#   NOT THIS FILE: the OIDC/SAML wrapper, where Recognize is the IdP at
#               https://idp.keyless.io/realms/<realm> and PF federates TO it. That is a
#               pingfederate_idp_connection, needs no ATM, and is the better surface for a
#               plain sign-on.
#
# Token contract, verbatim from web-sdk-reference-user-authorization:
#   sub = "The username passed to the SDK session"
#   aud = "authentication-service"
#   iat, exp — 5-10 minutes is sufficient; up to 5 minutes of clock skew tolerated
#   single-use for the duration of one session
# Missing, expired, or sub != the SDK username → SERVER_FORBIDDEN, before any biometrics.
#
# ── WHY signupTE AND NOT userToAgentTE ───────────────────────────────────────────────────────
# The obvious wiring is "exchange the signed-in user's PF token". It does not work for the case
# that matters most: Recognize AS SIGN-ON, where there is no session yet to exchange.
#
# signupTE solves both cases at once. It already accepts the BFF's own self-signed assertion
# (pingOneIdJwtProc validates it against the BFF's JWKS) and maps `subject` = preferred_username
# — which IS the username string the SDK is given. So the BFF can mint a first-factor token for
# an as-yet-unauthenticated user at sign-on, and for a signed-in user at step-up, through one
# path. No second exchange client, no second policy.
#
# ⚠ HARD CORRECTNESS CONSTRAINT: `sub` resolves to preferred_username. The browser MUST pass the
# SAME string as the SDK's `username`. A mismatch fails every session with SERVER_FORBIDDEN and
# the wire cannot tell you why (bodies are end-to-end encrypted). In app.py both sides come from
# the one normalised `user` value — keep it that way.

variable "recognize_audience" {
  description = "Recognize User Authorization audience — the `aud` claim value. Fixed by the vendor; do not change."
  type        = string
  default     = "authentication-service"
}

# Internal ATM-selection key only. NOT sent to Keyless, NOT the audience, never dialed — see the
# selection_settings comment below for why this exists and why it is a URN.
variable "recognize_resource_urn" {
  description = "RFC 8707 `resource` value the BFF sends so PF selects recognizeUserAuthATM. Absolute-URI form is a PF requirement."
  type        = string
  default     = "urn:northwind:recognize:authentication-service"
}

# ── The ATM that mints the first-factor assertion ────────────────────────────────────────────
# Cloned from the events flatten ATM (flatten.tf): RS256 on the CENTRALIZED signing key, so the
# public half is already published at PF's /pf/JWKS. That is the whole reason RemoteJWKSet works
# here with no extra key-publishing surface to build or rotate.
resource "pingfederate_oauth_access_token_manager" "recognize_user_auth" {
  manager_id = "recognizeUserAuthATM"
  name       = "PingOne Recognize User Authorization ATM"

  plugin_descriptor_ref = {
    id = "com.pingidentity.pf.access.token.management.plugins.JwtBearerAccessTokenManagementPlugin"
  }

  configuration = {
    fields = [
      { name = "JWS Algorithm", value = "RS256" },
      { name = "Use Centralized Signing Key", value = "true" },

      # NOT at+jwt. This is a first-factor assertion consumed by a third party, not an RFC 9068
      # access token for our own resource servers. Keyless documents no typ requirement, so the
      # plain value is the conservative choice against a strict validator.
      { name = "Type Header Value", value = "JWT" },

      { name = "Audience Claim Value", value = var.recognize_audience },

      # Deliberately blank. var.pf_issuer is a SYMBOLIC string for our own subjectJwtProc
      # round-trip (see variables.tf), not a real endpoint — stamping it would put a value that
      # means nothing to Keyless into their token, and would trip an iss check if they add one.
      { name = "Issuer Claim Value", value = "" },

      { name = "Client ID Claim Name", value = "client_id" },
      { name = "Scope Claim Name", value = "scope" },

      # REQUIRED by the Recognize contract, and NOT safe to leave implicit. The descriptor's
      # default is "true", but the provider sends nothing for an unspecified field and PF then
      # omits the claim — verified: the first minted token came back with exp but no iat, which
      # Recognize rejects. Declare it.
      { name = "Include Issued At Claim", value = "true" },

      # 5 minutes. The docs say 5-10 is sufficient and tolerate 5 minutes of clock skew, and the
      # token is single-use per session — short is strictly better. Field name confirmed against
      # GET /oauth/accessTokenManagers/descriptors/…JwtBearerAccessTokenManagementPlugin.
      { name = "Token Lifetime", value = "5" },
    ]
  }

  attribute_contract = {
    extended_attributes = [
      { name = "sub" }, # the SDK username — see the constraint note above
    ]
  }

  # ── ATM selection: an RFC 8707 `resource`, and it has to be a URN ────────────────────────────
  # Two constraints collide here. PF rejects a non-absolute resource URI outright —
  #   422 oauth_access_token_management_invalid_resource_uri
  #   "Resource URIs must be absolute and cannot contain a query or fragment part."
  # — so the bare audience string "authentication-service" cannot be used. And PF 13 IGNORED the
  # explicit `access_token_manager_id` request parameter in this exchange (verified: the minted
  # token came back stamped pi.atm=userJwtATM, typ=at+jwt, 8h lifetime — the client's DEFAULT
  # ATM), so that selector alone is not sufficient either.
  #
  # A URN satisfies "absolute" while being honest about what it is: a SELECTION KEY, not an
  # endpoint. Nothing ever dials it. The token's actual `aud` comes from Audience Claim Value
  # above and remains the bare "authentication-service" that Recognize requires — the two are
  # independent, which is what makes this safe rather than a second competing identifier.
  selection_settings = {
    resource_uris = [var.recognize_resource_urn]
  }
}

# ── The mapping: BFF assertion → a Recognize-audienced first-factor token ────────────────────
# NOTE the deliberate ABSENCE of an attestation issuance_criterion, unlike te_payments /
# te_account / te_events. Those are exchanges performed BY an attested agent presenting an
# OAuth-Client-Attestation header. This one is performed by the BFF for a human at a browser.
# Requiring attestation would fail every call. Criteria are per-mapping, so the agent mappings
# are unaffected by its absence here.
#
# The contract is `sub` ONLY — no scope, no act, no client_id beyond what the plugin stamps.
# This token is deliberately incapable of being used as an access token anywhere in the demo:
# its audience is authentication-service, which no resource server here accepts.
resource "pingfederate_oauth_access_token_mapping" "te_recognize_user_auth" {
  context = {
    type        = "TOKEN_EXCHANGE_PROCESSOR_POLICY"
    context_ref = { id = pingfederate_oauth_token_exchange_processor_policy.signup.policy_id }
  }
  access_token_manager_ref = {
    id = pingfederate_oauth_access_token_manager.recognize_user_auth.manager_id
  }

  attribute_contract_fulfillment = {
    "sub" = {
      source = { type = "TOKEN_EXCHANGE_PROCESSOR_POLICY" }
      value  = "subject" # = preferred_username from the BFF assertion
    }
  }
}

# ── What to hand Keyless ─────────────────────────────────────────────────────────────────────
# ⚠ Do NOT build this from var.pf_issuer. That variable is a SYMBOLIC RFC 9068 `iss` string that
# deliberately matches no live host (see variables.tf) — an earlier version of this output did
# exactly that and produced a URL nothing serves.
variable "pf_public_base_url" {
  description = "The PF runtime's REAL public origin (Railway service domain). Distinct from var.pf_issuer, which is symbolic and not dialable."
  type        = string
  default     = "https://pingfederate-staging.up.railway.app"
}

output "recognize_user_authorization_jwks_uri" {
  description = "The tenant's `User Authorization JWKs URI`. Verified publicly reachable and carrying the centralized signing key."
  value       = "${var.pf_public_base_url}/pf/JWKS"
}

# ⚠ KNOWN GAP — read before pointing Keyless at PF's DISCOVERY url rather than the JWKS url.
# PF sits behind Railway's TLS-terminating proxy and still advertises the container-local origin:
#   GET https://pingfederate-staging.up.railway.app/.well-known/openid-configuration
#     -> "issuer": "https://localhost:9031", "jwks_uri": "https://localhost:9031/pf/JWKS"
# The JWKS PATH is fine (that same path on the public host returns 200), but any consumer that
# does OIDC DISCOVERY will follow jwks_uri to localhost and fail. Fixing it needs BOTH
# server_settings.federation_info.base_url = the public URL AND virtual_host_names listing the
# public host (Jetty only trusts X-Forwarded-Host for registered vhosts). That change moves the
# advertised issuer, so it is NOT a drive-by edit — it is deliberately left undone here.
output "recognize_pf_discovery_is_proxy_broken" {
  description = "True while PF advertises localhost in its discovery document; a consumer needing discovery (rather than a direct JWKS URL) cannot use PF until federation_info.base_url + virtual_host_names are set."
  value       = true
}

output "recognize_user_authorization_audience" {
  description = "The `aud` PF stamps; must equal what the Authentication Service expects."
  value       = var.recognize_audience
}
