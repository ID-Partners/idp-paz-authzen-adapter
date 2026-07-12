# ── Autonomous demo: Bob (bank staff) + the autonomous agent's CIBA client ─────────────────────
# Second demo mode: the agent pipeline runs headless off Kafka, and BOB — the staff member who
# owns/operates the agent — authorizes each sensitive operation (RFC 9470 step-up resolved via
# FAPI-CIBA push instead of Alice's browser redirect). Alice remains the account owner; her
# accounts are the resource, not the token subject.
#
# Pieces:
#   1. bob added to the demo users PCV (alice's row adopted verbatim via import).
#   2. A Resource Owner Credentials (password-grant) mapping — the SIM BRIDGE: until the PingOne
#      MFA Integration Kit lands, "Bob approved on his phone" is simulated by the dashboard and
#      the orchestrator swaps the approval for a real PF password-grant token (sub=bob, real
#      chain, real PDP). The CIBA grant replaces it in REAL mode; the client carries both.
#   3. A PCV-context access-token mapping so password-grant tokens mint from userJwtATM exactly
#      like Alice's login tokens (same iss/contract → valid subjectJwtProc exchange subjects).
#   4. The autonomous agent's OAuth client: private_key_jwt (FAPI-CIBA requires real client
#      auth), CIBA poll + signed requests, RAR type payment_initiation.

variable "agent_autonomous" {
  type    = string
  default = "urn:agent:northwind-autonomous:v1"
}

variable "bob_password" {
  description = "Demo password for bob (bank staff / agent owner). Same demo value as alice."
  type        = string
  sensitive   = true
  default     = "2Federate"
}

import {
  to = pingfederate_password_credential_validator.userpcv
  id = "userpcv"
}

# Demo users: alice (adopted — encrypted values from the live archive) + bob (NEW).
resource "pingfederate_password_credential_validator" "userpcv" {
  validator_id = "userpcv"
  name         = "Demo Users PCV"
  plugin_descriptor_ref = {
    id = "org.sourceid.saml20.domain.SimpleUsernamePasswordCredentialValidator"
  }
  attribute_contract = {
    extended_attributes = []
  }
  configuration = {
    fields           = []
    sensitive_fields = []
    tables = [
      {
        name = "Users"
        rows = [
          {
            default_row = false
            fields = [
              { name = "Relax Password Requirements", value = "true" },
              { name = "Username", value = "alice" },
            ]
            sensitive_fields = [
              {
                name            = "Password"
                encrypted_value = "OBF:JWE:eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2Iiwia2lkIjoiR3NHNmFxWUJhTyIsInZlcnNpb24iOiIxMy4wLjMuMCJ9..811ZKk4jW5wiYtadGaLk_Q.tUkR0WvtJBEuW243Fmmnj-AWDeB_EegUa-5tJ0gblo06V3I4nVJSjvdD4ST7bLX2X_rp5wxiCU-Duw3jnqIBjA.Jo6QhokuP9Wo1vk1YieFDg"
              },
              {
                name            = "Confirm Password"
                encrypted_value = "OBF:JWE:eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2Iiwia2lkIjoiR3NHNmFxWUJhTyIsInZlcnNpb24iOiIxMy4wLjMuMCJ9..jmLC46GkdWgbSUSj9zsdhw.YOP5YdXY-t5AwXVXLjNpVtGu86xQMTtBjDsunFzDcDLBIEBDQaFfgYggczaZDDoKUAsnG6N1ZocT9WBiuQ1wqA._3YHdiwB9NaTu7RFOtAM-g"
              },
            ]
          },
          {
            default_row = false
            fields = [
              { name = "Relax Password Requirements", value = "true" },
              { name = "Username", value = "bob" },
            ]
            sensitive_fields = [
              { name = "Password", value = var.bob_password },
              { name = "Confirm Password", value = var.bob_password },
            ]
          },
        ]
      },
    ]
  }
}

# Password grant plumbing (the sim bridge): PCV → persistent grant.
resource "pingfederate_oauth_resource_owner_credentials_mapping" "userpcv" {
  # mapping_id IS the PCV instance id (password_validator_ref is derived, read-only).
  mapping_id = pingfederate_password_credential_validator.userpcv.validator_id

  attribute_contract_fulfillment = {
    "USER_KEY" = {
      source = { type = "PASSWORD_CREDENTIAL_VALIDATOR" }
      value  = "username"
    }
  }
}

# Password-grant tokens mint from userJwtATM with the SAME contract as Alice's login tokens
# (mirrors the authz_req|htmlform|userJwtATM mapping) — so a Bob token is a first-class
# subject for the userToAgentTE exchange (subjectJwtProc: iss + sub present).
resource "pingfederate_oauth_access_token_mapping" "ropc_user_jwt" {
  # PF rejects a PCV-context mapping until the ROPC mapping for that PCV exists.
  depends_on = [pingfederate_oauth_resource_owner_credentials_mapping.userpcv]
  context = {
    type        = "PCV"
    context_ref = { id = pingfederate_password_credential_validator.userpcv.validator_id }
  }
  access_token_manager_ref = { id = "userJwtATM" }

  attribute_contract_fulfillment = {
    "sub" = {
      source = { type = "PASSWORD_CREDENTIAL_VALIDATOR" }
      value  = "username"
    }
    "name" = {
      source = { type = "PASSWORD_CREDENTIAL_VALIDATOR" }
      value  = "username"
    }
    "acr" = {
      # THE STAFF-APPROVAL CHANNEL MARKER. The password grant exists ONLY as the autonomous
      # demo's staff-approval bridge (Alice logs in via the HTML form → acr
      # urn:pingidentity:loa:password), so tokens minted here carry a distinct acr that the
      # step-up policy recognises as "Bob, the internal authority, approved out-of-band".
      # PF can't attach RFC 9396 authorization_details to an ROPC grant (verified empirically:
      # the RAR plugin only runs on the authorization endpoint), so the PDP admits the staff
      # channel by acr + elevated scope instead of the in-token RAR match. The REAL CIBA
      # mapping (Phase F) stamps the SAME acr — the policy stays put when sim → real.
      source = { type = "TEXT" }
      value  = "urn:northwind:loa:staff-approval"
    }
    "auth_time" = {
      source = { type = "TEXT" }
      value  = "0"
    }
    "client_id" = {
      source = { type = "CONTEXT" }
      value  = "ClientId"
    }
  }
}

# The autonomous agent's OAuth client. PUBLIC-key client auth (private_key_jwt) — FAPI-CIBA
# requires confidential client auth; the JWKS is the committed demo/ciba-cli/ciba-pub-jwk.json
# (its private key rides in the orchestrator's CIBA_CLIENT_KEY_PEM env var, never the repo).
resource "pingfederate_oauth_client" "agent_autonomous" {
  client_id = var.agent_autonomous
  name      = "Autonomous Agent (staff-authorized)"
  enabled   = true

  # RESOURCE_OWNER_CREDENTIALS = the sim bridge; CIBA = the real staff approval (Phase F wires
  # the PingOne MFA authenticator + request policy; the grant plumbing is already on).
  grant_types = ["RESOURCE_OWNER_CREDENTIALS", "CIBA"]

  client_auth = {
    type                      = "PRIVATE_KEY_JWT"
    enforce_replay_prevention = false # PF server default, declared to keep the plan clean
  }
  jwks_settings = {
    jwks = jsonencode({
      keys = [{
        kty = "EC", crv = "P-256", use = "sig", alg = "ES256",
        kid = "d4c67a35a199",
        x   = "yQDhffUOW9bAQMRq31L2bdotQZnLAJtjeQIizEXUpj0",
        y   = "vPqh6rTaf_uBAo-PgnJNetru1tu9nboVojyUEiFvc1Q",
      }]
    })
  }

  ciba_delivery_mode           = "POLL"
  ciba_require_signed_requests = true
  # PF server defaults — declared explicitly (the provider errors on drift from null otherwise).
  ciba_polling_interval    = 3
  ciba_user_code_supported = false

  # Bob's approval covers a SPECIFIC operation: the payment rides as RFC 9396 RAR, governed by
  # the same pf-rar-paz-plugin → Ping Authorize plane as Alice's interactive consent.
  authorization_detail_types = ["payment_initiation"]

  # Same-shaped tokens as Alice's login (iss stamped → valid exchange subject); the agents'
  # audience-scoped ATMs stay selectable for downstream hops.
  default_access_token_manager_ref = {
    id = "userJwtATM"
  }
  restrict_to_default_access_token_manager = false
}
