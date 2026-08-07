# ── Entra bridge clients (idp-entra-demo Phase 1) ────────────────────────────────
# The Northwind bridge bootstraps Entra-originated agents (Copilot Studio via the
# gateway agent) into PF exactly like the AgentCore agents: public clients
# (client_auth NONE), TOKEN_EXCHANGE-only, authenticated by client attestation
# (attest_jwt_client_auth_dpop) — the bridge custodies each client's entity key
# and its public JWK is pre-registered in oidf-mock-attesters.json (entries
# merged from idp-entra-demo/pf/oidf-mock-attesters.entries.json).
#
# ONE ATM + ONE mapping serve ALL entra clients: the act chain is DERIVED from
# the authenticating client's id (OGNL on the ClientId context attribute), so
# registering a new Copilot agent in the bridge needs only a new client resource
# (+ trust-file entry) — no new ATM/mapping. These are NEW resources (no import).

variable "entra_gateway_client" {
  description = "The Northwind gateway agent's PF client (Track B / unregistered-caller fallback)"
  type        = string
  default     = "urn:agent:entra-gateway:v1"
}
variable "entra_copilot_demo_client" {
  description = "The demo Copilot Studio agent's per-agent PF client (bridge registry entry)"
  type        = string
  default     = "urn:agent:entra:d7c5a2b1-0000-4000-8000-copilot0demo"
}

# The shared ATM for Entra-originated agents — same shape as attestJwtAcct/Pmts:
# RFC 9068 at+jwt, iss = the symbolic pf_issuer (so delegated tokens chain as
# exchange subjects), aud = the bank RS, centralized signing key.
resource "pingfederate_oauth_access_token_manager" "attest_jwt_entra" {
  manager_id = "attestJwtEntra"
  name       = "Attestation JWT ATM (Entra bridge)"
  plugin_descriptor_ref = {
    id = "com.pingidentity.pf.access.token.management.plugins.JwtBearerAccessTokenManagementPlugin"
  }
  access_control_settings = {
    allowed_clients  = []
    restrict_clients = false
  }
  attribute_contract = {
    default_subject_attribute = null
    extended_attributes = [
      { multi_valued = false, name = "act" },
      { multi_valued = false, name = "client_id" },
      { multi_valued = false, name = "sub" },
    ]
  }
  configuration = {
    fields = [
      { name = "Access Grant GUID Claim Name", value = "agid" },
      { name = "Active Signing Certificate Key ID", value = "" },
      { name = "Active Symmetric Encryption Key ID", value = "" },
      { name = "Active Symmetric Key ID", value = "" },
      { name = "Asymmetric Encryption JWKS URL", value = "" },
      { name = "Asymmetric Encryption Key", value = "" },
      { name = "Audience Claim Value", value = "https://api.northwind.example/bank" },
      { name = "Authorization Details Claim Name", value = "authorization_details" },
      { name = "Client ID Claim Name", value = "client_id" },
      { name = "Default JWKS URL Cache Duration", value = "720" },
      { name = "Enable Token Revocation", value = "false" },
      { name = "Expand Scope Groups", value = "false" },
      { name = "Include Issued At Claim", value = "true" },
      { name = "Include JWE Key ID Header Parameter", value = "true" },
      { name = "Include JWE X.509 Thumbprint Header Parameter", value = "false" },
      { name = "Include Key ID Header Parameter", value = "true" },
      { name = "Include X.509 Thumbprint Header Parameter", value = "false" },
      { name = "Issuer Claim Value", value = var.pf_issuer },
      { name = "JWE Algorithm", value = "" },
      { name = "JWE Content Encryption Algorithm", value = "" },
      { name = "JWKS Endpoint Cache Duration", value = "720" },
      { name = "JWKS Endpoint Path", value = "" },
      { name = "JWS Algorithm", value = "RS256" },
      { name = "JWT ID Claim Length", value = "22" },
      { name = "Not Before Claim Offset", value = "" },
      { name = "Publish Key ID X.509 URL", value = "false" },
      { name = "Publish Keys to the PingFederate JWKS Endpoint", value = "false" },
      { name = "Publish Thumbprint X.509 URL", value = "false" },
      { name = "Scope Claim Name", value = "scope" },
      { name = "Space Delimit Scope Values", value = "true" },
      { name = "Token Lifetime", value = "720" },
      { name = "Type Header Value", value = "at+jwt" },
      { name = "Use Centralized Signing Key", value = "true" },
    ]
    sensitive_fields = []
    tables = [
      { name = "Symmetric Keys", rows = null },
      { name = "Certificates", rows = null },
    ]
  }
  selection_settings = {
    resource_uris = []
  }
  session_validation_settings = {
    check_session_revocation_status = false
    check_valid_authn_session       = false
    include_session_id              = false
    update_authn_session_activity   = false
  }
  token_endpoint_attribute_contract = {
    attributes = []
  }
}

# The exchange mapping for ALL entra clients: sub = the human principal from the
# subject token (Alice — PF validated her ENTRA-issued user token, see
# entra-user-subject.tf; not a PF-native login, there isn't one on this path);
# act = {"sub": <the authenticating client>} DERIVED from ClientId, so the chain
# names the actual Copilot agent client without per-client mappings. Alice's
# Entra token is always the chain root (no inbound act), so the entra hop is
# always the chain root here.
resource "pingfederate_oauth_access_token_mapping" "te_entra" {
  context = {
    type        = "TOKEN_EXCHANGE_PROCESSOR_POLICY"
    context_ref = { id = pingfederate_oauth_token_exchange_processor_policy.entra_user_to_agent.policy_id }
  }
  access_token_manager_ref = { id = pingfederate_oauth_access_token_manager.attest_jwt_entra.manager_id }

  attribute_contract_fulfillment = {
    "sub" = {
      source = { type = "TOKEN_EXCHANGE_PROCESSOR_POLICY" }
      value  = "subject"
    }
    "act" = {
      # {"sub": <client_id>} built from the ClientId context attribute — one
      # expression for every registered urn:agent:entra:* client. (Referencing
      # the inbound `act` in OGNL is rejected by PF 13.x — see token-exchange.tf
      # — but ClientId is an ordinary context attribute.)
      source = { type = "EXPRESSION" }
      value  = "\"{\\\"sub\\\":\\\"\" + #this.get(\"context.ClientId\") + \"\\\"}\""
    }
    "client_id" = {
      source = { type = "CONTEXT" }
      value  = "ClientId"
    }
  }

  # Attestation-based client auth (attest_jwt_client_auth_dpop): the exchange is
  # refused unless the request carries a valid OAuth-Client-Attestation JWT
  # (signed by the BRIDGE-custodied entity key pre-registered for this client)
  # + the DPoP cnf binding — same criterion as the AgentCore agents.
  issuance_criteria = {
    expression_criteria = [{
      error_result = "attestation_validation_failed"
      expression   = local.attestation_criterion
    }]
  }
}

locals {
  # Shared body for the entra agent clients — public, exchange-only, attested.
  entra_client_base = {
    grant_types                              = ["TOKEN_EXCHANGE"]
    bypass_approval_page                     = true
    restrict_to_default_access_token_manager = true
  }
}

resource "pingfederate_oauth_client" "entra_gateway" {
  client_id = var.entra_gateway_client
  name      = "Entra Gateway Agent (Northwind bridge)"
  enabled   = true

  client_auth = { type = "NONE" } # attestation IS the credential
  grant_types = local.entra_client_base.grant_types

  default_access_token_manager_ref = {
    id = pingfederate_oauth_access_token_manager.attest_jwt_entra.manager_id
  }
  restrict_to_default_access_token_manager = local.entra_client_base.restrict_to_default_access_token_manager
  bypass_approval_page                     = local.entra_client_base.bypass_approval_page

  token_exchange_processor_policy_ref = {
    id = pingfederate_oauth_token_exchange_processor_policy.entra_user_to_agent.policy_id
  }
}

resource "pingfederate_oauth_client" "entra_copilot_demo" {
  client_id = var.entra_copilot_demo_client
  name      = "Northwind Copilot (demo) — Entra agent"
  enabled   = true

  client_auth = { type = "NONE" }
  grant_types = local.entra_client_base.grant_types

  default_access_token_manager_ref = {
    id = pingfederate_oauth_access_token_manager.attest_jwt_entra.manager_id
  }
  restrict_to_default_access_token_manager = local.entra_client_base.restrict_to_default_access_token_manager
  bypass_approval_page                     = local.entra_client_base.bypass_approval_page

  token_exchange_processor_policy_ref = {
    id = pingfederate_oauth_token_exchange_processor_policy.entra_user_to_agent.policy_id
  }
}
