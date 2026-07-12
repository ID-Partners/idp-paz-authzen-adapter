# ── Audience-scoped FLATTEN exchange (event endpoint) ────────────────────────────────────────
# The payments agent does a 2nd RFC 8693 exchange with resource = the events audience. PF selects
# the events ATM (below) and mints a FLATTENED token: sub = the ROOT actor (innermost act.sub),
# NO act claim. The agent acts as itself for event publishing — deliberately not delegation, hard
# scoped to this one audience.
#
# Reuses the userToAgentTE policy from token-exchange.tf (it already exposes `act`). The ONLY novel
# bit is extracting the root actor's sub from the act JSON string — see the OGNL note below.

variable "events_audience" {
  type    = string
  default = "https://events.northwind.example"
}

# New JWT ATM for the events audience. Cloned from the attestation JWT ATMs (RS256, centralized
# signing key, at+jwt) but its contract is {sub, client_id} — NO act (the token is flattened).
resource "pingfederate_oauth_access_token_manager" "events" {
  manager_id = "eventsFlatJwtATM"
  name       = "Events Flattened JWT ATM"

  plugin_descriptor_ref = {
    # JWT bearer ATM plugin — confirm exact id on first import/plan against the live PF.
    id = "com.pingidentity.pf.access.token.management.plugins.JwtBearerAccessTokenManagementPlugin"
  }

  configuration = {
    fields = [
      { name = "JWS Algorithm", value = "RS256" },
      { name = "Use Centralized Signing Key", value = "true" },
      { name = "Type Header Value", value = "at+jwt" },
      { name = "Client ID Claim Name", value = "client_id" },
      { name = "Scope Claim Name", value = "scope" },
      { name = "Audience Claim Value", value = var.events_audience },
      { name = "Issuer Claim Value", value = "" },
    ]
  }

  attribute_contract = {
    extended_attributes = [
      { name = "sub" }, # the ROOT actor (promoted), NOT Alice
      { name = "client_id" },
      # deliberately NO "act" — the chain is flattened away for this audience
    ]
  }

  # Select this ATM when the exchange requests resource = the events audience.
  selection_settings = {
    resource_uris = [var.events_audience]
  }
}

locals {
  # Extract the ROOT actor's sub = the LAST `"sub":"…"` in the nested act JSON string.
  # ── This is the fragile OGNL you flagged. It works for the fixed act shape but is brittle.
  #    If it doesn't hold at apply, move this to Ping Authorize (paz-copilot): the audience
  #    policy governs the exchange AND returns the root actor, and the mapping sources sub from
  #    the policy response instead of this string-walk. See paz-audience-flatten.md.
  root_actor_ognl = trimspace(<<-EOT
    (#a = (#this.get("act") == null ? "" : #this.get("act").getValue()), #k = "\"sub\":\"", #i = #a.lastIndexOf(#k), #i < 0 ? "" : #a.substring(#i + #k.length(), #a.indexOf("\"", #i + #k.length())))
  EOT
  )
}

resource "pingfederate_oauth_access_token_mapping" "te_events" {
  context = {
    type        = "TOKEN_EXCHANGE_PROCESSOR_POLICY"
    context_ref = { id = pingfederate_oauth_token_exchange_processor_policy.user_to_agent.policy_id }
  }
  access_token_manager_ref = { id = pingfederate_oauth_access_token_manager.events.manager_id }

  attribute_contract_fulfillment = {
    "sub" = {
      # Promote the ROOT actor into sub. For the demo's fixed topology the root is the
      # concierge; TEXT literal is the working form (dynamic derivation from act is a refinement).
      source = { type = "TEXT" }
      value  = var.agent_concierge
    }
    "client_id" = {
      source = { type = "CONTEXT" }
      value  = "ClientId"
    }
    # NO "act" fulfillment → the flattened token carries no delegation chain.
  }

  # Same attestation-based client auth as the other exchange mappings — the events exchange is
  # also authenticated by attestation (attest_jwt_client_auth_dpop), not the client_secret.
  issuance_criteria = {
    expression_criteria = [{
      error_result = "attestation_validation_failed"
      expression   = local.attestation_criterion
    }]
  }
}
