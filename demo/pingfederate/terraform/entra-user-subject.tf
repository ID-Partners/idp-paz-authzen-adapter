# ── Entra as a trusted subject-token issuer (idp-entra-demo correction) ─────────────────
#
# Originally the Copilot Studio connection was modeled as a direct OAuth login against
# PingFederate — Alice "signs into PF" through the connector, and that PF-issued token became
# the RFC 8693 subject_token the bridge presents. That's backwards: in the real flow Alice is
# already signed into Entra (M365) before she ever opens Copilot, and Copilot already holds an
# Entra-issued token for her — there's no separate PF login step for an agent to trigger. What
# the bridge actually receives, and must present as subject_token, is that Entra user token.
#
# This file adds a SECOND subject-token trust path alongside subjectJwtProc/userToAgentTE (which
# validates PF's OWN previously-issued tokens, still used unchanged for every non-Entra hop):
# entraSubjectJwtProc validates a token PF itself never issued, from an issuer it has to be told
# to trust — Entra — exactly the way it trusts any other IdP. Default is now the REAL mydigitalid
# tenant (e9e4706f-67ac-4ce8-be45-0e1b42b4cc87), not a mock — Copilot Studio's A2A connection to
# the gateway uses genuine OBO (On-Behalf-Of) authentication with Microsoft Entra ID as the
# identity provider (see COPILOT-STUDIO-SETUP.md), which mints Alice a real Entra-issued,
# audience-scoped access token for api://mydigitalid.com.au/northwind-bridge. Override both vars
# with `-var` to point at the bridge's mock-mode `/mock-entra/jwks` for local/CI testing without a
# live Copilot Studio session (see bridge/entra.py's mint_mock_user_token).
#
# Only entra-agents.tf's `te_entra` mapping is repointed at the new policy. Every other exchange
# (the AgentCore-style agents, and any hop where an agent exchanges a token PF itself issued)
# keeps using userToAgentTE/subjectJwtProc exactly as before.

variable "entra_jwks_url" {
  description = <<-EOT
    Entra JWKS PF fetches to verify Alice's subject token. Real tenant discovery endpoint by
    default. For mock-mode local/CI testing, override to the bridge's own /mock-entra/jwks —
    if that bridge is Railway-hosted and this PF instance calls it over .railway.internal, use
    the INTERNAL hostname, not the public one: PF fetching a public URL from inside Railway's
    private network hairpins back out to the public internet, measured as a consistent ~20s
    stall ending in a client-side timeout — a real gotcha, not a hypothetical one.
  EOT
  type        = string
  default     = "https://login.microsoftonline.com/e9e4706f-67ac-4ce8-be45-0e1b42b4cc87/discovery/v2.0/keys"
}
variable "entra_issuer" {
  description = "The Entra tenant issuer this token processor trusts — the real mydigitalid tenant by default; override to https://login.microsoftonline.com/mock-tenant/v2.0 for mock-mode testing."
  type        = string
  default     = "https://login.microsoftonline.com/e9e4706f-67ac-4ce8-be45-0e1b42b4cc87/v2.0"
}

# Validates Alice's Entra-issued user token. Same JWT Token Processor plugin as subjectJwtProc,
# pointed at a DIFFERENT issuer and JWKS — the whole point is PF now trusts two distinct token
# origins for two distinct purposes, not one processor doing double duty.
resource "pingfederate_idp_token_processor" "entra_subject_jwt" {
  processor_id = "entraSubjectJwtProc"
  name         = "Entra Subject JWT Processor (Alice's user token)"
  plugin_descriptor_ref = {
    id = "org.sourceid.wstrust.processor.jwt.JWTTokenProcessor"
  }
  configuration = {
    fields = [
      { name = "JWKS Endpoint URI", value = var.entra_jwks_url },
      { name = "Issuer", value = var.entra_issuer },
      { name = "Expiry Tolerance", value = "0" },
    ]
  }
  attribute_contract = {
    core_attributes = [
      { name = "sub" }, # mock-minted as "alice" — see mint_mock_user_token's own note on why
    ]
    extended_attributes = [
      { name = "oid" },               # Entra's stable per-tenant user id — not used as subject
                                       # today, but present for a future customer-id lookup that
                                       # maps it rather than trusting sub directly.
      { name = "preferred_username" },
    ]
  }
}

# Alice's Entra token is always the ROOT of the delegation chain (she's the human; nothing is
# nested under her), so unlike userToAgentTE this policy carries no `act` extended attribute —
# there is never an inbound act to expose from this subject.
resource "pingfederate_oauth_token_exchange_processor_policy" "entra_user_to_agent" {
  policy_id            = "entraUserToAgentTE"
  name                 = "Entra User-to-Agent Token Exchange"
  actor_token_required = false

  processor_mappings = [
    {
      subject_token_type = "urn:ietf:params:oauth:token-type:access_token"
      subject_token_processor = {
        id = pingfederate_idp_token_processor.entra_subject_jwt.processor_id
      }
      attribute_contract_fulfillment = {
        "subject" = {
          source = { type = "SUBJECT_TOKEN" }
          value  = "sub"
        }
      }
    }
  ]
}
