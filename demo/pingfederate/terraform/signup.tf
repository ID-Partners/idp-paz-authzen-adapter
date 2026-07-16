# ── Sign-up federation: PingOne-authenticated users become first-class PF principals ──────────
#
# New users SIGN UP at PingOne (self-service registration + passkey enrolment, sign-on policy
# Bank_Signup_Passkey) — but the demo's entire delegation chain runs on PF-issued tokens (the
# agents RFC 8693-exchange the user's PF token at every hop). Rather than grafting a browser-SSO
# IdP connection + authentication-policy selector into the baked config (high-risk surgery on
# alice's HTML-form path), PF BROKERS the PingOne identity through the machinery this demo
# already trusts: token exchange.
#
#   BFF /signup → PingOne authorize (register + passkey) → BFF /signup/callback gets the
#   PingOne ID TOKEN → BFF exchanges it at PF (grant_type=token-exchange, subject_token_type=
#   id_token, policy signupTE) → PF validates iss/sig/aud against PingOne's JWKS and mints a
#   userJwtATM token with sub = the PingOne username — the SAME shape as alice's login token,
#   so gateways/PDP/agent-exchange all work unchanged for the new user.
#
# Everything here is ADDITIVE: nothing in alice's htmlform path or the userToAgentTE plane is
# touched. The acr stamped on brokered tokens is a distinct marker (passkey channel).

variable "pingone_env_id" {
  description = "PingOne environment id (AP / console.pingone.asia tenant)"
  type        = string
  default     = "fe8ab8dc-0dbb-4da4-8ee5-004cb3a6f21d"
}

variable "pingone_signup_client_id" {
  description = "PingOne application 'PF Bank Signup Federation' — the audience of the ID tokens PF accepts"
  type        = string
  default     = "0ce9dbdf-7d86-461a-b531-0a4afcb508d0"
}

locals {
  pingone_issuer = "https://auth.pingone.asia/${var.pingone_env_id}/as"
}

# 1) Token processor validating PingOne ID tokens: signature via PingOne's JWKS, issuer pinned,
#    audience pinned to the signup application (an ID token minted for any OTHER PingOne app is
#    refused). preferred_username carries the human-readable username used as the PF subject.
resource "pingfederate_idp_token_processor" "pingone_id_jwt" {
  processor_id = "pingOneIdJwtProc"
  name         = "PingOne Signup ID Token Processor"
  plugin_descriptor_ref = {
    id = "org.sourceid.wstrust.processor.jwt.JWTTokenProcessor"
  }
  configuration = {
    fields = [
      { name = "JWKS Endpoint URI", value = "${local.pingone_issuer}/jwks" },
      { name = "Issuer", value = local.pingone_issuer },
      { name = "Expiry Tolerance", value = "0" },
    ]
  }
  attribute_contract = {
    core_attributes = [
      { name = "sub" },
    ]
    extended_attributes = [
      { name = "preferred_username" },
      # aud is surfaced so the mapping can PIN the audience to the signup application —
      # the JWT processor plugin has no Audience field of its own.
      { name = "aud" },
    ]
  }
}

# 2) Exchange policy for the sign-up brokering — separate from userToAgentTE so the agent
#    delegation plane is untouched.
resource "pingfederate_oauth_token_exchange_processor_policy" "signup" {
  policy_id            = "signupTE"
  name                 = "PingOne Signup Brokering"
  actor_token_required = false

  attribute_contract = {
    extended_attributes = [
      { name = "aud" },
    ]
  }

  processor_mappings = [
    {
      subject_token_type = "urn:ietf:params:oauth:token-type:id_token"
      subject_token_processor = {
        id = pingfederate_idp_token_processor.pingone_id_jwt.processor_id
      }
      attribute_contract_fulfillment = {
        "subject" = {
          # The username (preferred_username with the profile scope); PingOne user GUIDs
          # never become PF subjects.
          source = { type = "SUBJECT_TOKEN" }
          value  = "preferred_username"
        }
        "aud" = {
          source = { type = "SUBJECT_TOKEN" }
          value  = "aud"
        }
      }
    }
  ]
}

# 3) Brokered tokens mint from userJwtATM with the SAME contract as alice's login tokens
#    (mirrors the ROPC + CIBA mappings in ciba.tf) — first-class subjects for the agent
#    exchange chain. Distinct acr marks the passkey sign-up channel.
resource "pingfederate_oauth_access_token_mapping" "te_signup" {
  context = {
    type        = "TOKEN_EXCHANGE_PROCESSOR_POLICY"
    context_ref = { id = pingfederate_oauth_token_exchange_processor_policy.signup.policy_id }
  }
  access_token_manager_ref = { id = "userJwtATM" }

  attribute_contract_fulfillment = {
    "sub" = {
      source = { type = "TOKEN_EXCHANGE_PROCESSOR_POLICY" }
      value  = "subject"
    }
    "name" = {
      source = { type = "TOKEN_EXCHANGE_PROCESSOR_POLICY" }
      value  = "subject"
    }
    "acr" = {
      source = { type = "TEXT" }
      value  = "urn:northwind:loa:passkey"
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

  # Audience pinning: only ID tokens minted FOR the signup application broker into PF user
  # tokens — an ID token from any other PingOne app is refused at issuance.
  issuance_criteria = {
    conditional_criteria = [{
      source         = { type = "TOKEN_EXCHANGE_PROCESSOR_POLICY" }
      attribute_name = "aud"
      condition      = "EQUALS"
      value          = var.pingone_signup_client_id
      error_result   = "invalid_subject_token_audience"
    }]
  }
}
