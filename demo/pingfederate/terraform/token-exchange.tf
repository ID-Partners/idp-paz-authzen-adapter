# ── Adopt the existing (hand-built) resources so Terraform MODIFIES them, never recreates ──
# Run `terraform plan -generate-config-out=generated.tf` once to capture the exact current
# bodies, then keep the edited resources below. Confirm the import IDs against the PF admin API
# (GET /oauth/accessTokenMappings, /oauth/tokenExchange/processor/policies, /idp/tokenProcessors).

import {
  to = pingfederate_idp_token_processor.subject_jwt
  id = "subjectJwtProc"
}
import {
  to = pingfederate_oauth_token_exchange_processor_policy.user_to_agent
  id = "userToAgentTE"
}
import {
  to = pingfederate_oauth_access_token_mapping.te_payments
  id = "urn:ietf:params:oauth:grant-type:token-exchange|userToAgentTE|attestJwtPmts" # confirm exact id on import
}
import {
  to = pingfederate_oauth_access_token_mapping.te_account
  id = "urn:ietf:params:oauth:grant-type:token-exchange|userToAgentTE|attestJwtAcct" # confirm exact id on import
}

# 1) Subject-token processor: expose the inbound `act` claim (adds to acr, scope already present).
resource "pingfederate_idp_token_processor" "subject_jwt" {
  processor_id = "subjectJwtProc"
  name         = "Subject JWT Processor (user token)"
  plugin_descriptor_ref = {
    # The JWT token processor plugin id from the existing instance (confirmed via import).
    id = "org.sourceid.wstrust.processor.jwt.JWTTokenProcessor"
  }
  configuration = {
    fields = [
      { name = "JWKS Endpoint URI", value = "http://localhost:9080/pf/JWKS" },
      { name = "Issuer", value = var.pf_issuer },
      { name = "Expiry Tolerance", value = "0" },
    ]
  }
  attribute_contract = {
    core_attributes = [
      { name = "sub" }, # the processor's core attr (confirmed via live import)
    ]
    extended_attributes = [
      { name = "acr" },
      { name = "scope" },
      { name = "act" }, # ← NEW: makes subjecttoken.act available to the exchange policy
    ]
  }
}

# 2) Token-exchange processor policy: carry `sub` AND the inbound `act` through to the mappings.
resource "pingfederate_oauth_token_exchange_processor_policy" "user_to_agent" {
  policy_id            = "userToAgentTE"
  name                 = "User-to-Agent Token Exchange"
  actor_token_required = false

  attribute_contract = {
    extended_attributes = [
      { name = "act" }, # ← NEW: the policy now exposes tepp.act
    ]
  }

  processor_mappings = [
    {
      subject_token_type = "urn:ietf:params:oauth:token-type:access_token"
      subject_token_processor = {
        id = pingfederate_idp_token_processor.subject_jwt.processor_id
      }
      attribute_contract_fulfillment = {
        "subject" = {
          source = { type = "SUBJECT_TOKEN" }
          value  = "sub"
        }
        "act" = {
          source = { type = "SUBJECT_TOKEN" } # ← NEW: the delegator chain from the incoming token
          value  = "act"
        }
      }
    }
  ]
}

# 3) Access-token mappings: DERIVE act = {this-agent, act={…incoming…}} via an OGNL expression,
#    instead of the old per-agent Text literal. The current actor's own id is a literal (it IS
#    this agent); everything under it is wrapped from tepp.act. Empty incoming act → just {sub}.
locals {
  # Wrap the inbound act (from the token-exchange processor policy) under this agent.
  act_expression = { for id in [var.agent_payments, var.agent_account] : id =>
    "\"{\\\"sub\\\":\\\"${id}\\\"\" + (#this.get(\"act\") == null ? \"\" : \",\\\"act\\\":\" + #this.get(\"act\").getValue()) + \"}\""
  }

  # Attestation-based client authentication: the pf-oidf-modules OGNL entry point that reads the
  # OAuth-Client-Attestation + DPoP headers off the request and verifies the attester-signed
  # attestation JWT + cnf binding. Placed as a token-issuance criterion so the exchange is refused
  # unless a valid attestation is presented — this is what lets us drop the client_secret.
  attestation_criterion = "@${var.attestation_utils_class}@validateClientAttestation(#this)"
}

resource "pingfederate_oauth_access_token_mapping" "te_payments" {
  context = {
    type        = "TOKEN_EXCHANGE_PROCESSOR_POLICY"
    context_ref = { id = pingfederate_oauth_token_exchange_processor_policy.user_to_agent.policy_id }
  }
  access_token_manager_ref = { id = "attestJwtPmts" }

  attribute_contract_fulfillment = {
    "sub" = {
      source = { type = "TOKEN_EXCHANGE_PROCESSOR_POLICY" }
      value  = "subject" # sub = the human principal (Alice), unchanged
    }
    "act" = {
      # Nested act chain: this agent wrapping the concierge (the demo's fixed delegation
      # topology). sub stays the human principal; act records who acted. TEXT literal — the
      # working form; a dynamic derivation from subjecttoken.act is a future refinement.
      source = { type = "TEXT" }
      value  = "{\"sub\":\"${var.agent_payments}\",\"act\":{\"sub\":\"${var.agent_concierge}\"}}"
    }
    "client_id" = {
      source = { type = "CONTEXT" }
      value  = "ClientId"
    }
  }

  # The agent authenticates by client attestation (attest_jwt_client_auth_dpop), NOT the
  # client_secret: this criterion invokes the pf-oidf-modules validator, which verifies the
  # OAuth-Client-Attestation JWT + the DPoP cnf binding off the request. Without a valid,
  # attester-signed attestation the exchange is refused — the secret alone is not sufficient.
  issuance_criteria = {
    expression_criteria = [{
      error_result = "attestation_validation_failed"
      expression   = local.attestation_criterion
    }]
  }
}

resource "pingfederate_oauth_access_token_mapping" "te_account" {
  context = {
    type        = "TOKEN_EXCHANGE_PROCESSOR_POLICY"
    context_ref = { id = pingfederate_oauth_token_exchange_processor_policy.user_to_agent.policy_id }
  }
  access_token_manager_ref = { id = "attestJwtAcct" }

  attribute_contract_fulfillment = {
    "sub" = {
      source = { type = "TOKEN_EXCHANGE_PROCESSOR_POLICY" }
      value  = "subject"
    }
    "act" = {
      source = { type = "TEXT" }
      value  = "{\"sub\":\"${var.agent_account}\",\"act\":{\"sub\":\"${var.agent_concierge}\"}}"
    }
    "client_id" = {
      source = { type = "CONTEXT" }
      value  = "ClientId"
    }
  }

  # Attestation-based client auth (see te_payments) — validated on the exchange, not the secret.
  issuance_criteria = {
    expression_criteria = [{
      error_result = "attestation_validation_failed"
      expression   = local.attestation_criterion
    }]
  }
}

# NOTE: the concierge mapping (attestJwtATM) is intentionally NOT changed — the concierge is the
# ROOT of the chain (it exchanges Alice's login token, which has no act), so its act is always
# just {concierge}. Leaving it as the existing literal keeps the root case explicit.
