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
  # THE act RULE — one expression, every agent, no demo topology encoded anywhere.
  # Wrap WHATEVER act arrived on the subject token under this agent:
  #     act = { sub: <this agent>, act: <incoming act verbatim> }
  # and when no act arrived (the root exchange) collapse to  act = { sub: <this agent> }.
  # This is RFC 8693 §4.1 actor nesting: the chain is whatever the caller presents, not a
  # shape this deployment assumes. Adding a hop needs NO PingFederate change.
  act_expression = { for id in [var.agent_payments, var.agent_account, var.agent_concierge] : id =>
    "\"{\\\"sub\\\":\\\"${id}\\\"\" + (#this.get(\"act\") == null ? \"\" : \",\\\"act\\\":\" + #this.get(\"act\").getValue()) + \"}\""
  }

  # Attestation-based client authentication: the pf-oidf-modules OGNL entry point that reads the
  # OAuth-Client-Attestation + DPoP headers off the request and verifies the attester-signed
  # attestation JWT + cnf binding. Placed as a token-issuance criterion so the exchange is refused
  # unless a valid attestation is presented — this is what lets us drop the client_secret.
  attestation_criterion = "@${var.attestation_utils_class}@validateClientAttestation(#this)"
}

# ── PREREQUISITE for the act derivation below ────────────────────────────────────────────────
# The mappings use source = EXPRESSION, which means PingFederate must EVALUATE OGNL at token
# issuance. PF ships with expression evaluation OFF by default (it is a code-execution surface),
# so a mapping that uses it will fail on a server where nobody turned it on.
#
# Declaring it here makes the config SELF-CONTAINED: rebuild PF from this terraform alone and the
# act derivation works. Previously this was an undeclared dependency — the .tf asserted a mapping
# that silently assumed a server-level setting it never mentioned, which is the same class of
# hidden assumption as the hardcoded act chain it replaces.
resource "pingfederate_config_store" "enable_ognl_expressions" {
  bundle       = "org.sourceid.common.expression.ExpressionManager"
  setting_id   = "evaluateExpressions"
  string_value = "true"
}

resource "pingfederate_oauth_access_token_mapping" "te_payments" {
  context = {
    type        = "TOKEN_EXCHANGE_PROCESSOR_POLICY"
    context_ref = { id = pingfederate_oauth_token_exchange_processor_policy.user_to_agent.policy_id }
  }
  access_token_manager_ref = { id = "attestJwtPmts" }
  depends_on               = [pingfederate_config_store.enable_ognl_expressions]

  attribute_contract_fulfillment = {
    "sub" = {
      source = { type = "TOKEN_EXCHANGE_PROCESSOR_POLICY" }
      value  = "subject" # sub = the human principal (Alice), unchanged
    }
    "act" = {
      # Derived, never assumed: nests the INCOMING act under this agent. sub stays the human
      # principal; act records the full actor chain as presented.
      source = { type = "EXPRESSION" }
      value  = local.act_expression[var.agent_payments]
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
  depends_on               = [pingfederate_config_store.enable_ognl_expressions]

  attribute_contract_fulfillment = {
    "sub" = {
      source = { type = "TOKEN_EXCHANGE_PROCESSOR_POLICY" }
      value  = "subject"
    }
    "act" = {
      source = { type = "EXPRESSION" }
      value  = local.act_expression[var.agent_account]
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

# NOTE: the concierge is TODAY the root (it exchanges a login token carrying no act), so the same
# expression collapses to {sub: concierge}. It is deliberately NOT special-cased: if a deeper chain
# ever reaches the concierge, it nests correctly with no config change. Encoding "the root has no
# act" would be exactly the hardcoded topology this file is meant to avoid.
