# ── Entra bridge clients, Option B (private_key_jwt, federation-native) ─────────
# Alongside entra-agents.tf's attestation-based clients (attest_jwt_client_auth_dpop +
# ClientAttestationUtils), this is the SIMPLER federated-client archetype: standard RFC 7523
# private_key_jwt client authentication — PF verifies the client_assertion's signature natively
# against the registered JWKS, same as any other private_key_jwt client (see ciba.tf's
# agent_autonomous for the proven pattern) — plus an issuance criterion that ADDITIONALLY
# requires the client_assertion to carry a trust_chain header proving OpenID Federation
# membership (OIDFederationUtils.validateTrustChain, walking authority_hints up to the same
# trust anchor Option A uses). No DPoP proof-of-possession, no workload/upstream claims riding
# along — the tradeoff against Option A's richer, higher-assurance attestation.
#
# A separate token-exchange-processor-policy + access-token-mapping is needed (not a reuse of
# entra-agents.tf's te_entra) because issuance_criteria lives on the mapping, which is resolved
# by policy context — reusing entra_user_to_agent would put THIS client under the attestation
# criterion too. The subject-token side is identical (same entraSubjectJwtProc processor); only
# the CLIENT side differs.

resource "pingfederate_oauth_token_exchange_processor_policy" "entra_user_to_agent_pkjwt" {
  policy_id            = "entraUserToAgentPkjwtTE"
  name                 = "Entra User-to-Agent Token Exchange (private_key_jwt)"
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

resource "pingfederate_oauth_access_token_mapping" "te_entra_pkjwt" {
  context = {
    type        = "TOKEN_EXCHANGE_PROCESSOR_POLICY"
    context_ref = { id = pingfederate_oauth_token_exchange_processor_policy.entra_user_to_agent_pkjwt.policy_id }
  }
  access_token_manager_ref = { id = pingfederate_oauth_access_token_manager.attest_jwt_entra.manager_id }

  attribute_contract_fulfillment = {
    "sub" = {
      source = { type = "TOKEN_EXCHANGE_PROCESSOR_POLICY" }
      value  = "subject"
    }
    "act" = {
      source = { type = "EXPRESSION" }
      value  = "\"{\\\"sub\\\":\\\"\" + #this.get(\"context.ClientId\") + \"\\\"}\""
    }
    "client_id" = {
      source = { type = "CONTEXT" }
      value  = "ClientId"
    }
  }

  issuance_criteria = {
    expression_criteria = [{
      error_result = "trust_chain_validation_failed"
      expression   = local.federation_trust_chain_criterion
    }]
  }
}

locals {
  federation_trust_chain_criterion = "@${var.oidf_federation_utils_class}@validateTrustChain(#this)"
}

variable "entra_gateway_pkjwt_client" {
  description = "The Northwind gateway agent's Option B (private_key_jwt) PF client — parallel to entra_gateway_client, not a replacement."
  type        = string
  default     = "urn:agent:entra-gateway-pkjwt:v1"
}

# Public JWKS for the client above — the PRIVATE half is bridge-custodied (a NEW, dedicated
# federation-client key, distinct from the attestation entity keys: this archetype and the
# attested one should not share key material even for the same logical gateway).
resource "pingfederate_oauth_client" "entra_gateway_pkjwt" {
  client_id = var.entra_gateway_pkjwt_client
  name      = "Entra Gateway Agent, private_key_jwt (Northwind bridge)"
  enabled   = true

  grant_types = ["TOKEN_EXCHANGE"]

  client_auth = {
    type                      = "PRIVATE_KEY_JWT"
    enforce_replay_prevention = false
  }
  jwks_settings = {
    jwks = jsonencode({
      keys = [{
        kty = "EC", crv = "P-256", use = "sig", alg = "ES256",
        kid = "tSaDUktvVgDloD8jmOdPOFV4MgaRvZ8JLH9_XAM1kYc",
        x   = "G1fBgonzhgwDSU-53t2OyWCZecodBXSzCMFitPM99BE",
        y   = "UHAwN7QYSkPlvmcjKnczKmEQc-X7X3cxAxbvzt0t4ZQ",
      }]
    })
  }

  default_access_token_manager_ref = {
    id = pingfederate_oauth_access_token_manager.attest_jwt_entra.manager_id
  }
  restrict_to_default_access_token_manager = true
  bypass_approval_page                     = true

  token_exchange_processor_policy_ref = {
    id = pingfederate_oauth_token_exchange_processor_policy.entra_user_to_agent_pkjwt.policy_id
  }
}
