# ─────────────────────────────────────────────────────────────────────────────
# Grant Management API token (Option B): a token AUDIENCED for the GM API.
#
# The GM API servlet (gm-api.war) verifies the presented token's `aud` == its
# configured audience (https://gm-api.demo/grants) and then checks token.sub ==
# grant.subject and token.client_id == grant.clientId. The shared login token
# (userJwtATM) already satisfies sub/client_id/scope/agid but carries NO aud, so
# the servlet rejects it (invalid_token).
#
# Rather than weaken the servlet's audience check or mutate the shared login token,
# we mint a SECOND token from the SAME login grant, re-audienced for the GM API,
# via an RFC 8707 resource indicator. The BFF (client northwind-webapp) requests
# resource=https://gm-api.demo/grants on its broker exchange (signupTE); PF selects
# gmJwtATM by that resource URI and issues a token with:
#   aud       = https://gm-api.demo/grants   (Audience Claim Value below)
#   sub       = the user                     (mapping: subject)
#   client_id = northwind-webapp             (mapping: CONTEXT ClientId)
#   agid      = the grant GUID               (Access Grant GUID Claim Name)
#   scope     = ...grant_management_evaluate (from the granted scopes)
# ─────────────────────────────────────────────────────────────────────────────

resource "pingfederate_oauth_access_token_manager" "gm_jwt" {
  access_control_settings = {
    allowed_clients  = []
    restrict_clients = false
  }
  attribute_contract = {
    default_subject_attribute = null
    # The servlet reads sub + client_id from the token; agid + scope come from the
    # built-in claim mappings below, not the contract. No `act`: this is the user's
    # own re-audienced token, not a delegated one.
    extended_attributes = [
      { multi_valued = false, name = "sub" },
      { multi_valued = false, name = "client_id" },
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
      { name = "Audience Claim Value", value = "https://gm-api.demo/grants" }, # the aud the GM servlet requires
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
  manager_id = "gmJwtATM"
  name       = "Grant Management API JWT ATM"
  parent_ref = null
  plugin_descriptor_ref = {
    id = "com.pingidentity.pf.access.token.management.plugins.JwtBearerAccessTokenManagementPlugin"
  }
  # RFC 8707: this ATM is selected ONLY when the token request asks for this resource,
  # so normal logins keep minting from userJwtATM (unchanged).
  selection_settings = {
    resource_uris = ["https://gm-api.demo/grants"]
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

# Mapping: the SAME signup broker exchange (client=northwind-webapp), but when the GM
# resource is requested PF fulfils gmJwtATM's contract. sub = the human principal;
# client_id = the requesting client (northwind-webapp) so the servlet's grant.clientId
# check passes.
resource "pingfederate_oauth_access_token_mapping" "te_signup_gm" {
  context = {
    type        = "TOKEN_EXCHANGE_PROCESSOR_POLICY"
    context_ref = { id = pingfederate_oauth_token_exchange_processor_policy.signup.policy_id }
  }
  access_token_manager_ref = { id = pingfederate_oauth_access_token_manager.gm_jwt.manager_id }

  attribute_contract_fulfillment = {
    "sub" = {
      source = { type = "TOKEN_EXCHANGE_PROCESSOR_POLICY" }
      value  = "subject"
    }
    "client_id" = {
      source = { type = "CONTEXT" }
      value  = "ClientId"
    }
  }

  # Same audience pinning as te_signup: only passkey assertions minted FOR the signup
  # application may broker into a PF token.
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
