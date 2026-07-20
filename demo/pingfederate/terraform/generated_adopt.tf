# __generated__ by Terraform
# Please review these resources and move them into your main configuration files.

# __generated__ by Terraform from "urn:agent:northwind-payments:v1"
resource "pingfederate_oauth_client" "agent_payments" {
  allow_authentication_api_init                = false
  authorization_detail_types                   = []
  bypass_activation_code_confirmation_override = null
  bypass_approval_page                         = true
  ciba_delivery_mode                           = null
  ciba_notification_endpoint                   = null
  ciba_polling_interval                        = null
  ciba_request_object_signing_algorithm        = null
  ciba_require_signed_requests                 = null
  ciba_user_code_supported                     = null
  client_auth = {
    type = "NONE"
  }
  client_id                           = "urn:agent:northwind-payments:v1"
  client_secret_retention_period      = null
  client_secret_retention_period_type = "SERVER_DEFAULT"
  default_access_token_manager_ref = {
    id = "attestJwtPmts"
  }
  description                                                          = null
  device_flow_setting_type                                             = "SERVER_DEFAULT"
  device_polling_interval_override                                     = null
  enable_cookieless_authentication_api                                 = false
  enabled                                                              = true
  exclusive_scopes                                                     = []
  extended_parameters                                                  = null
  grant_types                                                          = ["TOKEN_EXCHANGE"]
  jwks_settings                                                        = null
  jwt_secured_authorization_response_mode_content_encryption_algorithm = null
  jwt_secured_authorization_response_mode_encryption_algorithm         = null
  jwt_secured_authorization_response_mode_signing_algorithm            = null
  lockout_max_malicious_actions                                        = null
  lockout_max_malicious_actions_type                                   = "SERVER_DEFAULT"
  logo_url                                                             = null
  name                                                                 = "Payments Agent"
  offline_access_require_consent_prompt                                = "SERVER_DEFAULT"
  oidc_policy = {
    back_channel_logout_uri                         = null
    grant_access_session_revocation_api             = false
    grant_access_session_session_management_api     = false
    id_token_content_encryption_algorithm           = null
    id_token_encryption_algorithm                   = null
    id_token_signing_algorithm                      = null
    logout_mode                                     = "NONE"
    logout_uris                                     = null
    pairwise_identifier_user_type                   = false
    ping_access_logout_capable                      = false
    policy_group                                    = null
    post_logout_redirect_uris                       = null
    sector_identifier_uri                           = null
    user_info_response_content_encryption_algorithm = null
    user_info_response_encryption_algorithm         = null
    user_info_response_signing_algorithm            = null
  }
  pending_authorization_timeout_override               = null
  persistent_grant_expiration_type                     = "SERVER_DEFAULT"
  persistent_grant_idle_timeout                        = 0
  persistent_grant_idle_timeout_time_unit              = "DAYS"
  persistent_grant_idle_timeout_type                   = "SERVER_DEFAULT"
  persistent_grant_reuse_grant_types                   = []
  persistent_grant_reuse_type                          = "SERVER_DEFAULT"
  redirect_uris                                        = []
  refresh_rolling                                      = "SERVER_DEFAULT"
  refresh_token_rolling_grace_period                   = null
  refresh_token_rolling_grace_period_type              = "SERVER_DEFAULT"
  refresh_token_rolling_interval                       = null
  refresh_token_rolling_interval_type                  = "SERVER_DEFAULT"
  request_object_signing_algorithm                     = null
  request_policy_ref                                   = null
  require_dpop                                         = false
  require_jwt_secured_authorization_response_mode      = false
  require_offline_access_scope_to_issue_refresh_tokens = "SERVER_DEFAULT"
  require_proof_key_for_code_exchange                  = false
  require_pushed_authorization_requests                = false
  require_signed_requests                              = false
  restrict_scopes                                      = false
  restrict_to_default_access_token_manager             = false # allow the audience-selected events (flatten) ATM
  restricted_response_types                            = []
  restricted_scopes                                    = []
  token_exchange_processor_policy_ref = {
    id = "userToAgentTE"
  }
  token_introspection_content_encryption_algorithm = null
  token_introspection_encryption_algorithm         = null
  token_introspection_signing_algorithm            = null
  user_authorization_url_override                  = null
  validate_using_all_eligible_atms                 = false
}

# __generated__ by Terraform from "attestJwtAcct"
resource "pingfederate_oauth_access_token_manager" "attest_jwt_acct" {
  access_control_settings = {
    allowed_clients = [
    ]
    restrict_clients = false
  }
  attribute_contract = {
    default_subject_attribute = null
    extended_attributes = [
      {
        multi_valued = false
        name         = "act"
      },
      {
        multi_valued = false
        name         = "client_id"
      },
      {
        multi_valued = false
        name         = "sub"
      },
    ]
  }
  configuration = {
    fields = [
      {
        name  = "Access Grant GUID Claim Name"
        value = "agid"
      },
      {
        name  = "Active Signing Certificate Key ID"
        value = ""
      },
      {
        name  = "Active Symmetric Encryption Key ID"
        value = ""
      },
      {
        name  = "Active Symmetric Key ID"
        value = ""
      },
      {
        name  = "Asymmetric Encryption JWKS URL"
        value = ""
      },
      {
        name  = "Asymmetric Encryption Key"
        value = ""
      },
      {
        name  = "Audience Claim Value"
        value = "https://api.northwind.example/bank" # RFC 8707: tokens minted for the bank RS
      },
      {
        name  = "Authorization Details Claim Name"
        value = "authorization_details"
      },
      {
        name  = "Client ID Claim Name"
        value = "client_id"
      },
      {
        name  = "Default JWKS URL Cache Duration"
        value = "720"
      },
      {
        name  = "Enable Token Revocation"
        value = "false"
      },
      {
        name  = "Expand Scope Groups"
        value = "false"
      },
      {
        name  = "Include Issued At Claim"
        value = "true"
      },
      {
        name  = "Include JWE Key ID Header Parameter"
        value = "true"
      },
      {
        name  = "Include JWE X.509 Thumbprint Header Parameter"
        value = "false"
      },
      {
        name  = "Include Key ID Header Parameter"
        value = "true"
      },
      {
        name  = "Include X.509 Thumbprint Header Parameter"
        value = "false"
      },
      {
        name  = "Issuer Claim Value"
        value = var.pf_issuer # RFC 9068 iss; same var as subjectJwtProc's Issuer so delegated tokens stay valid flatten-exchange subjects
      },
      {
        name  = "JWE Algorithm"
        value = ""
      },
      {
        name  = "JWE Content Encryption Algorithm"
        value = ""
      },
      {
        name  = "JWKS Endpoint Cache Duration"
        value = "720"
      },
      {
        name  = "JWKS Endpoint Path"
        value = ""
      },
      {
        name  = "JWS Algorithm"
        value = "RS256"
      },
      {
        name  = "JWT ID Claim Length"
        value = "22"
      },
      {
        name  = "Not Before Claim Offset"
        value = ""
      },
      {
        name  = "Publish Key ID X.509 URL"
        value = "false"
      },
      {
        name  = "Publish Keys to the PingFederate JWKS Endpoint"
        value = "false"
      },
      {
        name  = "Publish Thumbprint X.509 URL"
        value = "false"
      },
      {
        name  = "Scope Claim Name"
        value = "scope"
      },
      {
        name  = "Space Delimit Scope Values"
        value = "true"
      },
      {
        name  = "Token Lifetime"
        value = "720"
      },
      {
        name  = "Type Header Value"
        value = "at+jwt"
      },
      {
        name  = "Use Centralized Signing Key"
        value = "true"
      },
    ]
    sensitive_fields = [
    ]
    tables = [
      {
        name = "Symmetric Keys"
        rows = null
      },
      {
        name = "Certificates"
        rows = null
      },
    ]
  }
  manager_id = "attestJwtAcct"
  name       = "Attestation JWT ATM (Account)"
  parent_ref = null
  plugin_descriptor_ref = {
    id = "com.pingidentity.pf.access.token.management.plugins.JwtBearerAccessTokenManagementPlugin"
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
    attributes = [
    ]
  }
}

# __generated__ by Terraform from "attestJwtPmts"
resource "pingfederate_oauth_access_token_manager" "attest_jwt_pmts" {
  access_control_settings = {
    allowed_clients = [
    ]
    restrict_clients = false
  }
  attribute_contract = {
    default_subject_attribute = null
    extended_attributes = [
      {
        multi_valued = false
        name         = "act"
      },
      {
        multi_valued = false
        name         = "client_id"
      },
      {
        multi_valued = false
        name         = "sub"
      },
    ]
  }
  configuration = {
    fields = [
      {
        name  = "Access Grant GUID Claim Name"
        value = "agid"
      },
      {
        name  = "Active Signing Certificate Key ID"
        value = ""
      },
      {
        name  = "Active Symmetric Encryption Key ID"
        value = ""
      },
      {
        name  = "Active Symmetric Key ID"
        value = ""
      },
      {
        name  = "Asymmetric Encryption JWKS URL"
        value = ""
      },
      {
        name  = "Asymmetric Encryption Key"
        value = ""
      },
      {
        name  = "Audience Claim Value"
        value = "https://api.northwind.example/bank" # RFC 8707: tokens minted for the bank RS
      },
      {
        name  = "Authorization Details Claim Name"
        value = "authorization_details"
      },
      {
        name  = "Client ID Claim Name"
        value = "client_id"
      },
      {
        name  = "Default JWKS URL Cache Duration"
        value = "720"
      },
      {
        name  = "Enable Token Revocation"
        value = "false"
      },
      {
        name  = "Expand Scope Groups"
        value = "false"
      },
      {
        name  = "Include Issued At Claim"
        value = "true"
      },
      {
        name  = "Include JWE Key ID Header Parameter"
        value = "true"
      },
      {
        name  = "Include JWE X.509 Thumbprint Header Parameter"
        value = "false"
      },
      {
        name  = "Include Key ID Header Parameter"
        value = "true"
      },
      {
        name  = "Include X.509 Thumbprint Header Parameter"
        value = "false"
      },
      {
        name  = "Issuer Claim Value"
        value = var.pf_issuer # RFC 9068 iss; same var as subjectJwtProc's Issuer so delegated tokens stay valid flatten-exchange subjects
      },
      {
        name  = "JWE Algorithm"
        value = ""
      },
      {
        name  = "JWE Content Encryption Algorithm"
        value = ""
      },
      {
        name  = "JWKS Endpoint Cache Duration"
        value = "720"
      },
      {
        name  = "JWKS Endpoint Path"
        value = ""
      },
      {
        name  = "JWS Algorithm"
        value = "RS256"
      },
      {
        name  = "JWT ID Claim Length"
        value = "22"
      },
      {
        name  = "Not Before Claim Offset"
        value = ""
      },
      {
        name  = "Publish Key ID X.509 URL"
        value = "false"
      },
      {
        name  = "Publish Keys to the PingFederate JWKS Endpoint"
        value = "false"
      },
      {
        name  = "Publish Thumbprint X.509 URL"
        value = "false"
      },
      {
        name  = "Scope Claim Name"
        value = "scope"
      },
      {
        name  = "Space Delimit Scope Values"
        value = "true"
      },
      {
        name  = "Token Lifetime"
        value = "720"
      },
      {
        name  = "Type Header Value"
        value = "at+jwt"
      },
      {
        name  = "Use Centralized Signing Key"
        value = "true"
      },
    ]
    sensitive_fields = [
    ]
    tables = [
      {
        name = "Symmetric Keys"
        rows = null
      },
      {
        name = "Certificates"
        rows = null
      },
    ]
  }
  manager_id = "attestJwtPmts"
  name       = "Attestation JWT ATM (Payments)"
  parent_ref = null
  plugin_descriptor_ref = {
    id = "com.pingidentity.pf.access.token.management.plugins.JwtBearerAccessTokenManagementPlugin"
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
    attributes = [
    ]
  }
}
