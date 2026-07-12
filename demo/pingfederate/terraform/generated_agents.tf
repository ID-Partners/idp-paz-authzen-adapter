# __generated__ by Terraform
# Please review these resources and move them into your main configuration files.

# __generated__ by Terraform from "urn:agent:northwind-concierge:v1"
resource "pingfederate_oauth_client" "agent_concierge" {
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
  client_id                           = "urn:agent:northwind-concierge:v1"
  client_secret_retention_period      = null
  client_secret_retention_period_type = "SERVER_DEFAULT"
  default_access_token_manager_ref = {
    id = "attestJwtATM"
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
  name                                                                 = "Concierge Agent"
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
  restrict_to_default_access_token_manager             = true
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

# __generated__ by Terraform from "urn:agent:northwind-account:v1"
resource "pingfederate_oauth_client" "agent_account" {
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
  client_id                           = "urn:agent:northwind-account:v1"
  client_secret_retention_period      = null
  client_secret_retention_period_type = "SERVER_DEFAULT"
  default_access_token_manager_ref = {
    id = "attestJwtAcct"
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
  name                                                                 = "Account Agent"
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
  restrict_to_default_access_token_manager             = true
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
