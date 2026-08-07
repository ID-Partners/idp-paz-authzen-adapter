# ─────────────────────────────────────────────────────────────────────────────
# OAuth authorization-server settings — declarative source for the COMMON SCOPES.
#
# Why this file exists: the BFF requests
#   openid banking:accounts:list banking:accounts:originate grant_management_evaluate
# (demo/app/app.py, DEFAULT_SCOPES) but PF only knew the first three, so every token
# request failed `invalid_scope` and the app fell back to has_token=false — which the
# dashboard reads as "not signed in". The grant-evaluation feature (gm-token.tf, and the
# agent's "what may I do?" call) shipped in the app before its scope existed in PF.
#
# `grant_management_evaluate` is a PLAIN COMMON SCOPE here, deliberately: this demo does
# not use PF's native OAuth grant management (`scope_for_oauth_grant_management` and
# `atm_id_for_oauth_grant_management` are both empty, as they are on the live server) —
# the Grant Management API is our own servlet (gm-api.war), and the scope is just the
# marker it checks. Do not "fix" this by pointing PF's native GM settings at it.
#
# CAUTION — this resource is a SINGLETON covering the WHOLE AS config, so every value
# below must mirror the live server or applying it will silently reset what it omits.
# The values here were read out of the deploy artifact (`../data.zip`,
# oauth-authz-server-settings.xml + config-store/oauth-scope-policy.xml) rather than
# guessed, so the intended diff is exactly one added scope. Before the first apply, run
#   terraform plan -generate-config-out=generated-oss.tf
# and diff it against this block; reconcile any drift BEFORE `terraform apply`.
# ─────────────────────────────────────────────────────────────────────────────

import {
  to = pingfederate_oauth_server_settings.oauth_server_settings
  id = "oauth_server_settings" # singleton — the id is a placeholder, per the provider docs
}

resource "pingfederate_oauth_server_settings" "oauth_server_settings" {
  # --- required ---
  authorization_code_entropy = 30 # authzCodeLength
  authorization_code_timeout = 60 # authzCodeTimeout (seconds)
  refresh_rolling_interval   = 0  # rollingInterval
  refresh_token_length       = 42 # refreshTokenLength

  # --- common scopes: the one functional change in this file ---
  default_scope_description = "Default access"
  scopes = [
    {
      name        = "banking:accounts:list"
      description = "List accounts and balances"
      dynamic     = false
    },
    {
      name        = "banking:payments:transfer"
      description = "Transfer funds between accounts"
      dynamic     = false
    },
    {
      name        = "banking:accounts:originate"
      description = "Open (originate) a new account"
      dynamic     = false
    },
    {
      # ADDED: lets the BFF/agent ask the AS what a grant permits (RFC 9396 grant
      # evaluation + entitlement search). Consumed by gm-api.war, not by PF itself.
      name        = "grant_management_evaluate"
      description = "Evaluate what an existing grant permits"
      dynamic     = false
    },
  ]
  exclusive_scopes = []

  # --- everything below mirrors the live server; present so the singleton is not reset ---
  activation_code_check_mode                              = "AFTER_AUTHENTICATION"
  allow_unidentified_client_extension_grants              = false
  allow_unidentified_client_ro_creds                      = false
  atm_id_for_oauth_grant_management                       = ""
  bypass_activation_code_confirmation                     = false
  bypass_authorization_for_approved_consents              = false
  client_secret_retention_period                          = 0
  consent_lifetime_days                                   = -1
  device_polling_interval                                 = 5
  disallow_plain_pkce                                     = false # restrictPlainPKCE
  dpop_proof_enforce_replay_prevention                    = false
  dpop_proof_lifetime_seconds                             = 120
  dpop_proof_require_nonce                                = false
  enable_cookieless_user_authorization_authentication_api = false
  include_issuer_in_authorization_response                = false
  jwt_secured_authorization_response_mode_lifetime        = 600
  offline_access_require_consent_prompt                   = false
  par_reference_length                                    = 24
  par_reference_timeout                                   = 60
  par_status                                              = "ENABLED"
  pending_authorization_timeout                           = 600
  persistent_grant_idle_timeout                           = 30
  persistent_grant_idle_timeout_time_unit                 = "DAYS"
  persistent_grant_lifetime                               = -1
  persistent_grant_lifetime_unit                          = "DAYS"
  refresh_rolling_interval_time_unit                      = "HOURS"
  refresh_token_rolling_grace_period                      = 60
  require_offline_access_scope_to_issue_refresh_tokens    = false
  return_id_token_on_open_id_with_device_authz_grant      = true
  roll_refresh_token_values                               = false
  scope_for_oauth_grant_management                        = ""
  token_endpoint_base_url                                 = ""
  user_authorization_consent_page_setting                 = "INTERNAL" # authzConsentSetting
  user_authorization_url                                  = ""
}
