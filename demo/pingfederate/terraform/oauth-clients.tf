# OAuth clients — browser-facing (BFF) client for the Northwind web app.
#
# Declarative source for the northwind-webapp client that data.zip realises.
# The client was originally hand-built; the import block adopts the live one
# so `terraform plan` diffs against reality instead of recreating it.
#
# Per-environment redirect URIs: PF is SHARED by the production and staging
# Railway environments (staging reuses production PF via its public URL), so
# every environment's /callback must be whitelisted here.

import {
  to = pingfederate_oauth_client.northwind_webapp
  id = "northwind-webapp"
}

resource "pingfederate_oauth_client" "northwind_webapp" {
  client_id = "northwind-webapp"
  name      = "Northwind Web App (BFF)"
  enabled   = true

  # TOKEN_EXCHANGE: the BFF brokers PingOne sign-up ID tokens into PF user tokens via the
  # signupTE processor policy (see signup.tf) — RFC 8693, subject_token_type=id_token.
  grant_types = ["AUTHORIZATION_CODE", "TOKEN_EXCHANGE"]

  token_exchange_processor_policy_ref = {
    id = pingfederate_oauth_token_exchange_processor_policy.signup.policy_id
  }

  redirect_uris = [
    "https://northwind-app-production.up.railway.app/callback", # production
    "https://northwind-app-staging.up.railway.app/callback",    # staging (agentgateway variant)
    "http://localhost:8090/callback",                           # local compose
  ]

  require_proof_key_for_code_exchange = true

  # RFC 9396 RAR: the payment-consent authorization_details type
  authorization_detail_types = ["payment_initiation"]

  default_access_token_manager_ref = {
    id = "userJwtATM"
  }

  # Allow the BFF to select a NON-default ATM on a token exchange. Needed for the Recognize
  # first-factor token (recognizeUserAuthATM, see recognize-user-auth.tf), which is chosen by
  # resource = authentication-service. With the default (true) PF refuses any ATM other than
  # userJwtATM and the exchange fails `invalid_target`.
  # This only WIDENS what the BFF may ask for; every mapping still governs what it actually gets.
  restrict_to_default_access_token_manager = false

  oidc_policy = {
    id_token_signing_algorithm = "RS256"
    policy_group = {
      id = "userOidc"
    }
  }

  # Demo client secret, managed declaratively so the exported data.zip always
  # carries a WORKING secret (the snapshot's encrypted secret had drifted from
  # what the app sends → 401 invalid_client on staging). This is the same demo
  # value already public in demo/app/app.py's OIDC_CLIENT_SECRET default —
  # NOT a production credential. Write-only in the API (plan can't read it back).
  client_auth = {
    type   = "SECRET"
    secret = var.webapp_client_secret
  }
}
