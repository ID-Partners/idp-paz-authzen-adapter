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

  grant_types = ["AUTHORIZATION_CODE"]

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

  oidc_policy = {
    id_token_signing_algorithm = "RS256"
    policy_group = {
      id = "userOidc"
    }
  }

  # The client secret is set out-of-band (it already exists on the imported
  # client); never commit it. client_auth.secret is write-only in the API, so
  # terraform can't read it back — leave the auth block to the live config.
}
