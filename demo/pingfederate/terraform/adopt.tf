# Adopt (import) the payments agent client + the two main agent ATMs so we can manage:
#  - payments client: restrict_to_default_access_token_manager = false (allow the events ATM)
#  - attestJwtPmts / attestJwtAcct: Audience Claim Value (RFC 8707 aud on issued tokens)
import {
  to = pingfederate_oauth_client.agent_payments
  id = "urn:agent:northwind-payments:v1"
}
# account + concierge agent clients: adopted so we can flip client_auth SECRET→NONE
# (attestation-only public clients — see generated_adopt.tf / the identity.py secret drop).
import {
  to = pingfederate_oauth_client.agent_account
  id = "urn:agent:northwind-account:v1"
}
import {
  to = pingfederate_oauth_client.agent_concierge
  id = "urn:agent:northwind-concierge:v1"
}
import {
  to = pingfederate_oauth_access_token_manager.attest_jwt_pmts
  id = "attestJwtPmts"
}
import {
  to = pingfederate_oauth_access_token_manager.attest_jwt_acct
  id = "attestJwtAcct"
}
