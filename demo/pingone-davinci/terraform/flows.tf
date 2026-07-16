# The sign-up passkey flow: Ping's official "PingOne Passwordless Registration (Passkey)"
# (github.com/pingone-davinci/si-pinglibrary-content), patched with an Http
# createSuccessResponse terminal (claim p1UserId = the created user) so it completes the
# PingOne-invoked OIDC authorize instead of dead-ending on the success page.
# Source + patch script context: ../flows-src, ../flows.
#
# Connection ids: the library flow was authored against the BOOTSTRAP connection instances,
# whose ids are well-known and match this environment for every connector except "Node"
# (our instance is named Teleport with a different id) — the single remap below.
resource "davinci_flow" "passkey_registration" {
  environment_id = var.pingone_env_id
  flow_json      = file("${path.module}/../flows/passkey-registration.flow.json")

  connection_link {
    id                            = "3566e86a35c26e575396dcfb89a3dcc0" # Teleport (nodeConnector)
    name                          = "Teleport"
    replace_import_connection_id  = "e7eae662d2ca276e4c6f097fc36a3bb1" # source "Node" instance
  }
}

# DaVinci application + flow policy: what the PingOne signup app's flowPolicyAssignment
# points at (the assignment swap happens via the PingOne management API).
resource "davinci_application" "bank_signup" {
  environment_id = var.pingone_env_id
  name           = "Bank Signup (Passkey)"
  oauth {
    enabled = true
    values {
      enabled                       = true
      allowed_grants                = ["authorizationCode"]
      allowed_scopes                = ["openid", "profile"]
      enforce_signed_request_openid = false
      redirect_uris                 = ["https://auth.pingone.asia/${var.pingone_env_id}/rp/callback/openid_connect"]
    }
  }
}

resource "davinci_application_flow_policy" "bank_signup_registration" {
  environment_id = var.pingone_env_id
  application_id = davinci_application.bank_signup.id
  name           = "Bank Signup Passkey Registration"
  status         = "enabled"
  policy_flow {
    flow_id    = davinci_flow.passkey_registration.id
    version_id = -1
    weight     = 100
  }
}

output "signup_flow_policy_id" {
  description = "Assign this to the PingOne signup application via flowPolicyAssignments"
  value       = davinci_application_flow_policy.bank_signup_registration.id
}
