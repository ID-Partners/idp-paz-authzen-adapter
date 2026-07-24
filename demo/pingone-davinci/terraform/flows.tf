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

# The flow policy MUST live on the DaVinci application PINGONE PROVISIONED for its OIDC
# integration ("PingOne SSO Connection") — a policy on any other DaVinci app is not
# invocable from a PingOne authorize (UNEXPECTED_ERROR, verified empirically). The
# assignment swap on the PingOne side happens via the management API.
variable "pingone_sso_dv_app_id" {
  description = "DaVinci application 'PingOne SSO Connection' (PingOne-provisioned)"
  type        = string
  default     = "74e432a9f7c4aaa657332b1a10282b61"
}

# The AUTHENTICATION trigger (required for PingOne-invoked policies — without it the
# authorize endpoint 500s UNEXPECTED_ERROR) is READ-ONLY in both the provider and the
# PingOne API: only PingOne-provisioned policies carry it. So we ADOPT the provisioned
# "PingOne - Sign On and Registration" policy (import below) and point ITS flow at our
# passkey flow — trigger preserved, flow swapped, all still config-as-code.
import {
  to = davinci_application_flow_policy.bank_signup_registration
  id = "fe8ab8dc-0dbb-4da4-8ee5-004cb3a6f21d/74e432a9f7c4aaa657332b1a10282b61/5eccfe79c581a8890d07cb7a217b25bd"
}

resource "davinci_application_flow_policy" "bank_signup_registration" {
  environment_id = var.pingone_env_id
  application_id = var.pingone_sso_dv_app_id
  name           = "Bank Signup Passkey Registration"
  status         = "enabled"
  policy_flow {
    # The OOTB Passwordless main flow: authorize-integrated + no-device→enrol branch.
    # Policy CHANGED IN PLACE (same policyId) per davinci-pingone-integration invariant 1.
    flow_id    = davinci_flow.ootb_passwordless_main.id
    version_id = -1
    weight     = 100
  }
}

# THE FIX for the authorize 500: assign the DaVinci flow policy to the PingOne signup
# application via the PINGONE-NATIVE resource (not the davinci provider's assignment).
# This is the exact call the console's Application → Policies tab makes — it registers
# the policy with PingOne and stamps the trigger=AUTHENTICATION that the authorize
# endpoint requires. The davinci provider's own davinci_application_flow_policy leaves
# the PingOne-side trigger null → UNEXPECTED_ERROR at authorize.
variable "pingone_signup_app_id" {
  description = "PingOne application 'PF Bank Signup Federation' (the OIDC app the BFF drives)"
  type        = string
  default     = "0ce9dbdf-7d86-461a-b531-0a4afcb508d0"
}

resource "pingone_application_flow_policy_assignment" "bank_signup" {
  environment_id = var.pingone_env_id
  application_id = var.pingone_signup_app_id
  flow_policy_id = davinci_application_flow_policy.bank_signup_registration.id
  priority       = 1
}

output "signup_flow_policy_id" {
  value = davinci_application_flow_policy.bank_signup_registration.id
}

