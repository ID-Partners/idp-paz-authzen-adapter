# Company (global) variables the library passkey flow reads at runtime — the flow errors
# if they don't exist. Values: WebAuthn RP = the PingOne auth domain (the flow UI runs on
# auth.pingone.asia); population = the env default; deviceID /
# publicKeyCredentialCreationOptions are runtime scratch (flow writes them).
locals {
  dv_company_variables = {
    origin                             = { value = "https://auth.pingone.asia", desc = "WebAuthn origin (flow UI host)" }
    rpId                               = { value = "auth.pingone.asia", desc = "WebAuthn relying-party id" }
    relyingParty                       = { value = "ID Partners Bank", desc = "WebAuthn relying-party display name" }
    p1PopulationId                     = { value = "fbd0b138-43fe-4db6-a3c7-ff500da75e81", desc = "Population for created users" }
    populationId                       = { value = "fbd0b138-43fe-4db6-a3c7-ff500da75e81", desc = "Population for created users" }
    companyName                        = { value = "ID Partners Bank", desc = "Branding" }
    companyLogo                        = { value = "", desc = "Branding logo URL" }
    deviceID                           = { value = "", desc = "Runtime scratch (flow-written)" }
    publicKeyCredentialCreationOptions = { value = "", desc = "Runtime scratch (flow-written)" }
  }
}

resource "davinci_variable" "company" {
  for_each       = local.dv_company_variables
  environment_id = var.pingone_env_id
  context        = "company"
  name           = each.key
  description    = each.value.desc
  type           = "string"
  value          = each.value.value != "" ? each.value.value : null
  mutable        = true
}

# ── OOTB Passwordless template company variables (flow reads {{global.variables.*}}) ─────────
# Passkey-only posture: passwordless required, magic-link off, agreement off.
locals {
  ootb_company_variables = {
    ciam_passwordlessRequired          = { value = "true", desc = "Passwordless-only: never fall back to password" }
    ciam_magicLinkEnabled              = { value = "false", desc = "Magic-link authentication disabled" }
    registartionPopulationId           = { value = "fbd0b138-43fe-4db6-a3c7-ff500da75e81", desc = "Population for registrations (template's spelling)" }
    rpid                               = { value = "auth.pingone.asia", desc = "WebAuthn relying-party id" }
    ciam_recoveryValidationAttempts    = { value = "5", desc = "Recovery code attempt limit" }
    ciam_verificationValidationAttempts = { value = "5", desc = "Verification code attempt limit" }
    agreementId                        = { value = "", desc = "Agreement (ToS) id — unused, agreement disabled" }
    ciam_authMethod                    = { value = "", desc = "Runtime scratch (flow-written)" }
    ciam_deviceId                      = { value = "", desc = "Runtime scratch (flow-written)" }
    ciam_errorMessage                  = { value = "", desc = "Runtime scratch (flow-written)" }
  }
}

resource "davinci_variable" "ootb_company" {
  for_each       = local.ootb_company_variables
  environment_id = var.pingone_env_id
  context        = "company"
  name           = each.key
  description    = each.value.desc
  type           = "string"
  value          = each.value.value != "" ? each.value.value : null
  mutable        = true
}
