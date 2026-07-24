# ── OOTB Passwordless composition: Registration + Authentication + Account Recovery ──────────
#
# Base = Ping's own "OOTB - Passwordless" template export (user-supplied, in
# ../flows-src/ootb-passwordless/, split per flow, http/node connection ids remapped to this
# company; Challenge + String Manipulation connections created with matching seed ids).
#
# WHY this template: it is AUTHORIZE-INTEGRATED (pingOneAuthenticationConnector
# returnSuccessResponseRedirect — see references/composition-authorize-handoff.md) AND has the
# no-device→ENROL branch built in (readAllDevices → Device Registration subflow with FIDO2
# createDevice/activateDevice) — the exact NO_USABLE_DEVICES fix. Import order per the subflow
# reference graph: leaves first, then account-registration + device-authentication, then main.

locals {
  ootb_dir = "${path.module}/../flows-src/ootb-passwordless"
  # old (source-export) subflow flowIds → resource, for subflow_link remapping
  ootb_old = {
    agreement     = "8ac0f56a85a8e7fcb563cee016145d4b"
    magic_link    = "7943151e8f1cd5792dfb83f541fea7e7"
    change_pwd    = "55a47f44fb54b0a12e8af96998d4f19d"
    account_reg   = "ff3d6d3443c607e4d7c8793de5354f26"
    account_rec   = "9ae4b6eaaba0b79a32a919bb7e988172"
    verify_email  = "5585937245e208fe051ed6da659ae334"
    device_reg    = "c727d7065c5bb6a553de72ea4082e96f"
    device_auth   = "1a5c86c06e8b16955fd3a60a5da9c506"
  }
}

# ── Leaf subflows (no subflow references of their own) ────────────────────────────────────────
resource "davinci_flow" "ootb_agreement" {
  environment_id = var.pingone_env_id
  flow_json      = file("${local.ootb_dir}/ootb-agreement-tos-subflow.json")
}
resource "davinci_flow" "ootb_magic_link" {
  environment_id = var.pingone_env_id
  flow_json      = file("${local.ootb_dir}/ootb-magic-link-authentication-subflow.json")
}
resource "davinci_flow" "ootb_change_password" {
  environment_id = var.pingone_env_id
  flow_json      = file("${local.ootb_dir}/ootb-change-password-subflow.json")
}
resource "davinci_flow" "ootb_account_recovery" {
  environment_id = var.pingone_env_id
  flow_json      = file("${local.ootb_dir}/ootb-account-recovery-subflow.json")
}
resource "davinci_flow" "ootb_verify_email" {
  environment_id = var.pingone_env_id
  flow_json      = file("${local.ootb_dir}/ootb-verify-email-subflow.json")
}
resource "davinci_flow" "ootb_device_registration" {
  environment_id = var.pingone_env_id
  flow_json      = file("${local.ootb_dir}/ootb-device-registration-subflow.json")
}

# ── Mid-tier subflows (reference the leaves) ─────────────────────────────────────────────────
resource "davinci_flow" "ootb_device_authentication" {
  environment_id = var.pingone_env_id
  flow_json      = file("${local.ootb_dir}/ootb-device-authentication-subflow.json")

  subflow_link {
    id                        = davinci_flow.ootb_magic_link.id
    name                      = "OOTB - Magic Link Authentication - Subflow"
    replace_import_subflow_id = local.ootb_old.magic_link
  }
}

resource "davinci_flow" "ootb_account_registration" {
  environment_id = var.pingone_env_id
  flow_json      = file("${local.ootb_dir}/ootb-account-registration-subflow.json")

  subflow_link {
    id                        = davinci_flow.ootb_agreement.id
    name                      = "OOTB - Agreement (ToS) - Subflow"
    replace_import_subflow_id = local.ootb_old.agreement
  }
  subflow_link {
    id                        = davinci_flow.ootb_verify_email.id
    name                      = "OOTB - Verify Email - Subflow"
    replace_import_subflow_id = local.ootb_old.verify_email
  }
  subflow_link {
    id                        = davinci_flow.ootb_device_registration.id
    name                      = "OOTB - Device Registration - Subflow"
    replace_import_subflow_id = local.ootb_old.device_reg
  }
}

# ── Main flow ────────────────────────────────────────────────────────────────────────────────
resource "davinci_flow" "ootb_passwordless_main" {
  environment_id = var.pingone_env_id
  flow_json      = file("${local.ootb_dir}/ootb-passwordless-registration-authentication-account-recovery-main-flow.json")

  subflow_link {
    id                        = davinci_flow.ootb_agreement.id
    name                      = "OOTB - Agreement (ToS) - Subflow"
    replace_import_subflow_id = local.ootb_old.agreement
  }
  subflow_link {
    id                        = davinci_flow.ootb_verify_email.id
    name                      = "OOTB - Verify Email - Subflow"
    replace_import_subflow_id = local.ootb_old.verify_email
  }
  subflow_link {
    id                        = davinci_flow.ootb_account_recovery.id
    name                      = "OOTB - Account Recovery - Subflow"
    replace_import_subflow_id = local.ootb_old.account_rec
  }
  subflow_link {
    id                        = davinci_flow.ootb_change_password.id
    name                      = "OOTB - Change Password - Subflow"
    replace_import_subflow_id = local.ootb_old.change_pwd
  }
  subflow_link {
    id                        = davinci_flow.ootb_account_registration.id
    name                      = "OOTB - Account Registration - Subflow"
    replace_import_subflow_id = local.ootb_old.account_reg
  }
  subflow_link {
    id                        = davinci_flow.ootb_device_authentication.id
    name                      = "OOTB - Device Authentication - Subflow"
    replace_import_subflow_id = local.ootb_old.device_auth
  }
}

output "ootb_main_flow_id" {
  value = davinci_flow.ootb_passwordless_main.id
}
