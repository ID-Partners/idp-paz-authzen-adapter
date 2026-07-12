# PingFederate config-as-code for the agentic-banking demo's token-exchange plane.
#
# This module is the DECLARATIVE SOURCE for the RFC 8693 act-chain behaviour. Because the
# Railway PingFederate is ephemeral (config loads from data.zip at boot), Terraform is used to
# AUTHOR the config against a PF, and the realised config is then exported back into
# `../data.zip` (the deploy artifact). See README.md for the apply → export → commit flow.
#
# What it changes vs the baked config:
#   - the `act` claim on each agent's exchanged token is DERIVED from the incoming token's act
#     (wrap {this-agent, act={…incoming…}}) instead of a per-agent hard-coded literal.

provider "pingfederate" {
  https_host                          = var.pf_admin_host
  admin_api_path                      = "/pf-admin-api/v1"
  username                            = var.pf_admin_username
  password                            = var.pf_admin_password
  insecure_trust_all_tls              = true # demo PF serves a self-signed cert
  x_bypass_external_validation_header = true # don't run PF's connection-validation probes on apply
}
