# PingOne DaVinci config-as-code for the sign-up passkey experience.
#
# Flows are AUTHORED here (exported flow JSON in ./flows, managed by davinci_flow) and the
# PingOne signup application runs them via a flow policy — same ethos as the PF terraform:
# git is the source of truth, the console is never hand-edited.
#
# Auth: the provider signs in AS A PINGONE USER (worker tokens are not accepted by the
# DaVinci API). The dedicated service user is `dv-admin` (DaVinci Admin + Environment Admin
# + Identity Data Admin, environment-scoped), created via the management API. Credentials
# come from the environment ONLY (never committed):
#
#   export PINGONE_USERNAME=dv-admin
#   export PINGONE_PASSWORD=…            # scratchpad/dv-admin-password.txt
#   export PINGONE_ENVIRONMENT_ID=fe8ab8dc-0dbb-4da4-8ee5-004cb3a6f21d
#   export PINGONE_REGION=AsiaPacific
provider "davinci" {
  # All connection settings come from the PINGONE_* environment variables.
}

# Auth smoke test + connector inventory: lists the environment's DaVinci connections
# (PingOne, PingOne MFA, Http, Functions, …) whose ids the flow JSON references.
data "davinci_connections" "all" {
  environment_id = var.pingone_env_id
}

variable "pingone_env_id" {
  description = "PingOne environment id (P1AS)"
  type        = string
  default     = "fe8ab8dc-0dbb-4da4-8ee5-004cb3a6f21d"
}

output "connections" {
  description = "DaVinci connections available to flows (name → {id, connector})"
  value = { for c in data.davinci_connections.all.connections :
            c.name => { id = c.id, connector = c.connector_id } }
}
