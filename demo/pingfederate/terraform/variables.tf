# Admin-API connection. Values come from env (TF_VAR_pf_admin_*) — never commit secrets.
# For the Railway PF the admin API is on :9999; reach it via an admin TCP proxy or an ssh
# tunnel, then set pf_admin_host to that host:port.

variable "pf_admin_host" {
  description = "PingFederate admin API host, e.g. https://localhost:9999 (over an ssh tunnel) or the admin TCP-proxy host:port"
  type        = string
  default     = "https://localhost:9999"
}

variable "pf_admin_username" {
  description = "PingFederate admin username"
  type        = string
  default     = "administrator"
}

variable "pf_admin_password" {
  description = "PingFederate admin password (set via TF_VAR_pf_admin_password; never commit)"
  type        = string
  sensitive   = true
}

variable "pf_issuer" {
  description = "The runtime issuer the subject-token JWT processor validates against"
  type        = string
  default     = "https://pingfederate-production-cb0a.up.railway.app"
}

# The fixed agent identities in the demo topology. Only the CURRENT actor's id is a literal
# here (it legitimately IS this agent); the delegated chain underneath is DERIVED from the
# incoming token, not hard-coded.
variable "agent_concierge" {
  type    = string
  default = "urn:agent:northwind-concierge:v1"
}
variable "agent_payments" {
  type    = string
  default = "urn:agent:northwind-payments:v1"
}
variable "agent_account" {
  type    = string
  default = "urn:agent:northwind-account:v1"
}

variable "attestation_utils_class" {
  description = "Fully-qualified pf-oidf-modules class whose validateClientAttestation(#this) OGNL entry point authenticates the client by attestation (attest_jwt_client_auth_dpop) instead of a secret."
  type        = string
  default     = "com.pingidentity.ps.oidf.servlet.clientregistration.utils.ClientAttestationUtils"
}

variable "webapp_client_secret" {
  description = "northwind-webapp (BFF) client secret — demo value, same as demo/app/app.py's OIDC_CLIENT_SECRET default. Override with TF_VAR_webapp_client_secret for a real deployment."
  type        = string
  sensitive   = true
  default     = "webapp-secret-123"
}
