data "davinci_applications" "all" {
  environment_id = var.pingone_env_id
}
output "dv_apps" {
  value = { for a in data.davinci_applications.all.applications : a.name => a.id }
}
