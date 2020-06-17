
output "project_id" {
  value = module.setup.project_id
}
output "project_number" {
  value = module.setup.project_number
}

output "ts_service_account" {
  value = module.setup.ts_service_account
}

output "ts_address" {
  value = module.setup.ts_address
}

output "natip_address" {
  value = module.setup.natip_address
}

output "gcr_id" {
  value = module.setup.gcr_id
}

output "token_server_instance_id" {
  value = module.deploy.instance_id
}