
output "ts_project_id" {
  value = module.setup.ts_project_id
}
output "ts_project_number" {
  value = module.setup.ts_project_number
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

output "ts_instance_id" {
  value = module.deploy.instance_id
}

output "ts_image_hash" {
  value = module.build.ts_image_hash
}