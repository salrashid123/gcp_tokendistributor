
output "tc_project_id" {
  value = module.setup.project_id
}
output "tc_project_number" {
  value = module.setup.project_number
}

output "tc_service_account" {
  value = module.setup.tc_service_account
}

output "tc_address" {
  value = module.setup.tc_address
}

output "natip_address" {
  value = module.setup.natip_address
}

output "gcr_id" {
  value = module.setup.gcr_id
}

output "tc_image_hash" {
  value = module.build.image_hash
}

output "tc_instance_id" {
  value = module.deploy.instance_id
}


# output "token_client_address" {
#   value = module.deploy.ip
# }