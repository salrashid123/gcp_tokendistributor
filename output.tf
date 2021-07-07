
output "ts_project_id" {
  value = module.ts_setup.ts_project_id
}

output "ts_project_number" {
  value = module.ts_setup.ts_project_number
}

output "ts_service_account" {
  value = module.ts_setup.ts_service_account
}

output "ts_external_address" {
  value = module.ts_deploy.ts_external_ip
}

output "ts_internal_address" {
  value = module.ts_deploy.ts_internal_ip
}

output "ts_image_hash" {
  value = module.ts_build.ts_image_hash
}

output "ts_instance_id" {
  value = module.ts_deploy.ts_instance_id
}

output "tc_project_id" {
  value = module.tc_setup.tc_project_id
}

output "tc_project_number" {
  value = module.tc_setup.tc_project_number
}

output "tc_service_account" {
  value = module.tc_setup.tc_service_account
}

output "tc_address" {
  value = module.tc_setup.tc_address
}

output "tc_image_hash" {
  value = module.tc_build.tc_image_hash
}

output "tc_instance_id" {
  value = module.tc_deploy.tc_instance_id
}


output "ts_vpnip_address" {
  value = module.ts_setup.ts_vpnip_address
}


output "ts_google_compute_vpn_gateway" {
  value = module.ts_setup.ts_google_compute_vpn_gateway
}


output "tc_vpnip_address" {
  value = module.tc_setup.tc_vpnip_address
}


output "tc_external_address" {
  value = module.tc_deploy.tc_external_ip
}

output "tc_internal_address" {
  value = module.tc_deploy.tc_internal_ip
}


