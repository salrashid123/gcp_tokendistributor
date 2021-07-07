

output "tc_project_id" {
  value = google_project.project.project_id
}

output "tc_project_number" {
  value = google_project.project.number
}

output "tc_service_account" {
  value = google_service_account.tokenclient.email
}

output "tc_address" {
  value = google_compute_address.tcip.address
}

output "tc_natip_address" {
  value = google_compute_address.natip.address
}

output "tc_vpnip_address" {
  value = google_compute_address.vpnip.address
}

output "tc_google_compute_vpn_gateway" {
  value = google_compute_vpn_gateway.target_gateway.name
}

output "gcr_id" {
  value = google_container_registry.registry.id
}

output "tc_network" {
  value = google_compute_network.tcnetwork.id
}

output "tc_subnet" {
  value = google_compute_subnetwork.tcsubnet.id
}