

output "ts_project_id" {
  value = google_project.project.project_id
}

output "ts_project_number" {
  value = google_project.project.number
}

output "ts_service_account" {
  value = google_service_account.tokenserver.email
}

output "ts_address" {
  value = google_compute_address.tsip.address
}

output "ts_natip_address" {
  value = google_compute_address.natip.address
}

output "ts_vpnip_address" {
  value = google_compute_address.vpnip.address
}

output "ts_google_compute_vpn_gateway" {
  value = google_compute_vpn_gateway.target_gateway.name
}

output "gcr_id" {
  value = google_container_registry.registry.id
}

output "ts_network" {
  value = google_compute_network.tsnetwork.id
}

output "ts_subnet" {
  value = google_compute_subnetwork.tssubnet.id
}