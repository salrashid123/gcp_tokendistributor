

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

output "natip_address" {
  value = google_compute_address.natip.address
}

output "gcr_id" {
  value = google_container_registry.registry.id
}

output "network" {
  value = google_compute_network.tcnetwork.id
}