

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

output "natip_address" {
  value = google_compute_address.natip.address
}

output "gcr_id" {
  value = google_container_registry.registry.id
}

output "network" {
  value = google_compute_network.tsnetwork.id
}