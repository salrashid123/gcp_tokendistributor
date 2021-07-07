
output "instance_id" {
  value = google_compute_instance.tokenserver.instance_id
}

# Comment the following block if using VPN or NAT
# output "ts_external_ip" {
#   value = google_compute_instance.tokenserver.network_interface.0.access_config.0.nat_ip
# }

output "ts_internal_ip" {
  value = google_compute_instance.tokenserver.network_interface.0.network_ip
}