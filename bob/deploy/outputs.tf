
output "tc_instance_id" {
  value = google_compute_instance.tokenclient.instance_id
}

# Comment the following block if using VPN or NAT
# output "tc_external_ip" {
#   value = google_compute_instance.tokenclient.network_interface.0.access_config.0.nat_ip
# }

output "tc_internal_ip" {
  value = google_compute_instance.tokenclient.network_interface.0.network_ip
}