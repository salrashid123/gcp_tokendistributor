output "vpn_key" {
  value = google_compute_vpn_tunnel.tunnel1.shared_secret
}