
resource "google_compute_firewall" "vpn_default" {
  name          = "allow-vpn-outbound-token-requests"
  project       = var.tc_project_id
  network       = var.tc_network
  allow {
    protocol = "tcp"
    ports    = ["50051"]
  }
  allow {
    protocol = "icmp"
  }
  direction = "EGRESS"
}


resource "google_compute_vpn_tunnel" "tunnel1" {
  name          = "tunnel1"
  project     = var.tc_project_id
  peer_ip     = var.ts_peer_vpn_ip
  region = var.region
  shared_secret = var.vpn_key
  local_traffic_selector = [var.tc_cidr]
  target_vpn_gateway = var.tc_gateway
}

resource "google_compute_route" "route1" {
  name       = "route1"
  project    = var.tc_project_id
  network    = var.tc_network
  dest_range = var.ts_cidr
  priority   = 900

  next_hop_vpn_tunnel = google_compute_vpn_tunnel.tunnel1.id
}