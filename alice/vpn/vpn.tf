

resource "google_compute_firewall" "vpn_default" {
  name          = "allow-vpn-inbound-token-requests"
  project       = var.ts_project_id
  network       = var.ts_network
  source_ranges = [var.tc_cidr]
  allow {
    protocol = "tcp"
    ports    = ["50051"]
  }
  allow {
    protocol = "icmp"
  }
  target_tags = ["tokenserver"]
  direction = "INGRESS"
}


resource "google_compute_vpn_tunnel" "tunnel1" {
  name          = "tunnel1"
  project     = var.ts_project_id
  peer_ip       = var.tc_peer_vpn_ip
  region = var.region
  shared_secret = var.vpn_key
  local_traffic_selector = [var.ts_cidr]
  target_vpn_gateway = var.ts_gateway
}

resource "google_compute_route" "route1" {
  name       = "route1"
  project    = var.ts_project_id
  network    = var.ts_network
  dest_range = var.tc_cidr
  priority   = 900

  next_hop_vpn_tunnel = google_compute_vpn_tunnel.tunnel1.id
}