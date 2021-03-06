
resource "google_compute_firewall" "default" {
  name          = "allow-inbound-token-requests"
  project       = google_project.project.project_id
  network       = google_compute_network.tsnetwork.name
  source_ranges = [var.allowedclientsubnet]
  allow {
    protocol = "tcp"
    ports    = ["50051"]
  }
  source_tags = ["tokenserver"]
}

resource "google_compute_address" "natip" {
  name    = "natip"
  project = google_project.project.project_id  
  region = google_compute_subnetwork.tssubnet.region
}

resource "google_compute_address" "tsip" {
  name    = "tsip"
  project = google_project.project.project_id 
  region = google_compute_subnetwork.tssubnet.region 
}

resource "google_compute_address" "vpnip" {
  name    = "vpnip"
  project = google_project.project.project_id 
  region = google_compute_subnetwork.tssubnet.region 
}

resource "google_compute_network" "tsnetwork" {
  name = "tsnetwork"
  project = google_project.project.project_id
  auto_create_subnetworks = false
  delete_default_routes_on_create = true
  depends_on = [google_project_service.service]
}

resource "google_compute_route" "default" {
  name        = "default-route"
  dest_range  = "0.0.0.0/0"
  project     = google_project.project.project_id  
  network     = google_compute_network.tsnetwork.name
  next_hop_gateway = "default-internet-gateway"
  priority    = 1000
}

resource "google_compute_subnetwork" "tssubnet" {
  name = "tssubnet"
  project = google_project.project.project_id
  network = google_compute_network.tsnetwork.id
  ip_cidr_range = var.ts_cidr
  region = var.region
}


resource "google_compute_router" "router" {
  name    = "router"
  project = google_project.project.project_id
  region  = google_compute_subnetwork.tssubnet.region
  network = google_compute_network.tsnetwork.id
}

resource "google_compute_router_nat" "nat" {
  name                               = "nat-all"
  project                            = google_project.project.project_id
  region                             = google_compute_router.router.region
  router                             = google_compute_router.router.name
  nat_ip_allocate_option             = "MANUAL_ONLY"
  nat_ips                            = [google_compute_address.natip.id]
  source_subnetwork_ip_ranges_to_nat = "LIST_OF_SUBNETWORKS"
  subnetwork {
    name                    = google_compute_subnetwork.tssubnet.id
    source_ip_ranges_to_nat = ["ALL_IP_RANGES"]
  }
}

resource "google_compute_vpn_gateway" "target_gateway" {
  name    = "vpn1"
  region  = google_compute_subnetwork.tssubnet.region
  project = google_project.project.project_id
  network = google_compute_network.tsnetwork.id
}

resource "google_compute_forwarding_rule" "fr_esp" {
  name        = "fr-esp"
  project = google_project.project.project_id
  region  = google_compute_subnetwork.tssubnet.region  
  ip_protocol = "ESP"
  ip_address  = google_compute_address.vpnip.address
  target      = google_compute_vpn_gateway.target_gateway.id
}

resource "google_compute_forwarding_rule" "fr_udp500" {
  name        = "fr-udp500"
  project = google_project.project.project_id  
  region  = google_compute_subnetwork.tssubnet.region  
  ip_protocol = "UDP"
  port_range  = "500"
  ip_address  = google_compute_address.vpnip.address
  target      = google_compute_vpn_gateway.target_gateway.id
}

resource "google_compute_forwarding_rule" "fr_udp4500" {
  name        = "fr-udp4500"
  project = google_project.project.project_id  
  region  = google_compute_subnetwork.tssubnet.region  
  ip_protocol = "UDP"
  port_range  = "4500"
  ip_address  = google_compute_address.vpnip.address
  target      = google_compute_vpn_gateway.target_gateway.id
}