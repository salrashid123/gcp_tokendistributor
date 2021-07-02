
# resource "google_compute_firewall" "default" {
#   name          = "allow-inbound-ssh-requests"
#   project       = google_project.project.project_id
#   network       = google_compute_network.tcnetwork.name
#   source_ranges = "0.0.0.0/0"
#   allow {
#     protocol = "tcp"
#     ports    = ["22"]
#   }
#   source_tags = ["tokenclient"]
# }

resource "google_compute_address" "natip" {
  name    = "natip"
  project = google_project.project.project_id  
  region = google_compute_subnetwork.tcsubnet.region
}

resource "google_compute_address" "tcip" {
  name    = "tcip"
  project = google_project.project.project_id 
  region = google_compute_subnetwork.tcsubnet.region 
}

resource "google_compute_network" "tcnetwork" {
  name = "tcnetwork"
  project = google_project.project.project_id
  auto_create_subnetworks = false
  delete_default_routes_on_create = true
  depends_on = [google_project_service.service]  
}

resource "google_compute_route" "default" {
  name        = "default-route"
  dest_range  = "0.0.0.0/0"
  project     = google_project.project.project_id  
  network     = google_compute_network.tcnetwork.name
  next_hop_gateway = "default-internet-gateway"
  priority    = 1000
}

resource "google_compute_subnetwork" "tcsubnet" {
  name = "tcsubnet"
  project = google_project.project.project_id
  network = google_compute_network.tcnetwork.id
  ip_cidr_range = "10.0.0.0/16"
  region = var.region
}


resource "google_compute_router" "router" {
  name    = "router"
  project = google_project.project.project_id
  region  = google_compute_subnetwork.tcsubnet.region
  network = google_compute_network.tcnetwork.id
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
    name                    = google_compute_subnetwork.tcsubnet.id
    source_ip_ranges_to_nat = ["ALL_IP_RANGES"]
  }
}
