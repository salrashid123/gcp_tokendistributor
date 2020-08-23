
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

resource "google_compute_network" "tsnetwork" {
  name = "tsnetwork"
  project = google_project.project.project_id
  depends_on = [google_project_service.service]
}

resource "google_compute_subnetwork" "tssubnet" {
  name = "tssubnet"
  project = google_project.project.project_id
  network = google_compute_network.tsnetwork.id
  ip_cidr_range = "10.0.0.0/16"
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
