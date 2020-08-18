
resource "random_id" "id" {
  byte_length = 4
  prefix      = "tc-"
}

resource "google_project" "project" {
  name            = var.tc_project_name
  project_id =  var.tc_project_id == "tc-random" ? random_id.id.hex : var.tc_project_id
  billing_account = var.billing_account
  org_id          = var.org_id
  auto_create_network = true
  labels = {}  
}

resource "google_project_service" "service" {
  for_each = toset([
    "compute.googleapis.com",
    "storage-api.googleapis.com",
    "storage-component.googleapis.com",
    "secretmanager.googleapis.com",
    "containerregistry.googleapis.com",
    "cloudbuild.googleapis.com",
    "logging.googleapis.com",
    "monitoring.googleapis.com",
    "containerregistry.googleapis.com",
  ])
  service            = each.key
  project            = google_project.project.project_id
  disable_on_destroy = false
  disable_dependent_services = false
}

resource "google_project_iam_member" "logwriter" {
  project = google_project.project.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.tokenclient.email}"
}
