
resource "random_id" "id" {
  byte_length = 4
  prefix      = "ts-"
}

resource "google_project" "project" {
  name            = var.ts_project_name
  project_id =  var.ts_project_id == "ts-random" ? random_id.id.hex : var.ts_project_id
  billing_account = var.billing_account
  org_id          = var.org_id
  auto_create_network = false
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
    "firestore.googleapis.com",
    "logging.googleapis.com",
    "monitoring.googleapis.com",
    "containerregistry.googleapis.com",
    "appengine.googleapis.com"
  ])
  service            = each.key
  project = google_project.project.project_id
  disable_on_destroy = false
  disable_dependent_services = false
}

resource "google_project_iam_member" "logwriter" {
  project = google_project.project.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.tokenserver.email}"
}

resource "google_project_iam_member" "firestorereader" {
  project = google_project.project.project_id
  role    = "roles/datastore.viewer"
  member  = "serviceAccount:${google_service_account.tokenserver.email}"
}