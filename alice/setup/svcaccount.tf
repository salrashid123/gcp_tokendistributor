resource "google_service_account" "tokenserver" {
  project      = google_project.project.project_id
  account_id   = "tokenserver"
  display_name = "Service Account for TokenServer"
}



