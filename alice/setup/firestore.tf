
resource "google_app_engine_application" "app" {
  project = google_project.project.project_id
  location_id = var.gae_location_id
  database_type = "CLOUD_FIRESTORE"
  depends_on = [google_project_service.service]
}