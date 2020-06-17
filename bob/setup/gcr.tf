resource "google_container_registry" "registry" {
  project = google_project.project.project_id
  depends_on = [google_project_service.service]
}

resource "google_storage_bucket_iam_member" "viewer" {
  bucket = google_container_registry.registry.id
  role = "roles/storage.objectViewer"
  member = "serviceAccount:${google_service_account.tokenclient.email}"
}