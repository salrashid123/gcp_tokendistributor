
resource "google_app_engine_application" "app" {
  project = google_project.project.project_id
  location_id = var.gae_location_id
  depends_on = [google_project_service.service]
}

# https://b.corp.google.com/issues/148567895

resource "null_resource" "firestore" {
  provisioner "local-exec" {
    command = "gcloud alpha firestore databases create --region ${var.gae_location_id} --project ${google_project.project.project_id} -q"    
  }
  depends_on = [google_app_engine_application.app]
}

