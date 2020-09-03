
resource "google_compute_instance_iam_binding" "binding" {
  project = var.project_id
  zone = var.zone
  instance_name = google_compute_instance.tokenclient.name
  role = "roles/compute.viewer"
  members = [
    "user:${var.ts_provisioner}",
    "serviceAccount:${var.ts_service_account}",    
  ]
}

resource "google_compute_disk_iam_binding" "binding" {
  project = var.project_id
  zone = var.zone
  name = google_compute_instance.tokenclient.name
  role = "roles/compute.viewer"
  members = [
    "user:${var.ts_provisioner}",
    "serviceAccount:${var.ts_service_account}",    
  ]
}