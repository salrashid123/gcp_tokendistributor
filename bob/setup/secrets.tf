resource "google_secret_manager_secret" "tlsca" {
  provider = google-beta
  secret_id = "tls-ca"
  replication {
    automatic = true
  }
  project = google_project.project.project_id
  depends_on = [google_project_service.service]
}

resource "google_secret_manager_secret_version" "tlsca" {
  provider = google-beta    
  secret = google_secret_manager_secret.tlsca.id
  secret_data = file(var.tlsca)
}

resource "google_secret_manager_secret_iam_member" "ts-reader" {
  provider = google-beta

  secret_id = google_secret_manager_secret.tlsca.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.tokenclient.email}"
}

resource "google_secret_manager_secret" "tls_crt" {
  provider = google-beta
  secret_id = "tls_crt"
  replication {
    automatic = true
  }
  project = google_project.project.project_id
  depends_on = [google_project_service.service]
}

resource "google_secret_manager_secret_version" "tls_crt" {
  provider = google-beta    
  secret = google_secret_manager_secret.tls_crt.id
  secret_data = file(var.tls_crt)
}

resource "google_secret_manager_secret_iam_member" "ts-cert-reader" {
  provider = google-beta

  secret_id = google_secret_manager_secret.tls_crt.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.tokenclient.email}"
}

resource "google_secret_manager_secret" "tls_key" {
  provider = google-beta
  secret_id = "tls_key"
  replication {
    automatic = true
  }
  project = google_project.project.project_id
  depends_on = [google_project_service.service]
}

resource "google_secret_manager_secret_version" "tls_key" {
  provider = google-beta    
  secret = google_secret_manager_secret.tls_key.id
  secret_data = file(var.tls_key)
}

resource "google_secret_manager_secret_iam_member" "ts-key-reader" {
  provider = google-beta

  secret_id = google_secret_manager_secret.tls_key.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.tokenclient.email}"
}