data "google_client_config" "default" {}

provider "docker" {
  registry_auth {
    address  = "gcr.io"
    username = "oauth2accesstoken"
    password = data.google_client_config.default.access_token
  }
}

resource "null_resource" "submit" {
  provisioner "local-exec" {
    command = "gcloud builds submit --config ${var.app_source_dir}/cloudbuild-ts.yaml --machine-type=n1-highcpu-32  --project ${var.project_id} ${var.app_source_dir}/ "    
  }
}

data "google_container_registry_image" "tokenserver_url" {
  name = "tokenserver"
  tag  = "latest"
  project = var.project_id
  depends_on = [null_resource.submit]  
}

data "docker_registry_image" "tokenserver" {
  name = data.google_container_registry_image.tokenserver_url.image_url
}

data "google_container_registry_image" "tokenserver" {
  name   = "tokenserver"
  digest = data.docker_registry_image.tokenserver.sha256_digest
  project = var.project_id
}