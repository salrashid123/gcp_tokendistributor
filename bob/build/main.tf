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
    command = "gcloud builds submit --config ${var.app_source_dir}/cloudbuild-tc.yaml --machine-type=n1-highcpu-32  --project ${var.project_id} ${var.app_source_dir}/ "    
  }
}

data "google_container_registry_image" "tokenclient_url" {
  name = "tokenclient"
  tag  = "latest"
  project = "${var.project_id}"
  depends_on = [null_resource.submit]  
}

data "docker_registry_image" "tokenclient" {
  name = data.google_container_registry_image.tokenclient_url.image_url
}

data "google_container_registry_image" "tokenclient" {
  name   = "tokenclient"
  digest = data.docker_registry_image.tokenclient.sha256_digest
  project = var.project_id
}