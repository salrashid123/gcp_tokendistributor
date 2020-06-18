

resource "null_resource" "submit" {
  provisioner "local-exec" {
    command = "gcloud builds submit --config ${var.app_source_dir}/cloudbuild-tc.yaml --project  $TF_VAR_project_id ${var.app_source_dir}/ "    
  }
}

data "external" "gcloud" {
  program = ["${path.module}/util.sh" ]    
  query = {
    project_id = var.project_id
  }
  depends_on = [null_resource.submit]
}