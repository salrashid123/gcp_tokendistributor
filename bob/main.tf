provider "google-beta" {
  # credentials = file("<NAME>.json")
}
provider "null" {}

module "setup" {
  source = "./setup"
  region = var.region
  project_name = var.project_name
  billing_account = var.billing_account
  org_id = var.org_id
  tlsca = var.tlsca
  tls_crt = var.tls_crt
  tls_key = var.tls_key
}

module "build" {
  source = "./build"
  app_source_dir = var.app_source_dir
  project_id = module.setup.project_id
  project_number = module.setup.project_number  
}

module "deploy" {
  source = "./deploy"
  network =  module.setup.network
  zone = var.zone
  project_id = module.setup.project_id
  project_number = module.setup.project_number  
  image_hash = module.build.image_hash
  tc_service_account = module.setup.tc_service_account
  ts_service_account = var.ts_service_account
  ts_address = var.ts_address
  ts_provisioner = var.ts_provisioner
  sni_servername = var.sni_servername  
  tc_address = module.setup.tc_address
  ts_audience = "https://tokenserver"
}
