provider "google-beta" {
  # credentials = file("<NAME>.json")
}
provider "null" {}

module "setup" {
  source = "./setup"
  region = var.region
  ts_project_name = var.ts_project_name
  ts_project_id = var.ts_project_id  
  billing_account = var.billing_account
  org_id = var.org_id
  allowedclientsubnet = var.allowedclientsubnet
  tls_server_ca = var.tls_server_ca
  tls_server_crt = var.tls_server_crt
  tls_server_key = var.tls_server_key
  gae_location_id = var.gae_location_id
}

module "build" {
  source = "./build"
  app_source_dir = var.app_source_dir
  project_id = module.setup.project_id
}

module "deploy" {
  source = "./deploy"
  network =  module.setup.network
  zone = var.zone
  project_id = module.setup.project_id
  project_number = module.setup.project_number  
  collection_id = var.collection_id
  image_hash = module.build.image_hash
  ts_address = module.setup.ts_address
  ts_service_account = module.setup.ts_service_account
  ts_subnet = module.setup.ts_subnet
  ts_audience = "https://tokenserver"
}
