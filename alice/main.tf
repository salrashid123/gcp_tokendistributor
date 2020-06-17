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
  allowedclientsubnet = var.allowedclientsubnet
  tlsca = var.tlsca
  tls_crt = var.tls_crt
  tls_key = var.tls_key
  gae_location_id = var.gae_location_id
}


module "deploy" {
  source = "./deploy"
  network =  module.setup.network
  zone = var.zone
  project_id = module.setup.project_id
  project_number = module.setup.project_number  
  collection_id = var.collection_id
  image_hash = var.image_hash
  ts_address = module.setup.ts_address
  ts_service_account = module.setup.ts_service_account
  ts_audience = "https://tokenserver"
}
