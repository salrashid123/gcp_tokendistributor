

module "ts_setup" {
  source = "./alice/setup"
  region = var.region
  project_name = var.project_name
  billing_account = var.billing_account
  org_id = var.org_id
  allowedclientsubnet = var.allowedclientsubnet
  tls_server_ca = var.tls_server_ca
  tls_server_crt = var.tls_server_crt
  tls_server_key = var.tls_server_key
  gae_location_id = var.gae_location_id
}


module "ts_build" {
  source = "./alice/build"
  app_source_dir = var.app_source_dir
  project_id = module.ts_setup.ts_project_id
}

module "ts_deploy" {
  source = "./alice/deploy"
  network =  module.ts_setup.network
  zone = var.zone
  project_id = module.ts_setup.ts_project_id
  project_number = module.ts_setup.ts_project_number  
  collection_id = var.collection_id
  image_hash = module.ts_build.ts_image_hash
  ts_address = module.ts_setup.ts_address
  ts_service_account = module.ts_setup.ts_service_account
  ts_audience = "https://tokenserver"
}

module "tc_setup" {
  source = "./bob/setup"
  region = var.region
  project_name = var.tc_project_name
  billing_account = var.billing_account
  org_id = var.org_id
  tls_client_ca = var.tls_client_ca
  tls_client_crt = var.tls_client_crt
  tls_client_key = var.tls_client_key
}

module "tc_build" {
  source = "./bob/build"
  app_source_dir = var.app_source_dir
  project_id = module.tc_setup.tc_project_id
  project_number = module.tc_setup.tc_project_number  
}


module "tc_deploy" {
  source = "./bob/deploy"
  network =  module.tc_setup.network
  zone = var.zone
  project_id = module.tc_setup.tc_project_id
  project_number = module.tc_setup.tc_project_number  
  image_hash = module.tc_build.tc_image_hash
  sni_servername = var.sni_servername  
  tc_address = module.tc_setup.tc_address
  ts_audience = "https://tokenserver"
  tc_service_account = module.tc_setup.tc_service_account


  ts_provisioner = var.ts_provisioner
  ts_service_account = var.ts_service_account
  ts_address =  var.ts_address

  # Uncomment for ci/cd testing
  # ts_service_account = module.ts_setup.ts_service_account
  # ts_address =  module.ts_setup.ts_address

}


module "ts_provisioner" {
  source = "./app"
  collection_id = var.collection_id
  zone = var.zone
  bind_pcr = var.bind_pcr
  bind_pcr_value = var.bind_pcr_value
  ts_project_id = module.ts_setup.ts_project_id

  tc_project_id = var.tc_project_id  
  tc_instance_id = var.tc_instance_id  

  # Uncomment for ci/cd testing
  # tc_project_id = module.tc_setup.tc_project_id  
  # tc_instance_id = module.tc_deploy.tc_instance_id
}
