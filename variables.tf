
variable "ts_project_name" {
  type    = string
  default = "tokenserver"
}
variable "ts_project_id" {
  type    = string
  default = "ts-random"
}
variable "billing_account" {
  type    = string
}
variable "org_id" {
  type    = string
}
variable "region" {
  type    = string
  default = "us-central1"
}
variable "zone" {
  type    = string
  default = "us-central1-a"
}
variable "app_source_dir" {
  type    = string
  default = "app/"
}


# Token Server

variable "collection_id" {
  type    = string
  default = "foo"
}
variable "bind_pcr" {
  type    = string
  default = "0"
}
variable "bind_pcr_value" {
  type    = string
  default = "fcecb56acc303862b30eb342c4990beb50b5e0ab89722449c2d9a73f37b019fe"
}
variable "ts_image_hash" {
  type    = string
  default = "docker.io/salrashid123/tokenserver@sha256:d6f25876bc04f2a7b2e5253b93daba39b5f1be570b11dffd81acf3992063dd91"
}

variable "gae_location_id" {
  type    = string
  default = "us-central"
}
variable "allowedclientsubnet" {
  type    = string
  default = "0.0.0.0/0"
}
variable "tls_server_ca" {
  type    = string
  default = "alice/certs/tls-ca.crt"
}
variable "tls_server_crt" {
  type    = string
  default = "alice/certs/tokenservice.crt"
}
variable "tls_server_key" {
  type    = string
  default = "alice/certs/tokenservice.key"
}

# Token Client

variable "tc_project_name" {
  type    = string
  default = "tokenclient"
}
variable "tls_client_ca" {
  type    = string
  default = "bob/certs/tls-ca.crt"
}
variable "tls_client_crt" {
  type    = string
  default = "bob/certs/tokenclient.crt"
}
variable "tls_client_key" {
  type    = string
  default = "bob/certs/tokenclient.key"
}
variable "tc_image_hash" {
  type    = string
  default = "docker.io/salrashid123/tokenclient@sha256:b40b8f71d96828ef00f839f9993b7cc65f24ee6cf22c386e0939ce0fca252f6a"  
}
variable "sni_servername" {
  type    = string
  default = "tokenservice.esodemoapp2.com"
}
variable "ts_provisioner" {
  type    = string
  default = "admin@esodemoapp2.com"  
}

# Following variables are just placeholders
# Comment this section out if running both alice/bob on the
# same org locally for CI/CD
# Start local
variable "ts_service_account" {
  type    = string
  default = "tokenserver@ts-random.iam.gserviceaccount.com"
}
variable "ts_address" {
  type    = string
  default = "127.0.0.1"
}

variable "tc_project_id" {
  type    = string
  default = "tc-random"
}
variable "tc_instance_id" {
  type    = string
  default = "1234567890"
}
# End Local