
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

variable "ts_image_hash" {
  type    = string
  default = "docker.io/salrashid123/tokenserver@sha256:5f2fa7d99f9ab1272305befea8d8810c609ff2e383b6e1e3acf22ca6a6f16a07"
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
  default = "app/certs/tls-ca.crt"
}
variable "tls_server_crt" {
  type    = string
  default = "app/certs/tokenservice.crt"
}
variable "tls_server_key" {
  type    = string
  default = "app/certs/tokenservice.key"
}

# Token Client

variable "tc_project_name" {
  type    = string
  default = "tokenclient"
}
variable "tls_client_ca" {
  type    = string
  default = "app/certs/tls-ca.crt"
}
variable "tls_client_crt" {
  type    = string
  default = "app/certs/tokenclient.crt"
}
variable "tls_client_key" {
  type    = string
  default = "app/certs/tokenclient.key"
}
variable "tc_image_hash" {
  type    = string
  default = "docker.io/salrashid123/tokenclient@sha256:32f6f33ba3d4f5595b5b4ac9fa82b00ff06810d6059bef8ee940e1ff4c9fb877"  
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