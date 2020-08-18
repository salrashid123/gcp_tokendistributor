
variable "tc_project_name" {
  type    = string
  default = "tokenclient"
}
variable "tc_project_id" {
  type    = string
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

variable "image_hash" {
  type = string
  default = "docker.io/salrashid123/tokenclient@sha256:a0357a27c36bf8faea53d47efe8808df036df6afc2b5174dad2e3413d44d683b"  
}

variable "ts_service_account" {
  type    = string
  default = ""
}

variable "ts_address" {
  type    = string
  default = ""
}

variable "app_source_dir" {
  type    = string
  default = "../app"
}

variable "ts_provisioner" {
  type    = string
  default = ""
}

variable "sni_servername" {
  type    = string
  default = "tokenservice.esodemoapp2.com"
}

variable "tls_client_ca" {
  type    = string
}
variable "tls_client_crt" {
  type    = string
}
variable "tls_client_key" {
  type    = string
}
