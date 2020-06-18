
variable "project_name" {
  type    = string
  default = "tokenclient"
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

variable "tlsca" {
  type    = string
  default = "certs/tls-ca.crt"
}
variable "tls_crt" {
  type    = string
  default = "certs/tokenclient.crt"
}
variable "tls_key" {
  type    = string
  default = "certs/tokenclient.key"
}
