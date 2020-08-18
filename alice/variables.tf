
variable "ts_project_name" {
  type    = string
  default = "tokenserver"
}
variable "ts_project_id" {
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

variable "collection_id" {
  type    = string
  default = "foo"
}
variable "image_hash" {
  type    = string
  default = "docker.io/salrashid123/tokenserver@sha256:9e14edad6ea155b193d3d9eb1cf51e338bf922a178e5d4032dc1bcee1b685c2c"
}

variable "zone" {
  type    = string
  default = "us-central1-a"
}

variable "app_source_dir" {
  type    = string
  default = "../app"  
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
}
variable "tls_server_crt" {
  type    = string
}
variable "tls_server_key" {
  type    = string
}
