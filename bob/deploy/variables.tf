
variable "project_id" {
  type    = string
}
variable "project_number" {
  type    = string
}

variable "image_hash" {
  type = string
}

variable "tc_service_account" {
  type = string
}

variable "ts_service_account" {
  type = string
}

variable "ts_address" {
  type = string
}
variable "tc_address" {
  type = string
}

variable "sni_servername" {
  type    = string
  default = "tokenservice.esodemoapp2.com"
}

variable "ts_provisioner" {
  type = string
}

variable "network" {
  type    = string
}

variable "zone" {
  type    = string
}

variable "ts_audience" {
  type    = string
}
