
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

variable "vpn_key" {
  type    = string
  default = "a971276b78b0315fff47d84a"  ###<<<<<<<<<<<<< change me `openssl rand -hex 12`
}

# Token Server

variable "collection_id" {
  type    = string
  default = "foo"
}

variable "ts_image_hash" {
  type    = string
  default = "docker.io/salrashid123/tokenserver@sha256:64ad74416a6b43a3f7ef4a45d0ef677d7c7a84a7db2743cd0c3dc0f05e9344c8"
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

variable "ts_pcr_value" {
  type    = string
  default = "24af52a4f429b71a3184a6d64cddad17e54ea030e2aa6576bf3a5a3d8bd3328f"
  #default = "0f35c214608d93c7a6e68ae7359b4a8be5a0e99eea9107ece427c4dea4e439cf" # for SEV
}

variable "ts_pcr" {
  type    = string
  default = "0"
}

variable "ts_cidr" {
  type    = string
  default = "192.168.0.0/16"
}

variable "ts_internal_ip" {
  type    = string
  default = ""  
}

variable "ts_external_ip" {
  type    = string
  default = ""
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
  default = "docker.io/salrashid123/tokenclient@sha256:0228eb3e54c90fa110b6bdceb4064fe07647ada0b3303067638bedb58ff8dbd8"  
}
variable "sni_servername" {
  type    = string
  default = "tokenservice.esodemoapp2.com"
}
variable "ts_provisioner" {
  type    = string
  default = "admin@esodemoapp2.com"  
}

variable "tc_cidr" {
  type    = string
  default = "10.0.0.0/16"
}

variable "tc_internal_ip" {
  type    = string
  default = ""
}

variable "tc_external_ip" {
  type    = string
  default = ""
}

variable "ts_vpnip_address" {
  type    = string
  default = ""
}

variable "tc_vpnip_address" {
  type    = string
  default = ""
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