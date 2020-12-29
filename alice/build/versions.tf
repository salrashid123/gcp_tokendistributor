terraform {
  required_providers {
    docker = {
      source = "kreuzwerker/docker"
    }
    google = {
      source = "hashicorp/google"
    }
    null = {
      source = "hashicorp/null"
    }
  }
  required_version = ">= 0.13"
}
