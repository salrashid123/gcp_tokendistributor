output "ts_image_hash" {
  value = data.google_container_registry_image.tokenserver.digest
}