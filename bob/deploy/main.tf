# for mTLS

resource "google_compute_instance" "tokenclient" {
  name         = "tokenclient"
  machine_type = "f1-micro"
  description = "TokenClient"
  project = var.project_id  
  zone = var.zone
  boot_disk {
    initialize_params {
      image = "cos-cloud/cos-stable-81-12871-119-0"
    }
  }
  tags = ["tokenclient"]
  service_account {
    email = var.tc_service_account
    scopes = ["userinfo-email", "cloud-platform"]
  }
  network_interface {
    network       = var.network
    access_config {
      nat_ip = var.tc_address
    }
  }
  metadata = {
    google-logging-enabled = true
    google-monitoring-enabled = false
    user-data = <<EOT
#cloud-config

write_files:
- path: /etc/systemd/system/cloudservice.service
  permissions: 0644
  owner: root
  content: |
    [Unit]
    Description=Start a simple docker container
    Wants=gcr-online.target
    After=gcr-online.target

    [Service]
    Environment="HOME=/home/cloudservice"
    ExecStartPre=/usr/bin/docker-credential-gcr configure-docker
    ExecStart=/usr/bin/docker run --rm -u 0 --device=/dev/tpm0:/dev/tpm0 --name=mycloudservice gcr.io/${var.project_id}/tokenclient@${var.image_hash} --address ${var.ts_address}:50051 --servername ${var.sni_servername} --tsAudience ${var.ts_audience} --useSecrets --tlsClientCert projects/${var.project_number}/secrets/tls_crt --tlsClientKey projects/${var.project_number}/secrets/tls_key --tlsCertChain projects/${var.project_number}/secrets/tls-ca --doAttestation --exchangeSigningKey --v=20 -alsologtostderr
    ExecStop=/usr/bin/docker stop mycloudservice
    ExecStopPost=/usr/bin/docker rm mycloudservice

runcmd:
- iptables -D INPUT -p tcp -m tcp --dport 22 -j ACCEPT
- systemctl mask --now serial-getty@ttyS0.service
- systemctl daemon-reload
- systemctl start cloudservice.service
EOT
  }
}

# for ALTS
# resource "google_compute_instance" "tokenclient" {
#   name         = "tokenclient"
#   machine_type = "f1-micro"
#   description = "TokenClient"
#   project = var.project_id  
#   zone = var.zone
#   boot_disk {
#     initialize_params {
#       image = "cos-cloud/cos-stable-81-12871-119-0"
#     }
#   }
#   tags = ["tokenclient"]
#   service_account {
#     email = var.tc_service_account
#     scopes = ["userinfo-email", "cloud-platform"]
#   }
#   network_interface {
#     network       = var.network
#     access_config {
#       nat_ip = var.tc_address
#     }
#   }
#   metadata = {
#     google-logging-enabled = true
#     google-monitoring-enabled = false
#     user-data = <<EOT
# #cloud-config

# write_files:
# - path: /etc/systemd/system/cloudservice.service
#   permissions: 0644
#   owner: root
#   content: |
#     [Unit]
#     Description=Start a simple docker container
#     Wants=gcr-online.target
#     After=gcr-online.target

#     [Service]
#     Environment="HOME=/home/cloudservice"
#     ExecStartPre=/usr/bin/docker-credential-gcr configure-docker
#     ExecStart=/usr/bin/docker run --rm -u 0 --device=/dev/tpm0:/dev/tpm0 --name=mycloudservice gcr.io/${var.project_id}/tokenclient@${var.image_hash} --address ${var.ts_address}:50051 --tsAudience ${var.ts_audience} --useALTS --doAttestation --exchangeSigningKey --v=20 -alsologtostderr
#     ExecStop=/usr/bin/docker stop mycloudservice
#     ExecStopPost=/usr/bin/docker rm mycloudservice

# runcmd:
# - iptables -D INPUT -p tcp -m tcp --dport 22 -j ACCEPT
# - systemctl mask --now serial-getty@ttyS0.service
# - systemctl daemon-reload
# - systemctl start cloudservice.service
# EOT
#   }
# }
