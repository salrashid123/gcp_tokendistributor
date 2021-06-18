
# For mTLS

resource "google_compute_instance" "tokenserver" {
  name         = "tokenserver"
  machine_type = "e2-small"
  description = "TokenServer"
  project = var.project_id  
  zone = var.zone
  boot_disk {
    initialize_params {
      image = "cos-cloud/cos-stable-81-12871-119-0"
    }
  }
  tags = ["tokenserver"]
  service_account {
    email = var.ts_service_account
    scopes = ["userinfo-email", "cloud-platform"]
  }
  network_interface {
    network       = var.network
    access_config {
      nat_ip = var.ts_address
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
    ExecStart=/usr/bin/docker run --rm -u 0 --device=/dev/tpm0:/dev/tpm0 -p 50051:50051 --name=mycloudservice gcr.io/${var.project_id}/tokenserver@${var.image_hash} --grpcport 0.0.0.0:50051 --tsAudience ${var.ts_audience} --useTPM --expectedPCRValue=24af52a4f429b71a3184a6d64cddad17e54ea030e2aa6576bf3a5a3d8bd3328f --pcr=0 --validatePeerIP --validatePeerSN --useMTLS --useSecrets --tlsCert projects/${var.project_number}/secrets/tls_crt --tlsKey projects/${var.project_number}/secrets/tls_key --tlsCertChain projects/${var.project_number}/secrets/tls-ca  --firestoreProjectId ${var.project_id} --firestoreCollectionName ${var.collection_id} --jwtIssuedAtJitter=5 --v=20 -alsologtostderr
    ExecStop=/usr/bin/docker stop mycloudservice
    ExecStopPost=/usr/bin/docker rm mycloudservice

bootcmd:
- iptables -D INPUT -p tcp -m tcp --dport 22 -j ACCEPT
- systemctl mask --now serial-getty@ttyS0.service

runcmd:
- systemctl daemon-reload
- systemctl start cloudservice.service
EOT
  }
}
