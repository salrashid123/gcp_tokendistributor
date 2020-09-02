resource "null_resource" "provisioner" {
  provisioner "local-exec" {
    command = "${path.module}/provisioner  --fireStoreProjectId ${var.ts_project_id}   --firestoreCollectionName ${var.collection_id}     --clientProjectId ${var.tc_project_id}   --clientVMZone ${var.zone}   --clientVMId ${var.tc_instance_id}   --secretsFile ${var.ts_secrets_file}"    
  }
}