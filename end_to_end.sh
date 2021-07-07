#!/bin/bash

export TF_VAR_billing_account=000C16-9779B5-redacted
export TF_VAR_org_id=67320878redacted


terraform init

## TokenServer
terraform apply --target=module.ts_setup -auto-approve
terraform apply --target=module.ts_build -auto-approve

export TF_VAR_ts_project_id=`terraform output -raw -state=terraform.tfstate ts_project_id`
export TF_VAR_ts_service_account=`terraform output -raw -state=terraform.tfstate ts_service_account`
export TF_VAR_ts_vpnip_address=`terraform output -raw -state=terraform.tfstate ts_vpnip_address`


## TokenClient
terraform apply --target=module.tc_setup -auto-approve
terraform apply --target=module.tc_build -auto-approve

export TF_VAR_tc_vpnip_address=`terraform output -raw -state=terraform.tfstate tc_vpnip_address`

## VPN
export TF_VAR_vpn_key=`openssl rand -hex 12`
terraform apply --target=module.ts_vpn -auto-approve
terraform apply --target=module.tc_vpn -auto-approve

## Deploy TokenServer
terraform apply --target=module.ts_deploy -auto-approve
# with VPN
export TF_VAR_ts_address=`terraform output -raw -state=terraform.tfstate ts_internal_address`
# no VPN
#export TF_VAR_ts_address=`terraform output -raw -state=terraform.tfstate ts_external_address`


## configure provisioner user
export TF_VAR_ts_provisioner=`gcloud config get-value core/account`

## Deploy TokenClient and allow provisioned user/service account to inspect VM
terraform apply --target=module.tc_deploy \
 -var="ts_service_account=$TF_VAR_ts_service_account" \
 -var="ts_address=$TF_VAR_ts_address" \
 -var="ts_provisioner=$TF_VAR_ts_provisioner" \
 -auto-approve

export TF_VAR_tc_project_id=`terraform output -raw -state=terraform.tfstate tc_project_id`
export TF_VAR_tc_instance_id=`terraform output -raw -state=terraform.tfstate tc_instance_id`

# for VPN
export TF_VAR_tc_address=`terraform output -raw -state=terraform.tfstate tc_internal_address`
# for no VPN
#export TF_VAR_tc_address=`terraform output -raw -state=terraform.tfstate tc_external_address`


## Provision
cd app/

go run src/provisioner/provisioner.go --fireStoreProjectId $TF_VAR_ts_project_id --firestoreCollectionName foo \
    --clientProjectId $TF_VAR_tc_project_id --clientVMZone us-central1-a --peerAddress=$TF_VAR_tc_address --peerSerialNumber=5 \
    --clientVMId $TF_VAR_tc_instance_id  --secretsFile=secrets.json


# cd ../
# terraform destroy --target=module.ts_setup -auto-approve && terraform destroy --target=module.tc_setup -auto-approve
# rm -rf .terraform* terraform*
