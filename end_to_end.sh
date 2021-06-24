#!/bin/bash

export TF_VAR_billing_account=000C16-9779B5-redacted
export TF_VAR_org_id=673208redacted


terraform init
terraform apply --target=module.ts_setup -auto-approve
terraform apply --target=module.ts_build -auto-approve
terraform apply --target=module.ts_deploy -auto-approve

export TF_VAR_ts_project_id=`terraform output -raw -state=terraform.tfstate ts_project_id`
export TF_VAR_ts_service_account=`terraform output -raw -state=terraform.tfstate ts_service_account`
export TF_VAR_ts_address=`terraform output -raw -state=terraform.tfstate ts_address`


terraform apply --target=module.tc_setup -auto-approve
terraform apply --target=module.tc_build -auto-approve

export TF_VAR_ts_provisioner=`gcloud config get-value core/account`

terraform apply --target=module.tc_deploy \
 -var="ts_service_account=$TF_VAR_ts_service_account" \
 -var="ts_address=$TF_VAR_ts_address" \
 -var="ts_provisioner=$TF_VAR_ts_provisioner" \
 -auto-approve


export TF_VAR_tc_project_id=`terraform output -raw -state=terraform.tfstate tc_project_id`
export TF_VAR_tc_instance_id=`terraform output -raw -state=terraform.tfstate tc_instance_id`
export TF_VAR_tc_address=`terraform output -raw -state=terraform.tfstate tc_address`


cd app/

go run src/provisioner/provisioner.go --fireStoreProjectId $TF_VAR_ts_project_id --firestoreCollectionName foo \
    --clientProjectId $TF_VAR_tc_project_id --clientVMZone us-central1-a --peerAddress=$TF_VAR_tc_address --peerSerialNumber=5 \
    --clientVMId $TF_VAR_tc_instance_id  --secretsFile=secrets.json


# cd ../
# terraform destroy --target=module.ts_setup -auto-approve 
# terraform destroy --target=module.tc_setup -auto-approve
# rm -rf .terraform* terraform*