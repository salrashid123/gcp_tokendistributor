
## gcloud CLI Sequence

The following sequence uses gcloud CLI for the same steps as terraform

### TokenServer

```bash
export org_id=111211221
export billing_account=000C16-9779B5-s234
export ts_project_name=tokenserver
export random_id=`head /dev/urandom | tr -dc a-z0-9 | head -c 4 ; echo ''`
export ts_project_id=ts-$random_id
export ts_sni=tokenservice.esodemoapp2.com

## Setup

gcloud projects create $ts_project_id --name $ts_project_name

gcloud config set project $ts_project_id

gcloud beta billing projects link $ts_project_id \
   --billing-account=$billing_account


export ts_project_number=`gcloud projects describe $ts_project_id --format="value(projectNumber)"`
export region=us-central1
export zone=$region-a
export ts_collection_id=foo
export ts_audience=https://tokenservice
export ts_service_account_email=tokenserver@$ts_project_id.iam.gserviceaccount.com
export allowedclientsubnet=0.0.0.0/0
export firestoreRegion=us-central

gcloud services enable --project $ts_project_id compute.googleapis.com \
    storage-api.googleapis.com \
    storage-component.googleapis.com \
    secretmanager.googleapis.com \
    containerregistry.googleapis.com \
    cloudbuild.googleapis.com \
    firestore.googleapis.com \
    logging.googleapis.com \
    monitoring.googleapis.com \
    appengine.googleapis.com

gcloud iam service-accounts create tokenserver \
 --display-name "Service Account for TokenServer" \
 --project $ts_project_id

gcloud projects add-iam-policy-binding $ts_project_id --member="serviceAccount:$ts_service_account_email" \
  --role="roles/logging.logWriter"

gcloud projects add-iam-policy-binding $ts_project_id --member="serviceAccount:$ts_service_account_email" \
  --role="roles/datastore.viewer"

gcloud projects add-iam-policy-binding $ts_project_id --member="serviceAccount:$ts_service_account_email" \
  --role="roles/monitoring.metricWriter"

gcloud auth configure-docker

curl -s -H "Authorization: Bearer `gcloud auth application-default print-access-token`" "https://gcr.io/v2/token?service=gcr.io&scope=repository:$ts_project_id/my-repo:push,pull"

gsutil iam ch serviceAccount:$ts_service_account_email:objectViewer gs://artifacts.$ts_project_id.appspot.com

gcloud app create --project $ts_project_id --region $firestoreRegion

curl --request PATCH   "https://appengine.googleapis.com/v1beta/apps/$ts_project_id?updateMask=databaseType"       --header "Authorization: Bearer `gcloud auth application-default print-access-token`"       --header 'Accept: application/json'      --header 'Content-Type: application/json'      --data '{"databaseType":"CLOUD_FIRESTORE"}'


gcloud compute networks create tsnetwork --project $ts_project_id

gcloud compute networks subnets create tssubnet --network=tsnetwork --range="10.0.0.0/16" --region=$region --project $ts_project_id

gcloud compute  firewall-rules create allow-inbound-token-requests --allow=tcp:50051 --network=tsnetwork  --source-ranges=$allowedclientsubnet  --target-tags=tokenserver --project $ts_project_id

gcloud compute addresses create natip --region=$region --project $ts_project_id

gcloud compute addresses create tsip --region=$region --project $ts_project_id

export natIP=`gcloud compute addresses describe natip --region=$region  --project $ts_project_id --format='value(address)'`
export tsIP=`gcloud compute addresses describe tsip --region=$region  --project $ts_project_id --format='value(address)'`

gcloud compute routers create router \
    --network tsnetwork \
    --region $region --project $ts_project_id


gcloud compute routers nats create nat-all --router=router --region=$region --nat-external-ip-pool=natip  --nat-custom-subnet-ip-ranges=tssubnet --project $ts_project_id


gcloud beta secrets create tls-ca --replication-policy=automatic   --data-file=alice/certs/tls-ca.crt --project $ts_project_id 

gcloud beta secrets add-iam-policy-binding tls-ca \
  --member=serviceAccount:$ts_service_account_email \
  --role=roles/secretmanager.secretAccessor  \
  --project $ts_project_id


gcloud beta secrets create tls_crt --replication-policy=automatic   --data-file=alice/certs/tokenservice.crt --project $ts_project_id 

gcloud beta secrets add-iam-policy-binding tls_crt \
  --member=serviceAccount:$ts_service_account_email \
  --role=roles/secretmanager.secretAccessor  \
  --project $ts_project_id

gcloud beta secrets create tls_key --replication-policy=automatic   --data-file=alice/certs/tokenservice.key --project $ts_project_id 

gcloud beta secrets add-iam-policy-binding tls_key \
  --member=serviceAccount:$ts_service_account_email \
  --role=roles/secretmanager.secretAccessor  \
  --project $ts_project_id


## Build

gcloud builds submit --config app/cloudbuild-ts.yaml --project $ts_project_id app/

docker pull gcr.io/$ts_project_id/tokenserver

### Deploy

export ts_image_hash=`docker inspect --format='{{index .RepoDigests 0}}' gcr.io/$ts_project_id/tokenserver`

envsubst < "ts-cloud-config.yaml.tmpl" > "ts-cloud-config.yaml"

gcloud beta compute  instances create \
  tokenserver  \
  --zone=$zone --machine-type=f1-micro  \
  --network=tsnetwork \
  --subnet=tssubnet   \
  --address $tsIP \
  --tags tokenserver \
  --service-account $ts_service_account_email \
  --scopes=cloud-platform,userinfo-email \
  --image-family cos-stable \
  --image-project cos-cloud \
  --metadata google-logging-enabled=true,google-monitoring-enabled=true \
  --shielded-secure-boot --shielded-vtpm --shielded-integrity-monitoring  \
  --metadata-from-file user-data=ts-cloud-config.yaml \
  --project $ts_project_id 
```

```bash
echo $ts_service_account_email
echo $tsIP
```

### TokenClient


```bash
## Setup

export org_id=67320456654
export billing_account=000C16-9779B5-45564
export tc_project_name=tokenclient
export random_id=`head /dev/urandom | tr -dc a-z0-9 | head -c 4 ; echo ''`
export tc_project_id=tc-$random_id
export ts_sni=tokenservice.esodemoapp2.com
export ts_audience=https://tokenservice

## Make sure these env vars from Alice are set

echo $ts_service_account_email
echo $tsIP
echo $ts_provisioner_email


gcloud projects create $tc_project_id --name $tc_project_name

gcloud config set project $tc_project_id

gcloud beta billing projects link $tc_project_id \
   --billing-account=$billing_account


export tc_project_number=`gcloud projects describe $tc_project_id --format="value(projectNumber)"`
export region=us-central1
export zone=$region-a
export ts_audience=https://tokenservice
export tc_service_account_email=tokenclient@$tc_project_id.iam.gserviceaccount.com


gcloud services enable --project $tc_project_id \
    compute.googleapis.com \
    storage-api.googleapis.com \
    storage-component.googleapis.com \
    secretmanager.googleapis.com \
    containerregistry.googleapis.com \
    cloudbuild.googleapis.com \
    logging.googleapis.com \
    monitoring.googleapis.com \
    containerregistry.googleapis.com


gcloud iam service-accounts create tokenclient \
 --display-name "Service Account for Tokenclient" \
 --project $tc_project_id

export tc_service_account_email=tokenclient@$tc_project_id.iam.gserviceaccount.com

gcloud projects add-iam-policy-binding $tc_project_id --member="serviceAccount:$tc_service_account_email" \
  --role="roles/monitoring.metricWriter"

gcloud projects add-iam-policy-binding $tc_project_id --member="serviceAccount:$tc_service_account_email" \
  --role="roles/logging.logWriter"

gcloud auth configure-docker

curl -s -H "Authorization: Bearer `gcloud auth application-default print-access-token`" "https://gcr.io/v2/token?service=gcr.io&scope=repository:$tc_project_id/my-repo:push,pull"

gsutil iam ch serviceAccount:$tc_service_account_email:objectViewer gs://artifacts.$tc_project_id.appspot.com

gcloud compute networks create tcnetwork --project $tc_project_id

gcloud compute networks subnets create tcsubnet --network=tcnetwork --range="10.0.0.0/16" --region=$region --project $tc_project_id

gcloud compute addresses create natip --region=$region --project $tc_project_id
gcloud compute addresses create tcip --region=$region --project $tc_project_id

export natIP=`gcloud compute addresses describe natip --region=$region  --project $tc_project_id --format='value(address)'`
export tcIP=`gcloud compute addresses describe tcip --region=$region  --project $tc_project_id --format='value(address)'`

echo $natIP
echo $tcIP

gcloud compute routers create router \
    --network tcnetwork \
    --region $region --project $tc_project_id



gcloud compute routers nats create nat-all --router=router --region=$region --nat-external-ip-pool=natip  --nat-custom-subnet-ip-ranges=tcsubnet --project $tc_project_id

gcloud beta secrets create tls_crt --replication-policy=automatic   --data-file=bob/certs/tokenclient.crt --project $tc_project_id 

gcloud beta secrets add-iam-policy-binding tls_crt \
  --member=serviceAccount:$tc_service_account_email \
  --role=roles/secretmanager.secretAccessor  \
  --project $tc_project_id

gcloud beta secrets create tls_key --replication-policy=automatic   --data-file=bob/certs/tokenclient.key --project $tc_project_id 

gcloud beta secrets add-iam-policy-binding tls_key \
  --member=serviceAccount:$tc_service_account_email \
  --role=roles/secretmanager.secretAccessor  \
  --project $tc_project_id


gcloud beta secrets create tls-ca  --replication-policy=automatic   --data-file=bob/certs/tls-ca.crt --project $tc_project_id 

gcloud beta secrets add-iam-policy-binding tls-ca \
  --member=serviceAccount:$tc_service_account_email \
  --role=roles/secretmanager.secretAccessor  \
  --project $tc_project_id


## Build

gcloud builds submit --config app/cloudbuild-tc.yaml --project $tc_project_id app/

docker pull gcr.io/$tc_project_id/tokenclient

### Deploy

export tc_image_hash=`docker inspect --format='{{index .RepoDigests 0}}' gcr.io/$tc_project_id/tokenclient`
echo $tc_image_hash

envsubst < "tc-cloud-config.yaml.tmpl" > "tc-cloud-config.yaml"

gcloud beta compute  instances create \
  tokenclient  \
  --zone=$zone --machine-type=f1-micro  \
  --network=tcnetwork \
  --subnet=tcsubnet   \
  --address $tcIP \
  --tags tokenclient \
  --service-account $tc_service_account_email \
  --scopes=cloud-platform,userinfo-email \
  --image-family cos-stable \
  --image-project cos-cloud \
  --metadata google-logging-enabled=true,google-monitoring-enabled=true \
  --shielded-secure-boot --shielded-vtpm --shielded-integrity-monitoring  \
  --metadata-from-file user-data=tc-cloud-config.yaml \
  --project $tc_project_id 


gcloud compute instances add-iam-policy-binding  tokenclient 	 \
   --member=serviceAccount:$ts_service_account_email  --role roles/compute.viewer   --project $tc_project_id 

gcloud compute instances add-iam-policy-binding  tokenclient 	 \
   --member=user:$ts_provisioner_email --role roles/compute.viewer   --project $tc_project_id 


export tc_instanceID=`gcloud compute instances describe tokenclient --format='value(id)' --project $tc_project_id`

# Provide Alice the following

echo $tc_instanceID
echo $tc_project_id
```

### Provision

```bash
# as Alice
echo $tc_instanceID
echo $tc_project_id

cd app/
go run src/provisioner/provisioner.go --fireStoreProjectId $ts_project_id --firestoreCollectionName foo     --clientProjectId $tc_project_id --clientVMZone us-central1-a --clientVMId $tc_instanceID 
```