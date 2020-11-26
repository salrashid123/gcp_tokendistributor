
## gcloud CLI Sequence

The following sequence uses gcloud CLI for the same steps as terraform

### TokenServer

```bash
# First setup some env vars
export org_id=your_org_id
export billing_account=your_billing_id

## the following will create a project for the 'tokenserver' from scratch.
##  if you have your own project you can set the value of `ts_project_id` and proceed and skip the line
##  where a new project is setup
export ts_project_name=tokenserver
export random_id=`head /dev/urandom | tr -dc a-z0-9 | head -c 6 ; echo ''`
export ts_project_id=ts-$random_id
export ts_sni=tokenservice.esodemoapp2.com

## Setup
git clone https://github.com/salrashid123/gcp_tokendistributor.git
cd gcp_tokendistributor/

gcloud projects create $ts_project_id --name $ts_project_name

gcloud config set project $ts_project_id

gcloud beta billing projects link $ts_project_id \
   --billing-account=$billing_account


## Enable some APIs.
### The only reason firestore is enabled is for a "save" location for the encryption as set by the provisioner
### The only reason GCP Secrets engine is used is to save/load the TLS certificates
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

## This is the service account the token server will run as.
## If this code is run outside of GCP, you will need to download a JSON certificate file
## and bootstrap application default credentials before running the tokenserver
gcloud iam service-accounts create tokenserver \
 --display-name "Service Account for TokenServer" \
 --project $ts_project_id

## allow the tokenserver to write to logs
gcloud projects add-iam-policy-binding $ts_project_id --member="serviceAccount:$ts_service_account_email" \
  --role="roles/logging.logWriter"

## to read from Firestore
gcloud projects add-iam-policy-binding $ts_project_id --member="serviceAccount:$ts_service_account_email" \
  --role="roles/datastore.viewer"

## to write to metrics/stackdriver
gcloud projects add-iam-policy-binding $ts_project_id --member="serviceAccount:$ts_service_account_email" \
  --role="roles/monitoring.metricWriter"

## the following steps enables google container registry
##  You don't have to use GCR (you can use any registry or for that matter, just run the TOkenServer directly on a VM)
gcloud auth configure-docker

curl -s -H "Authorization: Bearer `gcloud auth application-default print-access-token`" "https://gcr.io/v2/token?service=gcr.io&scope=repository:$ts_project_id/my-repo:push,pull"

gsutil iam ch serviceAccount:$ts_service_account_email:objectViewer gs://artifacts.$ts_project_id.appspot.com

## The following enables Firestore (you need appengine enabled for firestore)
gcloud app create --project $ts_project_id --region $firestoreRegion

curl --request PATCH   "https://appengine.googleapis.com/v1beta/apps/$ts_project_id?updateMask=databaseType"       --header "Authorization: Bearer `gcloud auth application-default print-access-token`"       --header 'Accept: application/json'      --header 'Content-Type: application/json'      --data '{"databaseType":"CLOUD_FIRESTORE"}'

## Create an isolated network.
##  you can use the default network here but i didn't want the default firewall and route rules
gcloud compute networks create tsnetwork --project $ts_project_id

gcloud compute networks subnets create tssubnet --network=tsnetwork --range="10.0.0.0/16" --region=$region --project $ts_project_id

## Allow inbound connections from outside to the tokenserver's port
##  Note, i allowed all internet access ($allowedclientsubnet).  In reality, you probably just need the IP range any token client will connect from
## eg, the static ip addresses allocated to each tokenclient

gcloud compute  firewall-rules create allow-inbound-token-requests --allow=tcp:50051 --network=tsnetwork  --source-ranges=$allowedclientsubnet  --target-tags=tokenserver --project $ts_project_id

## Create a NAT IP address for egress traffic from the tokenserver to internet.  This isn't used in the default configuration
gcloud compute addresses create natip --region=$region --project $ts_project_id

## This is the IP address for the tokenserver
gcloud compute addresses create tsip --region=$region --project $ts_project_id

export natIP=`gcloud compute addresses describe natip --region=$region  --project $ts_project_id --format='value(address)'`
export tsIP=`gcloud compute addresses describe tsip --region=$region  --project $ts_project_id --format='value(address)'`

gcloud compute routers create router \
    --network tsnetwork \
    --region $region --project $ts_project_id

gcloud compute routers nats create nat-all --router=router --region=$region --nat-external-ip-pool=natip  --nat-custom-subnet-ip-ranges=tssubnet --project $ts_project_id


## Use GCP secrets manager to create the TLS CA file, the public key and private key (server side public and private key)
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

## We are using cloud build here to make the image.
## You can use any container system to generate this (docker, bazel, etc)
gcloud builds submit --config app/cloudbuild-ts.yaml --project $ts_project_id app/

## Upload the image to the GCR owned by the tokenserver.
## THis image repo can be anywehre (within the tokenserver proejct or even on dockerhub)
docker pull gcr.io/$ts_project_id/tokenserver

### Deploy

cd gcloud_setup/

## Get the image hash for the tokenserver
export ts_image_hash=`docker inspect --format='{{index .RepoDigests 0}}' gcr.io/$ts_project_id/tokenserver`

envsubst < "ts-cloud-config.yaml.tmpl" > "ts-cloud-config.yaml"

## Create the VM Image
gcloud beta compute  instances create   tokenserver   \
 --zone=$zone --machine-type=f1-micro  \
 --network=tsnetwork   --subnet=tssubnet  \
 --address $tsIP   --tags tokenserver \
 --service-account $ts_service_account_email \
 --scopes=cloud-platform,userinfo-email \
 --image cos-stable-81-12871-119-0   --image-project cos-cloud \
 --metadata google-logging-enabled=true  \
 --shielded-secure-boot --shielded-vtpm --shielded-integrity-monitoring \
 --metadata-from-file user-data=ts-cloud-config.yaml  \
 --project $ts_project_id
```

```bash
echo
echo "Provide these values to TokenClient"
echo export ts_service_account_email=$ts_service_account_email
echo export tsIP=$tsIP
```

### TokenClient


```bash
## Setup

export org_id=your_org_id
export billing_account=your_billing_id

export tc_project_name=tokenclient
export random_id=`head /dev/urandom | tr -dc a-z0-9 | head -c 6 ; echo ''`
export tc_project_id=tc-$random_id
export ts_sni=tokenservice.esodemoapp2.com
export ts_audience=https://tokenservice

## Make sure these env vars from Alice are set
## ts_provisioner_email is the email address of the user/service account that will run the provisioner
export ts_provisioner_email=<user_to_run_provisioner>
echo $ts_service_account_email
echo $tsIP
echo $ts_provisioner_email

git clone https://github.com/salrashid123/gcp_tokendistributor.git
cd gcp_tokendistributor/

## You can skip this step and simply set the env var if you alredy have a project
gcloud projects create $tc_project_id --name $tc_project_name

gcloud config set project $tc_project_id

gcloud beta billing projects link $tc_project_id \
   --billing-account=$billing_account


export tc_project_number=`gcloud projects describe $tc_project_id --format="value(projectNumber)"`
export region=us-central1
export zone=$region-a
export ts_audience=https://tokenservice
export tc_service_account_email=tokenclient@$tc_project_id.iam.gserviceaccount.com

## Enable some services
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

## This is the service account the token client will run as.
## The token server will expect an OpenID Connect (instance identity document) that is from this service account
## and from a vm_id that we will later create

gcloud iam service-accounts create tokenclient \
 --display-name "Service Account for Tokenclient" \
 --project $tc_project_id

export tc_service_account_email=tokenclient@$tc_project_id.iam.gserviceaccount.com

gcloud projects add-iam-policy-binding $tc_project_id --member="serviceAccount:$tc_service_account_email" \
  --role="roles/monitoring.metricWriter"

gcloud projects add-iam-policy-binding $tc_project_id --member="serviceAccount:$tc_service_account_email" \
  --role="roles/logging.logWriter"

## Create container registry
gcloud auth configure-docker

curl -s -H "Authorization: Bearer `gcloud auth application-default print-access-token`" "https://gcr.io/v2/token?service=gcr.io&scope=repository:$tc_project_id/my-repo:push,pull"

gsutil iam ch serviceAccount:$tc_service_account_email:objectViewer gs://artifacts.$tc_project_id.appspot.com


## Create an isolated network (non default network)

gcloud compute networks create tcnetwork --project $tc_project_id

gcloud compute networks subnets create tcsubnet --network=tcnetwork --range="10.0.0.0/16" --region=$region --project $tc_project_id


## Create two static ip addresses.  
### NATIP: if you configure the tokenclient to *not* have an external IP address, all outbound traffic will use the NAT Gateway
### TCIP:  this is the IP address the tokenserver will see requests come from if NAT isn't used
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


## Create secrets to hold the TLS public/private keys
## These PEM file keys are given to the token client's admin by any other process.
## I just happen to be using GCP Secret Manager here on the same project as the tokenclient but there's nothing to 
### prevent these serets being held in a project owned by the TokenServer.  In this flow, the tokenservers admin
### creates all the MTLS keys but only saves teh tokenclient's ones in their GCP Secrets manager project.
### The tokenserver's admin will have to grant tc_service_account_email permissions to read the TLS certs (tokenclient.crt, tokenclient.key, tls-ca.crt)
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

### build using container builder and push to gcr
gcloud builds submit --config app/cloudbuild-tc.yaml --project $tc_project_id app/

docker pull gcr.io/$tc_project_id/tokenclient

### Deploy

export tc_image_hash=`docker inspect --format='{{index .RepoDigests 0}}' gcr.io/$tc_project_id/tokenclient`
echo $tc_image_hash

cd gcloud_setup/
envsubst < "tc-cloud-config.yaml.tmpl" > "tc-cloud-config.yaml"

gcloud beta compute  instances create   tokenclient   \
 --zone=$zone --machine-type=e2-small    --network=tcnetwork  \
 --subnet=tcsubnet     --address $tcIP   --tags tokenclient  \
 --service-account $tc_service_account_email \
 --scopes=cloud-platform,userinfo-email   --image cos-stable-81-12871-119-0  \
 --image-project cos-cloud   --metadata google-logging-enabled=true  \
 --shielded-secure-boot --shielded-vtpm --shielded-integrity-monitoring  \
 --metadata-from-file user-data=tc-cloud-config.yaml \
 --project $tc_project_id


## The following setup run by the tokenclient will authorize the provisioner user/service account and the service account that
## runs as the tokenserver access to READ the metadata for the TokenClients VM.
### This step is necessary to verify that the tokenclient has SSH disabled, running a known image, etc

## NOTE ts_provisioner_email is the person who will be running the provisioner application.  he/she needs to be able to view
##  the disk and VM specifications Bob runs.  Typically, this is alice@domain.com

gcloud compute instances add-iam-policy-binding  tokenclient 	 \
   --member=serviceAccount:$ts_service_account_email  --role roles/compute.viewer   --project $tc_project_id 

gcloud compute instances add-iam-policy-binding  tokenclient 	 \
   --member=user:$ts_provisioner_email --role roles/compute.viewer   --project $tc_project_id 

gcloud compute disks add-iam-policy-binding  tokenclient 	 \
   --member=serviceAccount:$ts_service_account_email  --role roles/compute.viewer   --project $tc_project_id 

gcloud compute disks add-iam-policy-binding  tokenclient 	 \
   --member=user:$ts_provisioner_email --role roles/compute.viewer   --project $tc_project_id 

export tc_instanceID=`gcloud compute instances describe tokenclient --format='value(id)' --project $tc_project_id`

# Provide Alice the following

echo export tc_instanceID=$tc_instanceID
echo export tc_project_id=$tc_project_id
```

### Provision

Create a file called `secrets.json`.  This will contain the raw/unencrypted data that will be saved into firestore and returned back to the client.

The format of this file is a list of `Secrets` as defined by the tokenservice.proto file:

eg
```json
[
    {
        "name": "secret1",
        "type": "GCP Bearer",
        "data": "Zm9vb2Jhcg=="
    },
    {
        "name": "secret2",
        "type": "GCP Bearer2",
        "data": "Zm9vb2Jhcg=="
    }
]
```

```bash
# as Alice
echo $tc_instanceID
echo $tc_project_id

cd app/
go run src/provisioner/provisioner.go \
  --fireStoreProjectId $ts_project_id \
  --firestoreCollectionName foo     --clientProjectId $tc_project_id --clientVMZone us-central1-a \
  --clientVMId $tc_instanceID \
  --useTPM \
  --peerSerialNumber=5 \
  --peerAddress=$tcIP \
  --attestationPCR=0 \
  --attestationPCRValue=fcecb56acc303862b30eb342c4990beb50b5e0ab89722449c2d9a73f37b019fe  \
  --secretsFile=secrets.json
```

---

### Run TokenServer/TokenClient directly

During development, you may want to directly run the TokenServer and TokenClient and not need to deal with containerizing components.

For example, to run the TokenServer, create a plain VM (eg debian)

```bash
envsubst < "ts-cloud-config.yaml.tmpl" > "ts-cloud-config.yaml"

gcloud compute  instances create   tokenserver   \
 --zone=$zone --machine-type=e2-small  \
 --network=tsnetwork   --subnet=tssubnet  \
 --address $tsIP   --tags tokenserver \
 --service-account $ts_service_account_email \
 --scopes=cloud-platform,userinfo-email \
 --shielded-secure-boot --shielded-vtpm --shielded-integrity-monitoring \
 --image=debian-10-buster-v20200805 --image-project=debian-cloud  \
 --project $ts_project_id

## We're opening firewall port to allow you to debug
gcloud compute  firewall-rules create allow-ssh --allow=tcp:22 --network=tsnetwork \
   --source-ranges=0.0.0.0/0  --target-tags=tokenserver --project $ts_project_id
```

Then ssh into that VM, [install golang](https://golang.org/doc/install), then finally execute the TokenServer using the parameters
you would use within `ts-cloud-config.yaml` ExecStart command, eg

```bash
git clone https://github.com/salrashid123/gcp_tokendistributor.git


cd gcp_tokendistributor/app

## Note, 58992830672 is the projectNumber where the GCP Secrets are saved (eg, the tokenserver's projectID, (ts-x3qw))
go run src/server/server.go \
  --grpcport 0.0.0.0:50051 \
  --tsAudience https://tokenservice \
  --useTPM \
  --useMTLS \
  --useSecrets \
  --tlsCert projects/58992830672/secrets/tls_crt \
  --tlsKey projects/58992830672/secrets/tls_key \
  --tlsCertChain projects/58992830672/secrets/tls-ca  \
  --firestoreProjectId ts-x3qw \
  --firestoreCollectionName foo \
  --expectedPCRValue=fcecb56acc303862b30eb342c4990beb50b5e0ab89722449c2d9a73f37b019fe \
  --pcr=0  --validatePeerIP --validatePeerSN --jwtIssuedAtJitter=5 \
  --v=20 -alsologtostderr

```

Similarly for a `TokenClient`, 

```bash
gcloud compute  instances create   tokenclient   \
 --zone=$zone --machine-type=n1-standard-1   --network=tcnetwork  \
 --subnet=tcsubnet     --address $tcIP   --tags tokenclient  \
 --service-account $tc_service_account_email \
 --scopes=cloud-platform,userinfo-email \
 --shielded-secure-boot --shielded-vtpm --shielded-integrity-monitoring \
 --image=debian-10-buster-v20200805 --image-project=debian-cloud  \
 --project $tc_project_id

gcloud compute  firewall-rules create allow-ssh --allow=tcp:22 --network=tcnetwork \
   --source-ranges=0.0.0.0/0  --target-tags=tokenclient --project $tc_project_id
```

 Install go, run (remember to replace the IP address below that points to the TokenServer as well as the GCP ProjectNumber where the TLScertificates are saved)

```bash
## Note, 149534119989 is the projectID where the tokenclien'ts TLS secrets are saved
go run src/client/client.go  \
  --address 34.67.171.121:50051 \
  --useMTLS \
  --servername tokenservice.esodemoapp2.com \
  --tsAudience https://tokenservice \
  --useSecrets \
  --tlsClientCert projects/149534119989/secrets/tls_crt \
  --tlsClientKey projects/149534119989/secrets/tls_key \
  --tlsCertChain projects/149534119989/secrets/tls-ca \
  --useTPM \
  --doAttestation \
  --exchangeSigningKey \
  --v=20 -alsologtostderr
 ```