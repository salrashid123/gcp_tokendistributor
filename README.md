## Remote Authorization and TokenDistributor for GCP VMs

Sample workflow to distribute a secret between two parties where one party directly delivers the secret to a _specific_, deprivileged virtual machine on GCP.  Normally when two parties want to share some data, one party grants IAM permissions on that resource to an identity owned by the other.  That is, if Alice wants to share data with a VM Bob owns,  Alice will grant IAM permissions on some data with the ServiceAccount Bob's VM runs as.  However, Bob essentially has indirect rights on that data simply by assuming the identity of the service account or by simply ssh into that VM and acquiring the service account credentials.  

This is problematic in some situations where Alice would like Bob's VM to process data in isolation but not alow Bob himself from acquiring that data and exfilterating.

The flow described in this repo flow inverts the access where the data owner (Alice) shares some secret material with permissions to sensitive data but **ONLY** to a isolated system owned by Bob.  The data owner (Alice) will share access _exclusively__ to the VM only after attesting some known binary that Alice is aware of and trusts is running on that VM and that that Bob cannot access the VM via SSH or any other means.

>> This is not an officially supported Google product

#### Architecture

![images/arch.png](images/arch.png)


In prose:

Alice wants to share a file she has on a GCS with a specific VM Bob started.  Alice and Bob do not work in the same company and do not share GCP projects.

Alice creates a GCP `projectA`
Bob creates a GCP `projectB`

Alice creates creates a VM (`VM-A`) with  `serviceAccountA` and public ip_address `ip-A`
Bob creates creates a VM (`VM-B`) with `serviceAccountB`.

>> Both VMs Alice and Bob run (especially Bob), can be [Confidential Compute Instances](https://cloud.google.com/blog/products/identity-security/introducing-google-cloud-confidential-computing-with-confidential-vms)

Bob and Alice exchange information offline about `ip-A`, `serviceAccountA` and `serviceAccountB` each party uses

Bob grants Alice and `serviceAccountA` permissions to read GCE startup script and metadata for `VM-A`

`VM-A` runs a `TokenService` that functions to validate and return authorized token requests from `VM-B` 

`VM-B` starts and attempts to contact `ip-A` and acquire the secret from the `TokenService`.

`TokenService` is not yet authorized for to give any token for `serviceAccountB` or `VM-B` and does not return a token.

Alice (offline) runs a `Provisioning` application which:
  
Reads `VM-B` startup script data
  
Validates that `VM-B` has been deprivileged (no ssh access)

Validates the docker image running on `VM-B` is known image hash and trusted by Alice) 

Provisioning Server generates hash of `VM-B` startup script that includes commands to prevent SSH and `docker run` command for the trusted image image.

Provisioning Server saves arbitrary `Secret` data as well as the hash of startupscript, Public IP address, ServiceAccount for the remote VM to Google FireStore using the `instance_id` for `VM-B` as the primary key 

`VM-B` contacts `TokenService`

`VM-B` uses its [instance_identity_document](https://cloud.google.com/compute/docs/instances/verifying-instance-identity#verify_signature) as an auth token to call `VM-A`

`VM-A` verifies the `identity document` is signed by Google

`VM-A` checks `instanceID`, `serviceAccount`, `audience` and other claims in the document.  The identity document must be signed within some duration threshold.

`VM-A` looks up Firestore using the `instanceID` as  the key.

`VM-A` uses GCP Compute API to retrieve the current/active startup script for `VM-B`

`VM-A` compares the hash of the retrieved startup script against the value in Firestore previously authorized, the egress IP address, VM Fingerprint, etc.  If mismatch, return error.

`VM-A` returns encrypted `Secrets` to `VM-B`

If the Secret is a GCP Service Account, use that to download data from Google Services.  

![images/sequence.png](images/sequence.png)

---
- [Start TokenServer Infrastructure and Service (Alice)](#Start-TokenServer-Infrastructure-and-Service-(Alice))
- [Deploy TokenService (Alice)](#Deploy-TokenService-(Alice))
- [Start TokenClient Infrastructure (Bob)](#Start-TokenClient-Infrastructure-(Bob))
- [Deploy TokenClient (Bob)](#Deploy-TokenClient-(Bob))
- [Provision TokenClient vm_id (Alice)](#Provision-TokenClient-vm_id-(Alice))

### Setup

This repo will configure the full TokenService infrastructure and Service:

1. Alice will use Terraform to create new GCP Project
2. Bob will Terraform to create new GCP Project
3. Alice and Bob will exchange specifications of ServiceAccounts and IP address of TokenService
5. Alice will use Terraform to create TokenServer
6. Bob will use Terraform to create TokenClient
7. Alice will use `Provisioning` application to authorize Bob's VM and ServiceAccount.
8. TokenServer will return secret to TokenClient

  *It is expected customers will customize the client and server to suite their needs.*

If you do not want to use terraform, the `gcloud_setup/` folder contains command sequences in gcloud.

Alice and Bob will both need:

* [terraform](terraform.io)
* `go 1.14`
* Permissions to create GCP Projects
* `gcloud` CLI

Note: Alice and Bob can setup their infrastructure and deploy applications pretty much independently.
However, Bob will need to know the TokenServer IP and projectID before he deploy the TokenClient

### Start TokenServer Infrastructure and Service (Alice)

As Alice, you will need your

*  [Billing Account ID](https://cloud.google.com/billing/docs/how-to/manage-billing-account) 
  `gcloud beta billing accounts list`

* OrganizationID
  `gcloud organizations list`
  If you do not have an organization, edit `alice/main.tf` and remove the `org_id` variable from `google_project`
 
Alice should also login to local gcloud for both cli and application-default credentials sources

```bash
gcloud auth login
gcloud auth application-default login
```

```bash
export TF_VAR_org_id=673208782222
export TF_VAR_billing_account=000C16-9779B5-12345

terraform init  

terraform apply --target=module.ts_setup -auto-approve

terraform apply --target=module.ts_build -auto-approve
```

You should see the new project details and IP address allocated/assigned for the `TokenServer`

```bash
    Outputs:

    ts_address = 35.239.242.219
    ts_image_hash = sha256:edafc58fca595e17d26b41d79760b292ddf16083e76fb7215d12df1d65fab132
    ts_project_id = ts-de7f98d5
    ts_project_number = 973084368812
    ts_service_account = tokenserver@ts-de7f98d5.iam.gserviceaccount.com
```


### Deploy TokenService (Alice)

Deploy the TokenService with defaults.  The command below will deploy an _unconfigured_ TokenServer with a static IP address (`TF_VAR_ts_address`)

```bash
terraform apply --target=module.ts_deploy -auto-approve
```

The terraform script `alice/deploy/main.tf` uses the default options described below.  Modify the startup commands appropriately and redeploy the Server as needed.

| Option | Description |
|:------------|-------------|
| **`-grpcport`** | host:port for the grpcServer(s) listener (default `:50051`|
| **`-useMTLS`** | Use mTLS. |
| **`-useSecrets`** | Use GCP Secret Manager for mTLS Certificates  |
| **`-tlsCert`** | TLS Certificate file for mTLS; specify either file or Secret Manager Path  |
| **`-tlsKey`** | TLS CertiKeyficate file for mTLS; specify either file or Secret Manager Path |
| **`-tlsCertChain`** | TLS Certificate Chain file for mTLS; specify either file or Secret Manager Path  |
| **`-tsAudience`** | The audience value for the tokenServer (default: `"https://tokenserver"`) |
| **`-validatePeerIP`** | Extract the PeerIP address for the TokenClient from the TLS Session and compare with provisioned value. |
| **`-validatePeerSN`** | Extract the SSL Serial Number and compare to provisioned value |
| **`-useTPM`** | Enable TPM based Remote Attestation flows (default: `false`) |
| **`-expectedPCRValue`** | ExpectedPCRValue from Quote/Verify (default: `PCR 0:  fcecb56acc303862b30eb342c4990beb50b5e0ab89722449c2d9a73f37b019fe`) |
| **`-pcr`** | PCR Bank to use for quote/verify (default: `0`) |
| **`-firestoreProjectId`** | ProjectID where the FireStore database is hosted. |
| **`-firestoreCollectionName`** | Name of the collection where provisioned values are saved (default: `foo`) |
| **`-jwtIssuedAtJitter`** | Validate the IssuedAt timestamp.  If issuedAt+jwtIssueAtJitter > now(), then reject (default: `1`) |

Note: if you would rather use an existing project for either the Client or Server, see the section in the Appendix.

**Provide Bob the values of `ts_address` and `ts_service_account` variables anytime later**

```bash
export TF_VAR_ts_project_id=`terraform output -state=terraform.tfstate ts_project_id`
export TF_VAR_ts_service_account=`terraform output -state=terraform.tfstate ts_service_account`
export TF_VAR_ts_address=`terraform output -state=terraform.tfstate ts_address`

echo
echo "Provide the following to Bob"
echo
echo export TF_VAR_ts_project_id=$TF_VAR_ts_project_id
echo export TF_VAR_ts_service_account=$TF_VAR_ts_service_account
echo export TF_VAR_ts_address=$TF_VAR_ts_address
```

In this case its

```bash
$ echo $TF_VAR_ts_service_account
  tokenserver@ts-de7f98d5.iam.gserviceaccount.com

$ echo $TF_VAR_ts_address
  35.239.36.219
```

### Start TokenClient Infrastructure (Bob)

As Bob, you will need your

*  [Billing Account ID](https://cloud.google.com/billing/docs/how-to/manage-billing-account) 

* OrganizationID
  `gcloud organizations list`
  If you do not have an organization, edit `alice/main.tf` and remove the `org_id` variable from `google_project`
 
The following will startup Bobs infrastructure (GCP project, and allocate IP for tokenClient). The `tc_build` step will also generate the docker image
for the TokenClient but not deploy it yet

This step can be done independently of Alice at anytime (i.e, concurrently with any of the prior steps taken by Alice)


```bash
export TF_VAR_org_id=111108786098
export TF_VAR_billing_account=22121-9779B5-30076F

terraform init

terraform apply --target=module.tc_setup -auto-approve

terraform apply --target=module.tc_build -auto-approve
```

The command will create a new GCP project, enable GCP api services, create a service account for the Token server and allocate a static IP:

```bash
    Outputs:

    tc_address = 35.193.246.123
    tc_image_hash = sha256:4e94992868f38d51b0ad85fd0e4649f818c754111eb73afb236c505024599f6f
    tc_project_id = tc-16a39413
    tc_project_number = 538014872919
    tc_service_account = tokenclient@tc-16a39413.iam.gserviceaccount.com
```

### Deploy TokenClient (Bob)

Bob will now deploy the TokenClient

Bob needs to set some additional environment variables that were *provided by Alice* earlier:

* `TF_VAR_ts_service_account`:  this is the service account Alice is using for the TokenServer (`tokenserver@ts-039e6b6a.iam.gserviceaccount.com`)
* `TF_VAR_ts_address`: this is the IP address of the TokenServer (`34.72.145.220`)
* `TF_VAR_ts_provisioner`: this is Alice's email address that Bob will authorize to read the TokenClients metadata values (eg `export TF_VAR_ts_provisioner=alice@esodemoapp2.com`)

Make sure the env vars are set (`TF_VAR_project_id` would be the the TokenClient (Bob) project)

>> this step is really important <<<

`TF_VAR_ts_provisioner` is the email/serviceAccount that will run the provisioning application.  This is needed so that Bob can allow the provisioning application to read the GCE metadata. For example, if Alice herself is running the privisoning app, it'd be `export TF_VAR_ts_provisioner=alice@domain.com`

```bash
export TF_VAR_ts_service_account=<value given by Alice>
export TF_VAR_ts_address=<value given by Alice>
export TF_VAR_ts_provisioner=<value given by Alice>

echo $TF_VAR_ts_service_account
echo $TF_VAR_ts_address
echo $TF_VAR_ts_provisioner
```

or specify them inline here:

Then deploy it to a VM

```bash
terraform apply --target=module.tc_deploy \
 -var="ts_service_account=$TF_VAR_ts_service_account" \
 -var="ts_address=$TF_VAR_ts_address" \
 -var="ts_provisioner=$TF_VAR_ts_provisioner" \
 -auto-approve
```

The terraform script `bob/deploy/main.tf` uses the default options described below.  Modify the startup commands appropriately and redeploy the Client VM as needed.

| Option | Description |
|:------------|-------------|
| **`-address`** | host:port for the TokenServer |
| **`-useMTLS`** | Use mTLS instead of TLS. |
| **`-tsAudience`** | Audience value to assign when generating and `id_token`.  Must match what the TokenServer expects (default: `"https://tokenservice"`) |
| **`-useSecrets`** | Use GCP Secret Manager for mTLS Certificates  |
| **`-tlsClientCert`** | TLS Certificate file for mTLS; specify either file or Secret Manager Path |
| **`-tlsClientKey`** | TLS CertiKeyficate file for mTLS; specify either file or Secret Manager Path  |
| **`-tlsCertChain`** | TLS Certificate Chain file for mTLS; specify either file or Secret Manager Path  |
| **`-sniServerName`** | SNI ServerName for the TLS connection (default: `tokenservice.esodemoapp2.com`; valid only for mTLS) |
| **`-serviceAccount`** | Path to GCP ServiceAccount JSON file to use to authenticate to authenticate to FireStore and GCE API (default: not used) |
| **`-firestoreProjectId`** | ProjectID where the FireStore database is hosted. |
| **`-useTPM`** | Enable TPM operations |
| **`-doAttestation`** | Start offer to Make/Activate Credential flow |
| **`-exchangeSigningKey`** | Offer RSA Signing Key (requires --doAttestation) |
| **`-tokenServerServiceAccount`** | Service Account for the TokenServer  |
| **`-maxLoop`** | Number of attempts the TokenClient will make to acquire a token (default: `360`) |
| **`-pollWaitSeconds`** | Number of seconds to wait between attempts (default: `10s`)|

You should see an output like:

```bash
      Outputs:
      tc_address = 35.193.246.123
      tc_image_hash = sha256:4e94992868f38d51b0ad85fd0e4649f818c754111eb73afb236c505024599f6f
      tc_instance_id = 7953211237324536786
      tc_project_id = tc-16a39413
      tc_project_number = 538014872919
      tc_service_account = tokenclient@tc-16a39413.iam.gserviceaccount.com
      ts_project_id = ts-48e50fad
```

Note the `tc_instance_id` and `tc_project_id`. 

```bash
export TF_VAR_tc_project_id=`terraform output -state=terraform.tfstate tc_project_id`
export TF_VAR_tc_instance_id=`terraform output -state=terraform.tfstate tc_instance_id`
export TF_VAR_tc_address=`terraform output -state=terraform.tfstate tc_address`

echo
echo "Provide the following to Alice:"
echo
echo export TF_VAR_tc_project_id=$TF_VAR_tc_project_id
echo export TF_VAR_tc_instance_id=$TF_VAR_tc_instance_id
echo export TF_VAR_tc_address=$TF_VAR_tc_address
```

** Provide these values to Alice for provisioning**

### Interlude

At this point the TokenClient and Server have started communicating but every request for a new token would fail since Alice hasn't yet vetted the integrity of the `TokenClient`:

You can see this in the logs

The tokenClient will attempt to contact tokenServer.  Since no vmID is provisioned, the tokenserver will respond w/ error

- TokenServer
![images/tserrors.png](images/tserrors.png)

- TokenClient
![images/tcerrors.png](images/tcerrors.png)

So...now 

>> **Provide token_client_instance_id to TokenServer Provisioning admin (Alice) so it can be provisioned**

Optionally provide `tc_address` to Alice (incase she wants to also a firewall around TokenServer or origin checks if NAT isn't used)


### Provision TokenClient vm_id (Alice)

Use `vm_id` to provision the Firestore Database after validating Bob's VM state

As Alice, 
```bash
export TF_VAR_tc_project_id=`<value given by Bob>`
export TF_VAR_tc_instance_id=`<value given by Bob>`
export TF_VAR_tc_address=`<value given by Bob>`
export TF_VAR_ts_project_id=`terraform output -state=terraform.tfstate ts_project_id`


echo $TF_VAR_tc_project_id
echo $TF_VAR_tc_instance_id
echo $TF_VAR_tc_address
echo $TF_VAR_ts_project_id

$ cd app/
```

Now provision the secrets you want to transfer as a formatted JSON file that maps to the `.proto` Secret struct:

- Secrets `proto`:

```proto
message Secret {
  string name = 1;
  SecretType type = 2;
  bytes data = 3;

  enum SecretType {
    RAW = 0;   // do not decode;
    TPM = 1;   // decode as TPM sealed data
    TINK = 2;  // decode as Tink Secret
  }  
}
message TokenResponse {
  string responseID = 1;
  string inResponseTo = 2;
  repeated Secret secrets = 3;  // this is a repeated field
}
```

The following `secrets.json` describes two secrets of differing types

```json
[
    {
        "name": "secret1",
        "type": "RAW",
        "data": "Zm9vb2Jhcg=="
    },
    {
        "name": "secret2",
        "type": "TINK",
        "data": "CLnwmtYGEmQKWAowdHlwZS5nb29nbGVhcGlzLmNvbS9nb29nbGUuY3J5cHRvLnRpbmsuQWVzR2NtS2V5EiIaIA7TocwCm37/3vReEGSRsoSp+a0KAq+KYEKqKH5dVqC4GAEQARi58JrWBiAB"
    }
]
```

The datafield is a base64encoded string of the actual secret.

Then provision

```bash
go run src/provisioner/provisioner.go --fireStoreProjectId $TF_VAR_ts_project_id --firestoreCollectionName foo \
    --clientProjectId $TF_VAR_tc_project_id --clientVMZone us-central1-a --clientVMId $TF_VAR_tc_instance_id  \
    --secretsFile=secrets.json
```


| Option | Description |
|:------------|-------------|
| **`-fireStoreProjectId`** | ProjectID for Firestore |
| **`-firestoreCollectionName`** | Firestore CollectionID (default: `foo`) |
| **`-clientProjectId`** | ProjectID for the TokenClient to lookup GCE VM specifications  |
| **`-clientVMZone`** | Zone where the TokenClient Runs |
| **`-clientVMId`** | Unique vm_id for the TokenClient |
| **`-secretsFile`** | Path to Secrets JSON file |
| **`-peerAddress`** | Expected IP address of the TokenClient |
| **`-peerSerialNumber`** | Expected mTLS Serial number sent by TokenClient |
| **`-useTPM`** | Enable TPM operations |
| **`-attestationPCR`** | PCR Bank to use for Attestation (default: `0`) |
| **`-attestationPCRValue`** | PCR Bank value Attestation (default: `fcecb56acc303862b30eb342c4990beb50b5e0ab89722449c2d9a73f37b019fe`) |

The output of the provisioning step will prompt Alice to confirm that the image startup script and metadata looks valid.

At that point, the image hash value will be saved into Firestore `R0OB1dVupyp/rNcb2/5Bfrx9uKjdjDNAPM9kUS7UiaI=`  using the `vm_id=2503055333933721897` in firestore document key.  Every time the TokenClient makes a request for a security token, the TokenServer will lookup the document and verify the image hash is still the one that was authorized.

The output also shows the unique `Fingerprint` of the VM `2020/07/22 09:47:32 Image Fingerprint: [yM8bKId-VQA=]`. 

```bash
$ go run src/provisioner/provisioner.go --fireStoreProjectId $TF_VAR_ts_project_id --firestoreCollectionName foo \
    --clientProjectId $TF_VAR_tc_project_id --clientVMZone us-central1-a --clientVMId $TF_VAR_tc_instance_id  \
    --secretsFile=secrets.json \
    --useTPM --attestationPCR=0 --attestationPCRValue=fcecb56acc303862b30eb342c4990beb50b5e0ab89722449c2d9a73f37b019fe

2020/09/08 16:03:27 tc-e381ee09  us-central1-a  4616733414634708048
2020/09/08 16:03:27 Found  VM instanceID "4616733414634708048"
2020/09/08 16:03:27 Image Data: #cloud-config

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
    ExecStart=/usr/bin/docker run --rm -u 0 --device=/dev/tpm0:/dev/tpm0 --name=mycloudservice gcr.io/tc-e381ee09/tokenclient@sha256:4e94992868f38d51b0ad85fd0e4649f818c754111eb73afb236c505024599f6f --address 35.222.5.146:50051 --servername tokenservice.esodemoapp2.com --tsAudience https://tokenserver --useSecrets --tlsCertChain projects/620714181540/secrets/tls-ca --v=25 -alsologtostderr
    ExecStop=/usr/bin/docker stop mycloudservice
    ExecStopPost=/usr/bin/docker rm mycloudservice

bootcmd:
- iptables -D INPUT -p tcp -m tcp --dport 22 -j ACCEPT
- systemctl mask --now serial-getty@ttyS0.service

runcmd:
- systemctl daemon-reload
- systemctl start cloudservice.service

2020/09/08 16:03:27      Found  VM initScriptHash: [bRU/GQt02of49h56ph2dv7F5ZgZ1kUskdREZvwWNaWg=]
2020/09/08 16:03:27      Found  VM CreationTimestamp "2020-09-08T12:59:59.972-07:00"
2020/09/08 16:03:27      Found  VM Fingerprint "Mj7BV6UuUs4="
2020/09/08 16:03:27      Found  VM CpuPlatform "Intel Haswell"
2020/09/08 16:03:27      Found  VM Boot Disk Source "https://www.googleapis.com/compute/v1/projects/tc-e381ee09/zones/us-central1-a/disks/tokenclient"
2020/09/08 16:03:27      Found Disk Image https://www.googleapis.com/compute/v1/projects/cos-cloud/global/images/cos-stable-81-12871-119-0
2020/09/08 16:03:27      Found  VM ServiceAccount "tokenclient@tc-e381ee09.iam.gserviceaccount.com"
2020/09/08 16:03:27 Found VM External IP 104.154.65.88
2020/09/08 16:03:27 looks ok? (y/N): 
y
2020/09/08 16:03:34 2020-09-08 20:03:34.37037 +0000 UTC
2020/09/08 16:03:34 Document data: "4616733414634708048"

```

Note that Alice not trusts the entire TokenClient vm Image hash which itself includes a docker image hash 
(`gcr.io/tc-03330b55/tokenclient@sha256:4e94992868f38d51b0ad85fd0e4649f818c754111eb73afb236c505024599f6f`).  
It is expected that this image was generated elsewhere such that both Alice and Bob would know the precise and source code that it includes.  
Docker based images will not generate deterministic builds but you can use `Bazel` as described in [Building deterministic Docker images with Bazel](https://blog.bazel.build/2015/07/28/docker_build.html) and as an example:


- [go with bazel with grpc with container](https://github.com/salrashid123/go-grpc-bazel-docker))

You can find more information about how to build the TokenClient and TokenServer in the appendix.


#### VM Fingerprint verification

The `fingerprint` value is a hash of the entire VM's state and configuration.  Any change (stop/restart, metadata update, etc) will change its value.  You can use this VM fingerprint to ensure that when the tokenclient makes a request, the VM is in the same state it was originally provisioned against 

```bash
$ gcloud compute instances describe 4616733414634708048 --zone us-central1-a --project tc-e381ee09 --format="value(fingerprint)"
Mj7BV6UuUs4=

$ gcloud compute instances stop 4616733414634708048 --zone us-central1-a --project tc-e381ee09 
$ gcloud compute instances start 4616733414634708048 --zone us-central1-a --project tc-e381ee09 

$ gcloud compute instances describe 4616733414634708048 --zone us-central1-a --project tc-e381ee09 --format="value(fingerprint)"
Y0hv2RZ_Qy0=

# change any metadata using console
$ gcloud compute instances describe 4616733414634708048 --zone us-central1-a --project tc-e381ee09  --format="value(fingerprint)"
SRVm69LywSw=
```

The following code snippet in the tokenserver performs a _runtime_ crosscheck against the value stored in firestore.

```golang
if cresp.Fingerprint != c.ImageFingerprint {
	glog.Errorf("   -------->  Error Image Fingerprint mismatch got [%s]  expected [%s]", cresp.Fingerprint, c.ImageFingerprint)
	return &tokenservice.TokenResponse{}, grpc.Errorf(codes.NotFound, fmt.Sprintf("Error:  ImageFingerpint does not match got [%s]  expected [%s]", cresp.Fingerprint, c.ImageFingerprint))
}
```

#### After Provisioning

After provisioning, the full sequence to exchange encrypted keys takes place.  

- TokenServer

The TokenServer output shows that it successfully authorized the specific TokenClient and returned given the credentials and which matched with a _live_ lookup of the VMid's metadata.   S

![images/tscomplete.png](images/tscomplete.png)

- TokenClient

The TokenClient would have acquired the secret key and then performed the optional quote/verify step.  The final step for the Client would be to save the key material to memory and start an arbitrary worker thread that would use the secrets.

![images/tccomplete.png](images/tccomplete.png)

```log
2020-11-21T03:03:01.593707258Z I1121 03:03:01.593640       1 client.go:378]      Tink AEAD Decrypted Text foo
2020-11-21T03:03:01.593367341Z I1121 03:03:01.593276       1 client.go:371]      Tink AEAD encrypted text AWrGuDmEm1pTNeyZ+zAaGtmdIib7zNSBpS/qLJac8DQ850VG
2020-11-21T03:03:01.592495689Z I1121 03:03:01.591794       1 client.go:347]      Decoding as Tink
2020-11-21T03:03:01.592473778Z I1121 03:03:01.591751       1 client.go:334]      Received  Data: name:"secret2" type:TINK data:"\x08\xb9\xf0\x9a\xd6\x06\x12d\nX\n0type.googleapis.com/google.crypto.tink.AesGcmKey\x12\"\x1a \x0eӡ\xcc\x02\x9b~\xff\xde\xf4^\x10d\x91\xb2\x84\xa9\xf9\xad\n\x02\xaf\x8a`B\xaa(~]V\xa0\xb8\x18\x01\x10\x01\x18\xb9\xf0\x9a\xd6\x06 \x01"
2020-11-21T03:03:01.592465864Z I1121 03:03:01.591740       1 client.go:337]      Decoding as RAW fooobar
2020-11-21T03:03:01.592419639Z I1121 03:03:01.591694       1 client.go:334]      Received  Data: name:"secret1" data:"fooobar"
2020-11-21T03:03:01.591811689Z I1121 03:03:01.591663       1 client.go:329]      Received  toResponse: 10cd4b47-2ba6-11eb-b228-0242ac110002
```
#### Firestore

Each clientVM unique vm_id is saved in TokenServer's Firestore database.  Note, the secret is *NOT* encrypted.  Ensure you secure access to FireStore

![images/ts_firestore.png](images/ts_firestore.png)


#### Deterministic Builds using Bazel

You can build the TokenClient and Server images using Bazel 


```bash
cd app/

bazel build --platforms=@io_bazel_rules_go//go/toolchain:linux_amd64 src/client:tokenclient
bazel run --platforms=@io_bazel_rules_go//go/toolchain:linux_amd64 src/client:tokenclient

bazel build --platforms=@io_bazel_rules_go//go/toolchain:linux_amd64 src/server:tokenserver
bazel run --platforms=@io_bazel_rules_go//go/toolchain:linux_amd64 src/server:tokenserver
```

The images will be

```bash
$ docker images
REPOSITORY                                  TAG                    IMAGE ID            CREATED             SIZE

gcr.io/yourproject/tokenclient/src/client   tokenclient            833121004941        50 years ago        20.7MB
gcr.io/yourproject/tokenserver/src/server   tokenserver            c98ed1bc6e27        50 years ago        30.5MB
```

These images will have a consistent image hash no matter where they are built.

Also note that the generated `tokenservice.pb.go` files were pregenerated.  This is to avoid conflicts due to GCP secretsmanager library which automatically
uses pregenerated library set.  See [Use pre-generated .pb.go files](https://github.com/bazelbuild/rules_go/blob/master/proto/core.rst#option-2-use-pre-generated-pbgo-files).

To recompile, comment out the `replace` steps in `app/go.mod`:

```golang
require (
	// tokenservice v0.0.0
)
// replace tokenservice => ./src/tokenservice
```

then import, compile, build with bazel

```bash
bazel run :gazelle -- update-repos -from_file=go.mod -build_file_proto_mode=disable_global
/usr/local/bin/protoc -I ./src/tokenservice --include_imports --include_source_info --descriptor_set_out=src/tokenservice/tokenservice.proto.pb  --go_out=plugins=grpc:./src/tokenservice/ src/tokenservice/tokenservice.proto
```

##### (enhancement) Generating GCP Service account

Provisioning application contained in the default deploy does **NOT** generate and and return a GCP ServiceAccount as the raw RSA material

You can easily embed a JSON GCP Service account witin any of the `Secret`


b. Modify the `provisioner.go` to create a GCP serviceAccount ([Creating service account keys](https://cloud.google.com/iam/docs/creating-managing-service-account-keys#iam-service-account-keys-create-go))
c. Extract *just* the RSA part of the key, remove the passphrase (which by default is `notasecret` on GCP ).  
d. Place the base64encoded Service Account as a `Secret` Data filed


##### Using RawKey for short term tokens

TokenServer does not *have to* return rsa or aes keys at all.  If Alice and Bob agree, the TokenServer can simply return a short term `access_token` directly to the TokenClient.   The Client can use that raw, non-refreshable token to access a GCP resource

The server can also issue a [downscoped Token](https://github.com/salrashid123/downscoped_token)


#### Binding TokenClient Origin IP and Certificate

You can also bind a given TokenClient's IP address to the `ServiceEntry` during provisioning.

What this means is even if a TokenClient connects to the TokenServer over mTLS using a valid certificate, the tokenserver will extract the provided SerialNumber that was provided by the TokenClient
In the default certificate in this repo, the SerialNumber is just `5`.  If you want to generate your own certificates, please see the section in the appendix

```
openssl x509 -in bob/certs/tokenclient.crt -noout -text
ertificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 5 (0x5)
```

The TokenServer will also check the IP address of where this request originated.
What that means is the TokenServer will verify the IP address it got matches the expect IP address set during provisioning

To use this check, add in the `--validatePeerIP --validatePeerSN` flag to the startup Arg for TokenServer:
```golang
	validatePeerIP          = flag.Bool("validatePeerIP", false, "Validate each TokenClients origin IP")
	validatePeerSN          = flag.Bool("validatePeerSN", false, "Validate each TokenClients Certificate Serial Number")
```

Then during Provisioning, you must submit the argument for the `peerSerialNumber` at least and an override value (optional)
```bash
--peerAddress $TF_VAR_tc_address --peerSerialNumber=5
```

The net effect is the firestore `ServiceEntry` now has an entry for these values

```golang
	PeerAddress        string    `firestore:"peer_address"`
	PeerSerialNumber   string    `firestore:"peer_serial_number"`
```

TokenServer `alice/deploy/main.tf`


```bash
    ExecStart=/usr/bin/docker run --rm -u 0 -p 50051:50051 --name=mycloudservice gcr.io/${var.project_id}/tokenserver@${var.image_hash} --grpcport 0.0.0.0:50051 --tsAudience ${var.ts_audience} --useSecrets --tlsCert projects/${var.project_number}/secrets/tls_crt --tlsKey projects/${var.project_number}/secrets/tls_key --tlsCertChain projects/${var.project_number}/secrets/tls-ca  --firestoreProjectId ${var.project_id} --firestoreCollectionName ${var.collection_id} --validatePeerIP --validatePeerSN  --v=20 -alsologtostderr
```

And during provisioning, specify the address for the TokenClient and the certificate serial number:

```bash
$ go run src/provisioner/provisioner.go --fireStoreProjectId $TF_VAR_ts_project_id  \
  --firestoreCollectionName foo     --clientProjectId $TF_VAR_tc_project_id \
  --clientVMZone us-central1-a --clientVMId $TF_VAR_tc_instance_id \
  --peerAddress $TF_VAR_tc_address --peerSerialNumber=5  --secretsFile=secrets.json
```


### Provision with TPM Sealed data

To Seal data to a TPM, you must generate an encoded token, embed it into a Secret and then provision.

The `provision.go` utility provides a way to seal data to the target VM's TPM:

- Seal data to TPM with PCR value:

```bash
go run src/provisioner/provisioner.go --clientProjectId $TF_VAR_tc_project_id \
  --clientVMZone us-central1-a --clientVMId $TF_VAR_tc_instance_id \
  --encryptToTPM="datasealedtotpm"  \
  --pcrValues 0=fcecb56acc303862b30eb342c4990beb50b5e0ab89722449c2d9a73f37b019fe
```
(the PCR=0 value for GCP COS images is `fcecb56acc303862b30eb342c4990beb50b5e0ab89722449c2d9a73f37b019fe`).  You can bind to any other PCR value you choose.  Specify multiple values using formatted as `--pcrValues 0=foo,23=bar`

The optionsl to use for the provisioner in this output only mode are:
| Option | Description |
|:------------|-------------|
| **`-encryptToTPM`** | Seal data to TokenClient's TPM Endorsement Public Key |
| **`-pcrValues`** | PCR bank and value to seal to (SHA256 PCR Values to seal against 0=foo,23=bar) (default: `0=fcecb56acc303862b30eb342c4990beb50b5e0ab89722449c2d9a73f37b019fe`) |

Note, running the the command with the provisioner will just emit the PCR sealed value.  It will NOT write to firestore

Once you have the sealed data, edit  `secrets.json` and add in the TPM seladed data as base64.  Remember ot label the type as `TPM`

```json
[
    {
        "name": "secret1",
        "type": "RAW",
        "data": "Zm9vb2Jhcg=="
    },
    {
        "name": "secret2",
        "type": "TPM",
        "data": "ClsAIHbS8s1nZ9RO/cjwrWJIIbJ+r1RvXSdwz2kLaNW2wTFiB+8YA+3ooGwjjR4OBO9sWYO4i4jDbBehISPXAqSzG4XnHqm0C89zUt+FfdPAtDJAmypWThb/JnsrEoACbjk2PCxZRLESfXwjU+3KFVxiUdHC/igz2D7n2Oy3E4rruCoaa1EKZ3l/teeGeTEpXU4osLPMMmYdAOviGbrbCEw0kVgOuQuSxydnL/ASRCL7G1jQUFEcC/VrBEpj7efCVw8zYp9DR32/VZRV3qN54m0gp1LnIKAOTT50a3SHjpPoUY96mnAhnMfwh6aa7v/JN5gdKTzG2+5JNQZM4bReqEBMOMkiSeorIeOx8fKg3zTkMU4sTIhW7UngpBj0wfPlfsnsZ6GZEWoRccK/29/XOqkbrpH7YOUR1AHPMZShT/748Wt6oQWogxgpQhQ570+1p6Gcz54XhIr6n+jN7K7dTxpOAAgACwAAAIAAIBTk3S+cCtyx7C0Y09sEqmuNLlbZFO+HyLbfupwEnllPABAAINPOonBGOxXG1EIAnOnzaiS+qow3x7HjgUyPMpDl/HZyIigICxIkCAASIPzstWrMMDhisw6zQsSZC+tQteCriXIkScLZpz83sBn+"
    }
]
```

Then provision

```bash
go run src/provisioner/provisioner.go --fireStoreProjectId $TF_VAR_ts_project_id --firestoreCollectionName foo \
    --clientProjectId $TF_VAR_tc_project_id --clientVMZone us-central1-a --clientVMId $TF_VAR_tc_instance_id  \
    --secretsFile=secrets.json
```

>> Some notes about using the TPM to seal data:
  Decryption of TPM based data by the TokenClient is visible by the GCP Hypervisor.  If the threat model why you are using this configuration strictly stipulates that hypervisor cannot read or corrupt VM memory then that would likely mean you also cannot a vTPM.  Note that GCP Confidential Compute instances uses SEV and not SNP.  Please see [AMD SEV-SNP:  Strengthening VM Isolation with Integrity Protection](https://www.amd.com/system/files/TechDocs/SEV-SNP-strengthening-vm-isolation-with-integrity-protection-and-more.pdf)


### Provision with TINK Encryption Key

`Secrets` proto also supports [TINK](https://github.com/google/tink) Keysets.  What that means is you can define an AEAD Tink JSON keyset inline as a secert

```json
[
    {
        "name": "secret1",
        "type": "RAW",
        "data": "Zm9vb2Jhcg=="
    },
    {
        "name": "secret2",
        "type": "TINK",
        "data": "CLnwmtYGEmQKWAowdHlwZS5nb29nbGVhcGlzLmNvbS9nb29nbGUuY3J5cHRvLnRpbmsuQWVzR2NtS2V5EiIaIA7TocwCm37/3vReEGSRsoSp+a0KAq+KYEKqKH5dVqC4GAEQARi58JrWBiAB"
    }
]
```

And then use that to decrypt data.  For example, the following snippet uses an AEAD TINK key to encrypt and decrypt some data

- Tink [encrypt/decrypt](https://gist.github.com/salrashid123/d943846f4512226fa3e5803749c7371f)

Also, depending on the security model you are using (i.e, you entrust google with the key but not the tokenclient's owner), you can also emit the AEAD key as a BigQuery decryption key as described here and in the command line equivalent below:

- [AEAD encryption concepts in Standard SQL](https://cloud.google.com/bigquery/docs/reference/standard-sql/aead-encryption-concepts#advanced_encryption_standard_aes)


```bash
bq  query \
--parameter=keyset1::CLnwmtYGEmQKWAowdHlwZS5nb29nbGVhcGlzLmNvbS9nb29nbGUuY3J5cHRvLnRpbmsuQWVzR2NtS2V5EiIaIA7TocwCm37/3vReEGSRsoSp+a0KAq+KYEKqKH5dVqC4GAEQARi58JrWBiAB \
--use_legacy_sql=false  'SELECT
  ecd1.customer_id as ecd1_cid
FROM mineral-minutia-820.aead.EncryptedCustomerData AS ecd1
WHERE AEAD.DECRYPT_STRING(FROM_BASE64(@keyset1),
  ecd1.encrypted_animal,
  "somedata") = "liger";'
```


### TPM Quote/Verify and Unrestricted Signing Key

The default protocol included in this repo also performs three optional TPM based flows:

* `Quote/Verify`
  This allows the TokenClient to issue an Attestation Key which the TokenServer can save. THis Key can be used to repeatedly verify PCR values resident on the Token Client

* `Restricted Signing Key (Attestation Key based signing)`:
   Use the Attestation Key to sign some data. The TPM will only sign data that has been Hashed by the TPM itself.

* `Unrestricted Signing Key`
   Normally, the AK cannot sign any arbitrary data (it is a restricted key). Instead, the TokenClient can generate a new RSA key on the TPM where the private key is always on the tpm. Once thats done, the AK can sign it and return the public part to the Token Server. Since the Endorsement Key and Attestation key were now associated together, the new unrestricted key can also be indirectly associated with that specific TokenClient. The TokenClient can now sign for any arbitrary data, send it to the TokenServer which can verify its authenticity by using the public key previously sent

These flows are enabled by the TokenClient by starting up by setting

- TokenClient: `--useTPM --doAttestation --exchangeSigningKey`

| Option | Description |
|:------------|-------------|
| **`-useTPM`** | Enable TPM operations |
| **`-doAttestation`** | Start offer to Make/Activate Credential flow |
| **`-exchangeSigningKey`** | Offer RSA Signing Key (requires --doAttestation) |

- TokenServer `--useTPM --expectedPCRValue=fcecb56acc303862b30eb342c4990beb50b5e0ab89722449c2d9a73f37b019fe --pcr=0` 

| Option | Description |
|:------------|-------------|
| **`-useTPM`** | Enable TPM operations |
| **`-expectedPCRValue`** | ExpectedPCRValue from Quote/Verify (default: `PCR 0:  fcecb56acc303862b30eb342c4990beb50b5e0ab89722449c2d9a73f37b019fe`) |
| **`-pcr`** | PCR Bank to use for quote/verify (default: `0`) |

- Provisioner `--useTPM --attestationPCR=0 --attestationPCRValue=fcecb56acc303862b30eb342c4990beb50b5e0ab89722449c2d9a73f37b019fe`

| Option | Description |
|:------------|-------------|
| **`-useTPM`** | Enable TPM operations |
| **`-attestationPCR`** | PCR Bank to use for Attestation (default: `0`) |
| **`-attestationPCRValue`** | PCR Bank value Attestation (default: `fcecb56acc303862b30eb342c4990beb50b5e0ab89722449c2d9a73f37b019fe`) |

![images/quoteverify.png](images/quoteverify.png)

If these options are enabled, the tokenserver will have an RSA key that is attested and bound to the TokenClient.  The TokenClient can then sign arbitrary data using its vTPM. The TokenServer will have the public portion of that key to cryptographically verify.

On TokenClient
![images/tc_unrestricted.png](images/tc_unrestricted.png)

On TokenServer
![images/ts_unrestricted.png](images/ts_unrestricted.png)

### Logs

The following files details the full end-to-end logs:

- TokenClient
- [logs/client_log.md](logs/client_log.md)

- TokenServer
- [logs/server_log.md](logs/server_log.md)


### Appendix

#### No externalIP
  Bob can also start  the VM without an external IP using the `--no-network` flag but it makes this tutorial much more complicated to 'invoke' Bob's VM to fetch secrets.  However, using a NAT Gateway to contact the tokenserver will invalidate and waken the `validatePeerIP` check.

  If a NAT Gateway is NOT used and each tokenclient connects to the server, Alice can add a firewall rule to only allow the set of egress IP addresses per tokenClient.

#### Enhancements

Further enhancements can be to use 
* [VPC-SC](https://cloud.google.com/vpc-service-controls):  This will ensure only requests originating from whitelisted projects and origin IPs are allowed API access to Alices GCS objects.  However, cross-orginzation VPC-SC isn't something i think is possible at the mment.  If Bob sets up a NAT egress endpoint, Alice can define a VPC prerimeter to include that egress

* [Organizational Policy](https://cloud.google.com/resource-manager/docs/organization-policy/org-policy-constraints): Bob's orgianzation can have restrictions on the type of VM and specifications Bob can start (eg, ShieldedVM, OSLogin).  

* [IAM Conditions](https://cloud.google.com/iam/docs/conditions-overview):  You can enable IAM conditions on any of the GCP resources in question. Since Alice and Bob are using GCP, you can place a condition on when the TokenService or on the GCS bucket or on Alice's ability to view the VM or logging metadata.

* [OS Config Agent](https://cloud.google.com/compute/docs/manage-os):  You can also install the OS config agent on the VM.  This agent will report specifications of the packages installed on the VM.  However, this agent can also be configured to [update packages](https://cloud.google.com/compute/docs/os-config-management) by the VM's admin by updating its metadata from outside the VM.  If you do not want Bob to dynamically update a packages on the VM, do not enable this feature.

#### EndToEnd Encryption
  
  The reason the protocol shows both AES and RSA keys is you an use both to achieve end-to-end encryption.
  
  For example, 
  * Encrypt the GCS file with AES key:
    the data that Alice has on the GCS bucket can be wrapped with an AES key on top of what Google Provides.
    Even if anyone got hold of the secret file, it would be encrypted anyway.  Bob can only decrypt it if he gets the AES key.
    You can go further with this and distribute keys that are infact part of [Shamirs Secret Sharing](https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing)

  * Encrypt PubSub message payload with key wrapping
    Alice can also encrypt pubsub message data with her encryption key and send that to the TokenServer.
    Alice could then post encrypted messages to a topic the TokenServer subscribes to.  The messages in transit and as far as Google or anyone is concerned, is
    encrypted at the application layer.  The TokenServer is the only system that can decrypt the message.  For more information, see
    [Message Payload Encryption in Google Cloud PubSub (Part 1: Shared Secret)](https://github.com/salrashid123/gcp_pubsub_message_encryption/tree/master/1_symmetric)
    
  * Mount Persistent Disk with LUKS encryption:
    - [LUKS on COS with](https://gist.github.com/salrashid123/008371c75e303727214c1012939a0ace)
    - [LUKS on COS with Loopback](https://gist.github.com/salrashid123/c9a8e59b86e41329dd8f2052a38915f5)
    - [https://github.com/salrashid123/gcp_luks_csek_disks](https://github.com/salrashid123/gcp_luks_csek_disks)
    

#### Using preexisting projects

You can bootstrap this system using your own existing project, see the steps detaled in the `gcloud_steps/` folder

#### Generating your own Certificates

This repo includes mTLS certificates that were pre-generated with specific SNI values.

```
openssl x509 -in alice/certs/tokenservice.crt -noout -text
        X509v3 extensions:
            X509v3 Subject Alternative Name: 
                DNS:tokenservice.esodemoapp2.com
```

If you want to use a different DNS SAN value or create a CA from scratch, see [Create Root CA Key and cert](https://github.com/salrashid123/ca_scratchpad).

#### Automated Testing

TODO:

- Allow cloud build "project creator" and "billing admin IAM rights
  `project_number@cloudbuild.gserviceaccount.com`

- see `test/cloudbuild.yaml`


