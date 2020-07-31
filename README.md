## Remote Authorization and TokenDistributor for GCP VMs

Sample workflow to distribute a secret between two parties where one party directly delivers the secret to a _specific_, deprivileged virtual machine on GCP.  Normally when two parties want to share some data, one party grants IAM permissions on that resource to an identity owned by the other.  That is, if Alice wants to share data with a VM Bob owns,  Alice will grant IAM permissions on some data with the ServiceAccount Bob's VM runs as.  However, Bob essentially has indirect rights on that data simply by assuming the identity of the service account or by simply ssh into that VM and acquiring the service account credentials.  

This is problematic in some situations where Alice would like Bob's VM to process data in isolation but not alow Bob himself from acquiring that data and exfilterating.

The flow described in this repo flow inverts the access where the data owner (Alice) shares some secret material with permissions to sensitive data but **ONLY** to a isolated system owned by Bob.  The data owner (Alice) will share access _exclusively__ to the VM only after attesting some known binary that Alice is aware of and trusts is running on that VM and that that Bob cannot access the VM via SSH or any other means.

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

Provisioning Server creates `RSAKey-A`, `AESKey-A`.   RSAKeyA maybe a GCP ServiceAccount Key.

Provisioning Server uses `VM-A`'s TPM based data to seal RSA and AES key.

Provisioning server encrypts RSA and AES key with `VM-B` TPM.

Provisioning Server generates hash of `VM-B` startup script that includes commands to prevent SSH and `docker run` command for the trusted image image.

Provisioning Server saves encrypted RSA/AES keys, hash of startupscript to Google FireStore using the `instance_id` for `VM-B` as the primary key
  

`VM-B` contacts `TokenService`

`VM-B` uses its [instance_identity_document](https://cloud.google.com/compute/docs/instances/verifying-instance-identity#verify_signature) as an auth token to call `VM-A`

`VM-A` verifies the `identity document` is signed by Google

`VM-A` checks `instanceID`, `serviceAccount`, `audience` and other claims in the document.

`VM-A` looks up Firestore using the `instanceID` as  the key.

`VM-A` uses GCP Compute API to retrieve the current/active startup script for `VM-B`

`VM-A` compares the hash of the retrieved startup script against the value in Firestore previously authorized.  If mismatch, return error.

`VM-A` returns encrypted RSA/AES key to `VM-B`

`VM-B` uses its TPM to decrypt RSA and AES key

If RSA key is a GCP Service Account, use that to download data from Google Services.  
The AES/RSA key can be from any provider  (AWS/Azure, etc) or really any arbitrary secret

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
  `gcloud organzations list`
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
    ts_image_hash = sha256:d15fca0990db0e106cae91e975c3093fed96131250702cdd7db1d45ca77e1c21
    ts_project_id = ts-de7f98d5
    ts_project_number = 973084368812
    ts_service_account = tokenserver@ts-de7f98d5.iam.gserviceaccount.com
```

**Provide Bob the values of `ts_address` and `ts_service_account` variables anytime later**

```bash
export TF_VAR_ts_project_id=`terraform output -state=terraform.tfstate ts_project_id`
export TF_VAR_ts_service_account=`terraform output -state=terraform.tfstate ts_service_account`
export TF_VAR_ts_address=`terraform output -state=terraform.tfstate ts_address`

echo $TF_VAR_ts_project_id
echo $TF_VAR_ts_service_account
echo $TF_VAR_ts_address
```

In this case its

```bash
$ echo $TF_VAR_ts_service_account
  tokenserver@ts-de7f98d5.iam.gserviceaccount.com

$ echo $TF_VAR_ts_address
  35.239.36.219
```

### Deploy TokenService (Alice)

Deploy the TokenService with defaults.  The command below will deploy an _unconfigured_ TokenServer with a static IP address (`TF_VAR_ts_address`)

```
terraform apply --target=module.ts_deploy -auto-approve
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
    tc_image_hash = sha256:661f10eeaf66af697a1d463ad6db2467b2ef990277cf85b0d40a53b239391704
    tc_project_id = tc-16a39413
    tc_project_number = 538014872919
    tc_service_account = tokenclient@tc-16a39413.iam.gserviceaccount.com
```

### Deploy TokenClient (Bob)

Bob will now deploy the TokenClient

Bob needs to set some additional environment variables that were *provided by Alice* earlier:

* `TF_VAR_ts_service_account`:  this is the service account Alice is using for the TokenServer (`tokenserver@ts-039e6b6a.iam.gserviceaccount.com`)
* `TF_VAR_ts_address`: this is the IP address of the TokenServer (`34.72.145.220`)
* `TF_VAR_ts_provisioner`: this is Alice's email address that Bob will authorize to read the TokenClients metadata values (`alice@esodemoapp2.com`)

Make sure the env vars are set (`TF_VAR_project_id` would be the the TokenClient (Bob) project)

>> this step is really important <<<

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

You should see an output like:

```bash
      Outputs:
      tc_address = 35.193.246.123
      tc_image_hash = sha256:661f10eeaf66af697a1d463ad6db2467b2ef990277cf85b0d40a53b239391704
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

echo $TF_VAR_tc_project_id
echo $TF_VAR_tc_instance_id
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
export TF_VAR_ts_project_id=`terraform output -state=terraform.tfstate ts_project_id`

echo $TF_VAR_tc_project_id
echo $TF_VAR_tc_instance_id
echo $TF_VAR_ts_project_id

$ cd app/
$ go run src/provisioner/provisioner.go --fireStoreProjectId $TF_VAR_ts_project_id --firestoreCollectionName foo     --clientProjectId $TF_VAR_tc_project_id --clientVMZone us-central1-a --clientVMId $TF_VAR_tc_instance_id --sealToPCR=0 --sealToPCRValue=fcecb56acc303862b30eb342c4990beb50b5e0ab89722449c2d9a73f37b019fe

```

NOTE, `PCR=0` on COS instances has the default `sha256` startup value of `fcecb56acc303862b30eb342c4990beb50b5e0ab89722449c2d9a73f37b019fe`.  You can pick any other PCR or customize it for any other VM you use instead of COS.
See [Integrity Monitoring](https://cloud.google.com/security/shielded-cloud/shielded-vm#integrity-monitoring)

Using [tpm2_tools](https://github.com/tpm2-software/tpm2-tools) on a GCP VM:

```bash
$ tpm2_pcrread sha1:0 
sha1:
  0 : 0x51C323DE0C0C694F4601CDD02BEB58FF13629F74

$ echo 51C323DE0C0C694F4601CDD02BEB58FF13629F74 | xxd -r -p | base64
UcMj3gwMaU9GAc3QK+tY/xNin3Q=

$ tpm2_pcrread sha256:0 
sha256:
  0 : 0xFCECB56ACC303862B30EB342C4990BEB50B5E0AB89722449C2D9A73F37B019FE
```

Gives the sha1 PCR value:

![images/pcr0.png](images/pcr0.png)

The output of the provisioning step will prompt Alice to confirm that the image startup script and metadata looks valid.

At that point, the image hash value will be saved into Firestore `R0OB1dVupyp/rNcb2/5Bfrx9uKjdjDNAPM9kUS7UiaI=`  using the `vm_id=2503055333933721897` in firestore document key.  Every time the TokenClient makes a request for a security token, the TokenServer will lookup the document and verify the image hash is still the one that was authorized.

The output also shows the unique `Fingerprint` of the VM `2020/07/22 09:47:32 Image Fingerprint: [yM8bKId-VQA=]`.  Eventually this data should also get saved into Firestore and validated by the TokenServer.

```
2020/06/23 09:47:32 tc-16a39413  us-central1-a  7953211237324536786
2020/06/23 09:47:32 Found  VM instanceID "7953211237324536786"
2020/06/23 09:47:32 Found s VM ServiceAccount "tokenclient@tc-16a39413.iam.gserviceaccount.com"
2020/06/23 09:47:32 Image Data: #cloud-config

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
    ExecStart=/usr/bin/docker run --rm -u 0 --device=/dev/tpm0:/dev/tpm0 --name=mycloudservice gcr.io/tc-16a39413/tokenclient@sha256:661f10eeaf66af697a1d463ad6db2467b2ef990277cf85b0d40a53b239391704 --address 35.239.242.219:50051 --servername tokenservice.esodemoapp2.com --tsAudience https://tokenserver --useSecrets --tlsClientCert projects/538014872919/secrets/tls_crt --tlsClientKey projects/538014872919/secrets/tls_key --tlsCertChain projects/538014872919/secrets/tls-ca --doAttestation --exchangeSigningKey --v=20 -alsologtostderr
    ExecStop=/usr/bin/docker stop mycloudservice
    ExecStopPost=/usr/bin/docker rm mycloudservice

bootcmd:
- iptables -D INPUT -p tcp -m tcp --dport 22 -j ACCEPT
- systemctl mask --now serial-getty@ttyS0.service

runcmd:
- systemctl daemon-reload
- systemctl start cloudservice.service

2020/06/23 09:47:32 ImageStartup Hash: [Kwmp//kyXrJQUCw3tzVu0ydSZrQa1ehLdVRQ9wEm4Jo=]
2020/07/22 09:47:32 Image Fingerprint: [yM8bKId-VQA=]
2020/06/23 09:47:33 Derived EKPub for Instance:
2020/06/23 09:47:33 -----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAy8Fz/K9LNhF2Ir0b7uGW
pFFZwnPXUk9e6Jp/+4ZblZKGj/F63Wp5mVbsL/aeJ7OELg0TLmMCxTQC5wLpH/39
/uR9R826PuiYOvs7Fbj5DdE6DLq4sNvrRu5uwzp4Ho60xx46wuH8BF7P+bVS7m/u
1nmFLJwAoMPsgEmMonHQyRd4BNzjYThUdP68muy47tngASOsqtbXP4H99U6bwes1
aPqAe/3Tbc4f6kDg7QqqgKRBAjJowVhydnCgCEud7KVBisIBgjmBhoRGoISUBIDv
HQd5D5afIdOd9ni1sHfaTFW35TBvtgkgsJwcFIptP7IhTaQzDrkQ4ZdpzBK/JjxX
uwIDAQAB
-----END PUBLIC KEY-----
2020/06/23 09:47:33 looks ok? (y/N): 
y
2020/06/23 09:47:34 Generating RSA Key
2020/06/23 09:47:35 Sample control Signed data: Cln+uxlGriFF4oVqI0kPGIQjLr9gT+MDtLzScj/2xPlfZxjyjNJ5r2g3I8bNgnv48znYx9BggGnz3EbojZMmJMRNorl3YEXYX9tnTdMRE46LZ+xVcms7/fmB9tpqdG7lhtD5QNUPU69HMbW7x44qv2g2t1sAFFSXMtzy1JS2N48HgFQn9LOa2mqBh7OwW4KpF1KD8eVDnlFRa5n4jPEZTWOGk74B4pbVKpbRuEGp6lh3lVBkHM+s3q4D3JDiWkBLGamTfw1+wlTPmWRKWqfcnNqb2k4sj3yRwVHN46wYaJZWqoCW8lkoL9Juz3G489hnYMugMPseZpXevtZrUOhaIg
2020/06/23 09:47:35 Generating AES Key
2020/06/23 09:47:35 Sealed AES Key with hash: OUpYGm7Vwr48Yv6bj8e4i/CJazCcgmtB1eQFhUSLIww=
2020/06/23 09:47:35 2020-06-23 13:47:35.863366 +0000 UTC
2020/06/23 09:47:36 Document data: "7953211237324536786"
```

Note, there is also a terraform module included here to _automatically_ process requests and only designed for use with automated testing (not actual production use!)

To use that, first compile the provisioner

```bash
cd app/
go build -o provisioner src/provisioner/provisioner.go
```

then invoke it
```
terraform apply --target=module.ts_provisioner -auto-approve
```
Note, the autoprovisioner approves any and all requests...If you want to use this in real life, you must bake in logic to the approval process in the provisioner to check for signals (eg a "golden" image hash, sourceIP, project, tec)

#### After Provisioning

After provisioning, the full sequence to exchange encrypted keys takes place.  In addition, remoteAttestation (quote/verify) and TPM signing key is transmitted from the client to the server

- TokenServer

The TokenServer output shows that it successfully authorized the specific TokenClient and returned given the credentials and which matched with a _live_ lookup of the VMid's metadata.   Since the default script here perform the additional steps of Quote/Verify, you should see the final step of returning the key back (eg `Return ProvideSigningKeyResponse`)

![images/tscomplete.png](images/tscomplete.png)

- TokenClient

The TokenClient would have acquired the secret key and then performed the optional quote/verify step.  The final step for the Client would be to save the key material to memory and start an arbitrary worker thread that would use the secrets.

![images/tccomplete.png](images/tccomplete.png)


#### Firestore

Each clientVM unique vm_id is saved in TokenServer's Firestore database

The AES and RSA keys intended for the client VM is encrypted using the client VM's _own_ TPM EkPub

![images/ts_firestore.png](images/ts_firestore.png)

#### mTLS or ALTS

Both alice and bob must decide upfront if they wish to use mTLS or ALTS (Application Layer Transport Security) for encryption and in the case of ALTS, supplemental authentication.  ALTS only works on GCP at the moment so mTLS is applicable if Alice runs the TokenServer onprem.   The default value is mTLS in this example.

the `main.tf` files for both Alice and Bob have the cloud-init configuration for ALTS commented out.  To use alts, redeploy the service on both ends using the commented versions.

- For reference, see [grpc_alts](https://github.com/salrashid123/grpc_alts)

If mTLS is uses, the issue of key distribution and security of the TLS keys becomes an issue.  The TLS aspect here is used for confidentiality mostly since API requests are always authenticated (using bob's oidc token) and the raw RSA/AES keys that do get transmitted are encrypted such that it can only get decrypted by the TokenClient's vTPM.

#### (enhancement) Generating GCP Service account

Provisioning application contained in the default deploy does **NOT** generate and and return a GCP ServiceAccount as the raw RSA material

Supporting GCP ServiceAccounts is still a TODO:

tasks involved in doing that:

a. Modify the TokenResponse proto When TokenClient receives the to include the KeyID serviceAccountName 

```proto
message TokenResponse {
  string responseID = 1;
  string inResponseTo = 2;
  bytes sealedRSAKey = 3;
  bytes sealedAESKey = 4;
  int64 pcr = 5;
  string resourceReference = 6;
  string serviceAccountKeyId = 7;
  string serviceAccountEmail = 8;
}
```

b. Modify the `provisioner.go` to create a GCP serviceAccount ([Creating service account keys](https://cloud.google.com/iam/docs/creating-managing-service-account-keys#iam-service-account-keys-create-go))
c. Extract *just* the RSA part of the key, remove the passphrase (which by default is `notasecret` on GCP ).  
d. Use TokenClient's TPM to save that as the `sealedRSAKey`, isave the keyID and serviceAccountEmail value

e. TokenClient will embed the `sealedRSAKey` to the TPM and use that to generate GCP access_tokens as described here:

- [oauth2.TPMTokenSource](https://github.com/salrashid123/oauth2#usage-tpmtokensource)


#### (enhancement) Transmitting short term token

TokenServer does not *have to* return rsa or aes keys and involve a tpm at all.  If Alice and Bob agree, the TokenServer can simply return a short term `access_token` directly to the TokenClient.   The Client can use that raw, non-refreshable token to access a GCP resource

The server can also issue a [downscoped Token](https://github.com/salrashid123/downscoped_token)

To support this, the TokenResponse proto would include just the token and maybe its expiration time
```proto
message TokenResponse {
  string responseID = 1;
  string inResponseTo = 2;
  string access_token = 3;
  int64  expire_at = 4;
}
```

#### (tofix) Concurrent access to TPM

TokenClient and TokenServer access the local TPM for various operations.  This device on GCP is at `/dev/tpm0` and cannot be accessed concurrently by various processes.  

TODO: perform locking 

#### TPM Quote/Verify and Unrestricted Signing Key

The default protocol included in this repo also performs three optional TPM based flows:

* Quote/Verify:  this allows the TokenClient to issue an Attestation Key which the TokenServer can save.  THis Key can be used to repeatedly verify PCR values resident on the Token Client
* Restricted Signing Key (Attestation Key based signing).  Use the Attestation Key to sign some data.  The TPM will only sign data that has been Hashed by the TPM itself.
* Unrestricted Signing Key: Normally, the AK cannot sign any arbitrary data (it is a restricted key).  Instead, the TokenClient can generate a new RSA key on the TPM where the private key is **always** on the tpm. Once thats done, the AK can sign it and return the public part to the Token Server.  Since the Endorsement Key and Attestation key were now associated together, the new unrestricted key can also be indirectly associated with that specific TokenClient.  The TokenClient can now sign for any arbitrary data, send it to the TokenServer which can verify its authenticity by using the public key previously sent

These flows are enabled by the `TokenClient` by starting up the client with the `--doAttestation` flag. 

![images/quoteverify.png](images/quoteverify.png)



## Appendix

### No externalIP
  Bob can also start  the VM without an external IP using the `--no-network` flag but it makes this tutorial much more complicated to 'invoke' Bob's VM to fetch secrets...I just left it out.

## Enhancements

Further enhancements can be to use 
* [VPC-SC](https://cloud.google.com/vpc-service-controls):  This will ensure only requests originating from whitelisted projects and origin IPs are allowed API access to Alices GCS objects.  However, cross-orginzation VPC-SC isn't something i think is possible at the mment.  If Bob sets up a NAT egress endpoint, Alice can define a VPC prerimeter to include that egress
* [Organizational Policy](https://cloud.google.com/resource-manager/docs/organization-policy/org-policy-constraints): Bob's orgianzation can have restrictions on the type of VM and specifications Bob can start (eg, ShieldedVM, OSLogin).  

* `IAM Tuning`: You can tune the access on both Alice and Bob side further using the IAM controls available.  For more information, see [this repo](https://github.com/salrashid123/restricted_security_gce)

* [IAM Conditions](https://cloud.google.com/iam/docs/conditions-overview):  You can enable IAM conditions on any of the GCP resources in question. Since Alice and Bob are using GCP, you can place a condition on when the TokenService or on the GCS bucket or on Alice's ability to view the VM or logging metadata.

* [OS Config Agent](https://cloud.google.com/compute/docs/manage-os):  You can also install the OS config agent on the VM.  This agent will report specifications of the packages installed on the VM.  However, this agent can also be configured to [update packages](https://cloud.google.com/compute/docs/os-config-management) by the VM's admin by updating its metadata from outside the VM.  If you do not want Bob to dynamically update a packages on the VM, do not enable this feature.

## EndToEnd Encryption
  
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
    - [https://github.com/salrashid123/gcp_luks_csek_disks](https://github.com/salrashid123/gcp_luks_csek_disks)
    - [tpm2_software Disk Encryption](https://tpm2-software.github.io/2020/04/13/Disk-Encryption.html)
    - [WIP: [RFC] Add TPM2 support](https://gitlab.com/cryptsetup/cryptsetup/-/merge_requests/51)
    


## Automated Testing

TODO:

- Allow cloud build "project creator" and "billing admin IAM rights
  `project_number@cloudbuild.gserviceaccount.com`

- see `test/cloudbuild.yaml`


