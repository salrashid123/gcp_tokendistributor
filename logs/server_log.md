### Sample TokenServer log
(in reverse order)


```log
...
...

I0622 12:04:13.242025       1 server.go:228]      Looking up Firestore Collection foo for instanceID 8939838129032687278
E0622 12:04:13.304228       1 server.go:238] ERROR:  Could not find instanceID new Firestore Client 8939838129032687278
I0622 12:04:23.239553       1 server.go:174]      Found OIDC KeyID  19fe2a7b6795239606ca0a750794a7bd9fd95961
E0622 12:04:23.239870       1 server.go:187]      OIDC doc has Audience [https://tokenserver]   Issuer [https://accounts.google.com] and SubjectEmail [tokenclient@tc-4f4f5a70.iam.gserviceaccount.com]
I0622 12:04:23.239918       1 server.go:225]    Instance Confidentiality Status 0
I0622 12:04:23.239933       1 server.go:228]      Looking up Firestore Collection foo for instanceID 8939838129032687278
E0622 12:04:23.276278       1 server.go:238] ERROR:  Could not find instanceID new Firestore Client 8939838129032687278
I0622 12:04:33.242268       1 server.go:174]      Found OIDC KeyID  19fe2a7b6795239606ca0a750794a7bd9fd95961
E0622 12:04:33.242393       1 server.go:187]      OIDC doc has Audience [https://tokenserver]   Issuer [https://accounts.google.com] and SubjectEmail [tokenclient@tc-4f4f5a70.iam.gserviceaccount.com]
I0622 12:04:33.242405       1 server.go:225]    Instance Confidentiality Status 0
I0622 12:04:33.242413       1 server.go:228]      Looking up Firestore Collection foo for instanceID 8939838129032687278
E0622 12:04:33.320132       1 server.go:238] ERROR:  Could not find instanceID new Firestore Client 8939838129032687278
I0622 12:04:43.239985       1 server.go:174]      Found OIDC KeyID  19fe2a7b6795239606ca0a750794a7bd9fd95961
E0622 12:04:43.240301       1 server.go:187]      OIDC doc has Audience [https://tokenserver]   Issuer [https://accounts.google.com] and SubjectEmail [tokenclient@tc-4f4f5a70.iam.gserviceaccount.com]
I0622 12:04:43.240321       1 server.go:225]    Instance Confidentiality Status 0
I0622 12:04:43.240350       1 server.go:228]      Looking up Firestore Collection foo for instanceID 8939838129032687278
E0622 12:04:43.299306       1 server.go:238] ERROR:  Could not find instanceID new Firestore Client 8939838129032687278
I0622 12:04:53.239040       1 server.go:174]      Found OIDC KeyID  19fe2a7b6795239606ca0a750794a7bd9fd95961
E0622 12:04:53.240475       1 server.go:187]      OIDC doc has Audience [https://tokenserver]   Issuer [https://accounts.google.com] and SubjectEmail [tokenclient@tc-4f4f5a70.iam.gserviceaccount.com]
I0622 12:04:53.240574       1 server.go:225]    Instance Confidentiality Status 0
I0622 12:04:53.241036       1 server.go:228]      Looking up Firestore Collection foo for instanceID 8939838129032687278
E0622 12:04:53.288728       1 server.go:238] ERROR:  Could not find instanceID new Firestore Client 8939838129032687278
I0622 12:05:03.240161       1 server.go:174]      Found OIDC KeyID  19fe2a7b6795239606ca0a750794a7bd9fd95961
E0622 12:05:03.241146       1 server.go:187]      OIDC doc has Audience [https://tokenserver]   Issuer [https://accounts.google.com] and SubjectEmail [tokenclient@tc-4f4f5a70.iam.gserviceaccount.com]
I0622 12:05:03.241178       1 server.go:225]    Instance Confidentiality Status 0
I0622 12:05:03.241657       1 server.go:228]      Looking up Firestore Collection foo for instanceID 8939838129032687278
E0622 12:05:03.303551       1 server.go:238] ERROR:  Could not find instanceID new Firestore Client 8939838129032687278
I0622 12:05:13.242427       1 server.go:174]      Found OIDC KeyID  19fe2a7b6795239606ca0a750794a7bd9fd95961
E0622 12:05:13.242641       1 server.go:187]      OIDC doc has Audience [https://tokenserver]   Issuer [https://accounts.google.com] and SubjectEmail [tokenclient@tc-4f4f5a70.iam.gserviceaccount.com]
I0622 12:05:13.242682       1 server.go:225]    Instance Confidentiality Status 0
I0622 12:05:13.242698       1 server.go:228]      Looking up Firestore Collection foo for instanceID 8939838129032687278
E0622 12:05:13.306178       1 server.go:238] ERROR:  Could not find instanceID new Firestore Client 8939838129032687278
I0622 12:05:23.239789       1 server.go:174]      Found OIDC KeyID  19fe2a7b6795239606ca0a750794a7bd9fd95961
E0622 12:05:23.244237       1 server.go:187]      OIDC doc has Audience [https://tokenserver]   Issuer [https://accounts.google.com] and SubjectEmail [tokenclient@tc-4f4f5a70.iam.gserviceaccount.com]
I0622 12:05:23.244271       1 server.go:225]    Instance Confidentiality Status 0
I0622 12:05:23.244285       1 server.go:228]      Looking up Firestore Collection foo for instanceID 8939838129032687278
I0622 12:05:23.284710       1 server.go:249]      TLS Peer IP Check
I0622 12:05:23.284809       1 server.go:261]     Verified PeerIP 34.121.225.36:41564
I0622 12:05:23.285306       1 server.go:277]      Using mTLS Client cert Peer IP and SerialNumber
I0622 12:05:23.285360       1 server.go:286]      Client Peer Address [34.121.225.36:41564] - Subject[tokenclienta@otherdomain.com] - SerialNumber [5] Validated
I0622 12:05:23.285597       1 server.go:297]      Looking up InstanceID using GCE APIs for instanceID 8939838129032687278
I0622 12:05:23.496755       1 server.go:313]      Found  VM instanceID "8939838129032687278"
I0622 12:05:23.496788       1 server.go:314]      Found  VM CreationTimestamp "2021-06-22T04:57:59.255-07:00"
I0622 12:05:23.496801       1 server.go:315]      Found  VM Fingerprint "sSHMqlnfdVM="
I0622 12:05:23.496812       1 server.go:316]      Found  VM CpuPlatform "AMD Rome"
I0622 12:05:23.496822       1 server.go:319]      Found  VM ServiceAccount "tokenclient@tc-4f4f5a70.iam.gserviceaccount.com"
I0622 12:05:23.496835       1 server.go:325]      Found Registered External IP Address: 34.121.225.36
I0622 12:05:23.496852       1 server.go:336]      Found  VM Boot Disk Source "https://www.googleapis.com/compute/v1/projects/tc-4f4f5a70/zones/us-central1-a/disks/tokenclient"
I0622 12:05:23.802459       1 server.go:351]     Found Disk Image https://www.googleapis.com/compute/v1/projects/cos-cloud/global/images/cos-stable-81-12871-119-0
I0622 12:05:23.802546       1 server.go:363]      Derived Image Hash from metadata v7SftwlRj75WRXCq0Q/buov8D7t+Sg08fRqaylohfiI=
I0622 12:05:23.802564       1 server.go:395] ======= GetToken ---> 1f641610-d352-11eb-b51d-0242ac110002
I0622 12:05:23.802573       1 server.go:401]      Got rpc: RequestID 1f641610-d352-11eb-b51d-0242ac110002 for subject 114199941857925684534 and email tokenclient@tc-4f4f5a70.iam.gserviceaccount.com for instanceID 8939838129032687278
I0622 12:05:23.802699       1 server.go:419] <<<--- GetToken ======= 1f641610-d352-11eb-b51d-0242ac110002
I0622 12:05:24.313630       1 server.go:174]      Found OIDC KeyID  19fe2a7b6795239606ca0a750794a7bd9fd95961
E0622 12:05:24.313981       1 server.go:187]      OIDC doc has Audience [https://tokenserver]   Issuer [https://accounts.google.com] and SubjectEmail [tokenclient@tc-4f4f5a70.iam.gserviceaccount.com]
I0622 12:05:24.314007       1 server.go:225]    Instance Confidentiality Status 0
I0622 12:05:24.314019       1 server.go:228]      Looking up Firestore Collection foo for instanceID 8939838129032687278
I0622 12:05:24.365365       1 server.go:249]      TLS Peer IP Check
I0622 12:05:24.365402       1 server.go:261]     Verified PeerIP 34.121.225.36:41564
I0622 12:05:24.365443       1 server.go:277]      Using mTLS Client cert Peer IP and SerialNumber
I0622 12:05:24.365559       1 server.go:286]      Client Peer Address [34.121.225.36:41564] - Subject[tokenclienta@otherdomain.com] - SerialNumber [5] Validated
I0622 12:05:24.365610       1 server.go:297]      Looking up InstanceID using GCE APIs for instanceID 8939838129032687278
I0622 12:05:24.572894       1 server.go:313]      Found  VM instanceID "8939838129032687278"
I0622 12:05:24.573003       1 server.go:314]      Found  VM CreationTimestamp "2021-06-22T04:57:59.255-07:00"
I0622 12:05:24.573147       1 server.go:315]      Found  VM Fingerprint "sSHMqlnfdVM="
I0622 12:05:24.573171       1 server.go:316]      Found  VM CpuPlatform "AMD Rome"
I0622 12:05:24.573237       1 server.go:319]      Found  VM ServiceAccount "tokenclient@tc-4f4f5a70.iam.gserviceaccount.com"
I0622 12:05:24.573254       1 server.go:325]      Found Registered External IP Address: 34.121.225.36
I0622 12:05:24.573267       1 server.go:336]      Found  VM Boot Disk Source "https://www.googleapis.com/compute/v1/projects/tc-4f4f5a70/zones/us-central1-a/disks/tokenclient"
I0622 12:05:24.746076       1 server.go:351]     Found Disk Image https://www.googleapis.com/compute/v1/projects/cos-cloud/global/images/cos-stable-81-12871-119-0
I0622 12:05:24.746150       1 server.go:363]      Derived Image Hash from metadata v7SftwlRj75WRXCq0Q/buov8D7t+Sg08fRqaylohfiI=
I0622 12:05:24.746183       1 server.go:430] ======= MakeCredential ======== 40adda5d-3879-4e2b-8c47-5c459d629e75
I0622 12:05:24.746191       1 server.go:431]      Got AKName 000b38bf125fe251606c0df4ff0777c86d65423ad453ca148863fbae501bd5737d39
I0622 12:05:24.746197       1 server.go:432]      Registry size 0
I0622 12:05:24.746208       1 server.go:435]      From InstanceID 8939838129032687278
I0622 12:05:24.959995       1 server.go:454]      Acquired PublicKey from GCP API: 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAon140WZ75XDaoprRmmsa
4i7ueGtXkWIfNdTFpirNwRikslULGdh1V4zzPwm9CCJozsvWc9LVl4IM5/Fa2/eH
of4cxoPELkdAI1MR0qH84bqijTCCYl9DOT/IB2eZPAoJ9D8NYCmG5NdwNk4KOQg1
HshTEMAZ7Ruz7SgFJ1Jf9G/Fj8WtFY8lP0bb4jeO+tOhQbZ62Puw+ngRckdSTowM
l/mF8gLCSLIj2EcXEqrKsxJ/dqL/3egB7A7Wexxy0xwxPK15ppRWEmtjprbF2Riz
tgALlBqFTW7Lwl8NyubZOW2dYrf4F5Ph1wHwLTG9dNoyDuzpXltIphgwLJFheNPs
2QIDAQAB
-----END PUBLIC KEY-----
I0622 12:05:24.960036       1 server.go:456]      Decoding ekPub from client
I0622 12:05:24.960140       1 server.go:477]      EKPubPEM: 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAon140WZ75XDaoprRmmsa
4i7ueGtXkWIfNdTFpirNwRikslULGdh1V4zzPwm9CCJozsvWc9LVl4IM5/Fa2/eH
of4cxoPELkdAI1MR0qH84bqijTCCYl9DOT/IB2eZPAoJ9D8NYCmG5NdwNk4KOQg1
HshTEMAZ7Ruz7SgFJ1Jf9G/Fj8WtFY8lP0bb4jeO+tOhQbZ62Puw+ngRckdSTowM
l/mF8gLCSLIj2EcXEqrKsxJ/dqL/3egB7A7Wexxy0xwxPK15ppRWEmtjprbF2Riz
tgALlBqFTW7Lwl8NyubZOW2dYrf4F5Ph1wHwLTG9dNoyDuzpXltIphgwLJFheNPs
2QIDAQAB
-----END PUBLIC KEY-----
I0622 12:05:24.960152       1 server.go:483]      Verified EkPub from GCE API matches ekPub from Client
I0622 12:05:24.960166       1 server.go:805]      --> Starting makeCredential()
I0622 12:05:24.960173       1 server.go:806]      Read (ekPub) from request
I0622 12:05:24.973816       1 server.go:824]      Read (akPub) from request
I0622 12:05:24.973909       1 server.go:846]      Decoded AkPub: 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwivAscaq+ze8FSuZ9B0n
1UMkFev+EVQ4Z6SrPbsnM/14DOhPMizjFSlK7gavrK7tHfWwEwLGNMCFlwOdq954
4hszBl4FOn6kOAimPegtxKkW5SA5C8P2pVkuCwAapisN70y8r+gSBW5CSfFJLbcV
NrR1o+Z5OCO/NSj/q9mA67Ao5Bm5MN6QaVgYXFeMFOwyS9fMQ+qUCUTNQkL6SJcA
gNFRfrw6L4mY9y3n6TCyuJnBz8Wyae+rq1O6RCGJ1AsrmakJYkBOx7QnEHGIkoso
TqK6HoAIl3BtwLK4Ysd9upySjtg8/VS4ytJzGwTUfV7tz/8foEU3owA+fdD8p1R4
IwIDAQAB
-----END PUBLIC KEY-----
I0622 12:05:24.973946       1 server.go:849]      AK Default parameter match template
I0622 12:05:24.977391       1 server.go:858]      Loaded AK KeyName 000b38bf125fe251606c0df4ff0777c86d65423ad453ca148863fbae501bd5737d39
I0622 12:05:24.977416       1 server.go:860]      MakeCredential Start
I0622 12:05:24.980716       1 server.go:867]      credBlob 0020e26da7b9ae79b82fff09ab71ba0bf6c10cd7203100a20f61ca505acf258123f0ff91645c29bcf7319b2ae9b1
I0622 12:05:24.980740       1 server.go:868]      encryptedSecret0 0a20e13b18b55ad315d6ecd00f70e7eaadb5a696de0646dca3b38ec81cd9b614bc792d63838888df18cf4a5cffa90e5b0bc031a6faf342e2b44ac6a666fc39579d4f34ca011bf08fd7d6fe070df1ba5e90387d1c9fefda4860fad0a1f25916f6b8dcbe08cc5dcade895a4ece3fa55d0eb43b385e25790ce3d4987e01bedc62a9ca35c026a4e3bd3e1c928d31e5286bcf00df52a9ae0e7ebee7b153d78d56aab14691be5e4bf4c4f8deca7f6787f2ad827aef38f6515d192cf66e857919161b755007a6885438b7f74641f2a4cfbf94cf5a3f6e7d18d6ae880f09d9ae9af60fa2887ec4512a0dcdc07fa49725dca842446050f4299d181601c3fe3cc5225e615d
I0622 12:05:24.987042       1 server.go:869]      <-- End makeCredential()
I0622 12:05:24.989758       1 server.go:499]      Returning MakeCredentialResponse ======== 40adda5d-3879-4e2b-8c47-5c459d629e75
I0622 12:05:26.052861       1 server.go:174]      Found OIDC KeyID  19fe2a7b6795239606ca0a750794a7bd9fd95961
E0622 12:05:26.053060       1 server.go:187]      OIDC doc has Audience [https://tokenserver]   Issuer [https://accounts.google.com] and SubjectEmail [tokenclient@tc-4f4f5a70.iam.gserviceaccount.com]
I0622 12:05:26.053079       1 server.go:225]    Instance Confidentiality Status 0
I0622 12:05:26.053090       1 server.go:228]      Looking up Firestore Collection foo for instanceID 8939838129032687278
I0622 12:05:26.113110       1 server.go:249]      TLS Peer IP Check
I0622 12:05:26.113707       1 server.go:261]     Verified PeerIP 34.121.225.36:41564
I0622 12:05:26.114015       1 server.go:277]      Using mTLS Client cert Peer IP and SerialNumber
I0622 12:05:26.114306       1 server.go:286]      Client Peer Address [34.121.225.36:41564] - Subject[tokenclienta@otherdomain.com] - SerialNumber [5] Validated
I0622 12:05:26.114590       1 server.go:297]      Looking up InstanceID using GCE APIs for instanceID 8939838129032687278
I0622 12:05:26.316482       1 server.go:313]      Found  VM instanceID "8939838129032687278"
I0622 12:05:26.317148       1 server.go:314]      Found  VM CreationTimestamp "2021-06-22T04:57:59.255-07:00"
I0622 12:05:26.317455       1 server.go:315]      Found  VM Fingerprint "sSHMqlnfdVM="
I0622 12:05:26.317717       1 server.go:316]      Found  VM CpuPlatform "AMD Rome"
I0622 12:05:26.317965       1 server.go:319]      Found  VM ServiceAccount "tokenclient@tc-4f4f5a70.iam.gserviceaccount.com"
I0622 12:05:26.318218       1 server.go:325]      Found Registered External IP Address: 34.121.225.36
I0622 12:05:26.318463       1 server.go:336]      Found  VM Boot Disk Source "https://www.googleapis.com/compute/v1/projects/tc-4f4f5a70/zones/us-central1-a/disks/tokenclient"
I0622 12:05:26.507298       1 server.go:351]     Found Disk Image https://www.googleapis.com/compute/v1/projects/cos-cloud/global/images/cos-stable-81-12871-119-0
I0622 12:05:26.507832       1 server.go:363]      Derived Image Hash from metadata v7SftwlRj75WRXCq0Q/buov8D7t+Sg08fRqaylohfiI=
I0622 12:05:26.508132       1 server.go:515] ======= ActivateCredential ======== 40adda5d-3879-4e2b-8c47-5c459d629e75
I0622 12:05:26.508391       1 server.go:516]      Secret TeMaPEZQle
I0622 12:05:26.508655       1 server.go:519]      From InstanceID 8939838129032687278
I0622 12:05:26.508915       1 server.go:726]      --> Starting verifyQuote()
I0622 12:05:26.509155       1 server.go:738]      Read and Decode (attestion)
I0622 12:05:26.509424       1 server.go:745]      Attestation ExtraData (nonce): TeMaPEZQle 
I0622 12:05:26.509671       1 server.go:746]      Attestation PCR#: [0] 
I0622 12:05:26.509922       1 server.go:747]      Attestation Hash: 2ba7022b59f2158786ea3ea29a7ad12ff0c6c9d6682da6555d8926075b643b1f 
I0622 12:05:26.510186       1 server.go:764]      Expected PCR Value:           --> 24af52a4f429b71a3184a6d64cddad17e54ea030e2aa6576bf3a5a3d8bd3328f
I0622 12:05:26.510436       1 server.go:765]      sha256 of Expected PCR Value: --> 2ba7022b59f2158786ea3ea29a7ad12ff0c6c9d6682da6555d8926075b643b1f
I0622 12:05:26.510696       1 server.go:767]      Decoding PublicKey for AK ========
I0622 12:05:26.511145       1 server.go:798]      Attestation Signature Verified 
I0622 12:05:26.511417       1 server.go:799]      <-- End verifyQuote()
I0622 12:05:26.511667       1 server.go:539]      Verified Quote
I0622 12:05:26.511895       1 server.go:544]      Returning ActivateCredentialResponse ======== 40adda5d-3879-4e2b-8c47-5c459d629e75
I0622 12:05:26.514148       1 server.go:174]      Found OIDC KeyID  19fe2a7b6795239606ca0a750794a7bd9fd95961
E0622 12:05:26.514379       1 server.go:187]      OIDC doc has Audience [https://tokenserver]   Issuer [https://accounts.google.com] and SubjectEmail [tokenclient@tc-4f4f5a70.iam.gserviceaccount.com]
I0622 12:05:26.514398       1 server.go:225]    Instance Confidentiality Status 0
I0622 12:05:26.514411       1 server.go:228]      Looking up Firestore Collection foo for instanceID 8939838129032687278
I0622 12:05:26.562237       1 server.go:249]      TLS Peer IP Check
I0622 12:05:26.562273       1 server.go:261]     Verified PeerIP 34.121.225.36:41564
I0622 12:05:26.562296       1 server.go:277]      Using mTLS Client cert Peer IP and SerialNumber
I0622 12:05:26.562319       1 server.go:286]      Client Peer Address [34.121.225.36:41564] - Subject[tokenclienta@otherdomain.com] - SerialNumber [5] Validated
I0622 12:05:26.562333       1 server.go:297]      Looking up InstanceID using GCE APIs for instanceID 8939838129032687278
I0622 12:05:26.778111       1 server.go:313]      Found  VM instanceID "8939838129032687278"
I0622 12:05:26.778155       1 server.go:314]      Found  VM CreationTimestamp "2021-06-22T04:57:59.255-07:00"
I0622 12:05:26.778168       1 server.go:315]      Found  VM Fingerprint "sSHMqlnfdVM="
I0622 12:05:26.778179       1 server.go:316]      Found  VM CpuPlatform "AMD Rome"
I0622 12:05:26.778741       1 server.go:319]      Found  VM ServiceAccount "tokenclient@tc-4f4f5a70.iam.gserviceaccount.com"
I0622 12:05:26.778758       1 server.go:325]      Found Registered External IP Address: 34.121.225.36
I0622 12:05:26.778801       1 server.go:336]      Found  VM Boot Disk Source "https://www.googleapis.com/compute/v1/projects/tc-4f4f5a70/zones/us-central1-a/disks/tokenclient"
I0622 12:05:26.926140       1 server.go:351]     Found Disk Image https://www.googleapis.com/compute/v1/projects/cos-cloud/global/images/cos-stable-81-12871-119-0
I0622 12:05:26.926208       1 server.go:363]      Derived Image Hash from metadata v7SftwlRj75WRXCq0Q/buov8D7t+Sg08fRqaylohfiI=
I0622 12:05:26.926235       1 server.go:557] ======= OfferQuote ========  40adda5d-3879-4e2b-8c47-5c459d629e75
I0622 12:05:26.926262       1 server.go:560]      From InstanceID 8939838129032687278
I0622 12:05:26.926293       1 server.go:571]      Returning OfferQuoteResponse ======== 40adda5d-3879-4e2b-8c47-5c459d629e75
I0622 12:05:26.966053       1 server.go:174]      Found OIDC KeyID  19fe2a7b6795239606ca0a750794a7bd9fd95961
E0622 12:05:26.966465       1 server.go:187]      OIDC doc has Audience [https://tokenserver]   Issuer [https://accounts.google.com] and SubjectEmail [tokenclient@tc-4f4f5a70.iam.gserviceaccount.com]
I0622 12:05:26.966628       1 server.go:225]    Instance Confidentiality Status 0
I0622 12:05:26.966753       1 server.go:228]      Looking up Firestore Collection foo for instanceID 8939838129032687278
I0622 12:05:27.016914       1 server.go:249]      TLS Peer IP Check
I0622 12:05:27.017017       1 server.go:261]     Verified PeerIP 34.121.225.36:41564
I0622 12:05:27.017600       1 server.go:277]      Using mTLS Client cert Peer IP and SerialNumber
I0622 12:05:27.017836       1 server.go:286]      Client Peer Address [34.121.225.36:41564] - Subject[tokenclienta@otherdomain.com] - SerialNumber [5] Validated
I0622 12:05:27.018066       1 server.go:297]      Looking up InstanceID using GCE APIs for instanceID 8939838129032687278
I0622 12:05:27.209838       1 server.go:313]      Found  VM instanceID "8939838129032687278"
I0622 12:05:27.210091       1 server.go:314]      Found  VM CreationTimestamp "2021-06-22T04:57:59.255-07:00"
I0622 12:05:27.210202       1 server.go:315]      Found  VM Fingerprint "sSHMqlnfdVM="
I0622 12:05:27.210291       1 server.go:316]      Found  VM CpuPlatform "AMD Rome"
I0622 12:05:27.210381       1 server.go:319]      Found  VM ServiceAccount "tokenclient@tc-4f4f5a70.iam.gserviceaccount.com"
I0622 12:05:27.210463       1 server.go:325]      Found Registered External IP Address: 34.121.225.36
I0622 12:05:27.210562       1 server.go:336]      Found  VM Boot Disk Source "https://www.googleapis.com/compute/v1/projects/tc-4f4f5a70/zones/us-central1-a/disks/tokenclient"
I0622 12:05:27.415096       1 server.go:351]     Found Disk Image https://www.googleapis.com/compute/v1/projects/cos-cloud/global/images/cos-stable-81-12871-119-0
I0622 12:05:27.415267       1 server.go:363]      Derived Image Hash from metadata v7SftwlRj75WRXCq0Q/buov8D7t+Sg08fRqaylohfiI=
I0622 12:05:27.415286       1 server.go:586] ======= ProvideQuote ======== 40adda5d-3879-4e2b-8c47-5c459d629e75
I0622 12:05:27.415293       1 server.go:588]      From InstanceID 8939838129032687278
I0622 12:05:27.415316       1 server.go:726]      --> Starting verifyQuote()
I0622 12:05:27.415323       1 server.go:738]      Read and Decode (attestion)
I0622 12:05:27.415353       1 server.go:745]      Attestation ExtraData (nonce): 3fd1cc63-4859-414a-b679-8d8c2556aae7 
I0622 12:05:27.415360       1 server.go:746]      Attestation PCR#: [0] 
I0622 12:05:27.415373       1 server.go:747]      Attestation Hash: 2ba7022b59f2158786ea3ea29a7ad12ff0c6c9d6682da6555d8926075b643b1f 
I0622 12:05:27.415414       1 server.go:764]      Expected PCR Value:           --> 24af52a4f429b71a3184a6d64cddad17e54ea030e2aa6576bf3a5a3d8bd3328f
I0622 12:05:27.415425       1 server.go:765]      sha256 of Expected PCR Value: --> 2ba7022b59f2158786ea3ea29a7ad12ff0c6c9d6682da6555d8926075b643b1f
I0622 12:05:27.415437       1 server.go:767]      Decoding PublicKey for AK ========
I0622 12:05:27.415646       1 server.go:798]      Attestation Signature Verified 
I0622 12:05:27.415660       1 server.go:799]      <-- End verifyQuote()
I0622 12:05:27.415667       1 server.go:612]      Returning ProvideQuoteResponse ======== 40adda5d-3879-4e2b-8c47-5c459d629e75
I0622 12:05:27.542323       1 server.go:174]      Found OIDC KeyID  19fe2a7b6795239606ca0a750794a7bd9fd95961
E0622 12:05:27.542572       1 server.go:187]      OIDC doc has Audience [https://tokenserver]   Issuer [https://accounts.google.com] and SubjectEmail [tokenclient@tc-4f4f5a70.iam.gserviceaccount.com]
I0622 12:05:27.542590       1 server.go:225]    Instance Confidentiality Status 0
I0622 12:05:27.542601       1 server.go:228]      Looking up Firestore Collection foo for instanceID 8939838129032687278
I0622 12:05:27.584653       1 server.go:249]      TLS Peer IP Check
I0622 12:05:27.584686       1 server.go:261]     Verified PeerIP 34.121.225.36:41564
I0622 12:05:27.584721       1 server.go:277]      Using mTLS Client cert Peer IP and SerialNumber
I0622 12:05:27.584747       1 server.go:286]      Client Peer Address [34.121.225.36:41564] - Subject[tokenclienta@otherdomain.com] - SerialNumber [5] Validated
I0622 12:05:27.584763       1 server.go:297]      Looking up InstanceID using GCE APIs for instanceID 8939838129032687278
I0622 12:05:27.806623       1 server.go:313]      Found  VM instanceID "8939838129032687278"
I0622 12:05:27.806656       1 server.go:314]      Found  VM CreationTimestamp "2021-06-22T04:57:59.255-07:00"
I0622 12:05:27.806671       1 server.go:315]      Found  VM Fingerprint "sSHMqlnfdVM="
I0622 12:05:27.806682       1 server.go:316]      Found  VM CpuPlatform "AMD Rome"
I0622 12:05:27.806694       1 server.go:319]      Found  VM ServiceAccount "tokenclient@tc-4f4f5a70.iam.gserviceaccount.com"
I0622 12:05:27.806706       1 server.go:325]      Found Registered External IP Address: 34.121.225.36
I0622 12:05:27.806718       1 server.go:336]      Found  VM Boot Disk Source "https://www.googleapis.com/compute/v1/projects/tc-4f4f5a70/zones/us-central1-a/disks/tokenclient"
I0622 12:05:28.074725       1 server.go:351]     Found Disk Image https://www.googleapis.com/compute/v1/projects/cos-cloud/global/images/cos-stable-81-12871-119-0
I0622 12:05:28.074774       1 server.go:363]      Derived Image Hash from metadata v7SftwlRj75WRXCq0Q/buov8D7t+Sg08fRqaylohfiI=
I0622 12:05:28.074813       1 server.go:625] ======= ProvideSigningKey ======== 40adda5d-3879-4e2b-8c47-5c459d629e75
I0622 12:05:28.074821       1 server.go:626]      client provided uid: 40adda5d-3879-4e2b-8c47-5c459d629e75
I0622 12:05:28.074829       1 server.go:629]      From InstanceID 8939838129032687278
I0622 12:05:28.074837       1 server.go:636]      SigningKey -----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4yFjjSxY0q7xU28Kjpd3
bC7LAayXbj1IkmwYKAcyFA8uO3D5ghONeXxUi5LzKuPNPZc/WATrG+b9E66EXgIk
+NLfOS/lo2wQEqQz8RSQCNMRljGQUMZ0gF6Oq+jCnQRv492Rp0G7Wh8vOqORGAqy
H92BF8Q3Z5PLxZpH1ipiAN6Oheed2ukr3j1OqoeW4Io3RQ9E4mH97tYfFXnpp73Q
4G3znhYXDt6DzNaOteZqYjKFhNCt95t3LQrX/dPpC8YsZZc0fq6Zq1e/t7rVwXs+
JcQX9+Pgit6V4l61H+Fk2v0+1hVLNhrf0sbeqv27byU7AHIBA93WxnW5zTbMZewH
nwIDAQAB
-----END PUBLIC KEY-----
I0622 12:05:28.074849       1 server.go:637]      SigningKey Attestation /1RDR4AXACIACxybHL7Vd7g1ulv7Jt1PHbxRAIKux9RcIJYPZ17xKm2eAAAAAAAAAAa0SgAAAAkAAAAAASAWBREAFigAACIAC4R/huhoqpjiLM9WB8j+leTYeaPJaBtJNClIZLgcKMjVACIAC080w3ZfV/uybrlY9naEtUE/fDmXn87KEF5QyBRfovBv
I0622 12:05:28.074893       1 server.go:638]      SigningKey Signature MeJ8DtJjxHppwaOz9gj4vFFOzuOkg1E8t34yAOIOBEmQKJbn/2YwdF0OIDBkIoqY9rm9eQoqdxoCWMmA5SEcPsjCe25cbCBEcC0d5beeWBQa+4W5rxrcaRCLeUbpb4kRW8V7/ANub7WctrjLCpkf1Xj1inWvgm5bCX2NHtrsscAODhktk94nTYeOuxf3dmxosMWRV4p2vOmDVxjFPd3ULa3DEZ/nyVSfKM/jaDt88B4szFuXx8Dju93LvRtpbDVG2W64XnnBgBnORBzymuDHz55Jbp+4mc+AjnKObv0afK6zer69/lRTxBibRXwOaPf71PkcXgrFln9mfFv1hY3TRQ==
I0622 12:05:28.074922       1 server.go:645]      Read and Decode (attestion)
I0622 12:05:28.074973       1 server.go:650]      Attestation att.AttestedCertifyInfo.QualifiedName: 4f34c3765f57fbb26eb958f67684b5413f7c39979fceca105e50c8145fa2f06f
I0622 12:05:28.075002       1 server.go:658]      Decoding PublicKey for AK ======== 40adda5d-3879-4e2b-8c47-5c459d629e75
I0622 12:05:28.075240       1 server.go:677]      Attestation of Signing Key Verified
I0622 12:05:28.075322       1 server.go:709]      Attestation MatchesPublic true
I0622 12:05:28.075359       1 server.go:713]      Returning ProvideSigningKeyResponse ======== 40adda5d-3879-4e2b-8c47-5c459d629e75
```
