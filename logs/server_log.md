### Sample TokenServer log
(in reverse order)


```log
...
...
I0620 12:26:22.024159       1 server.go:174]      Found OIDC KeyID  19fe2a7b6795239606ca0a750794a7bd9fd95961
E0620 12:26:22.024418       1 server.go:187]      OIDC doc has Audience [https://tokenserver]   Issuer [https://accounts.google.com] and SubjectEmail [tokenclient@tc-b23369ac.iam.gserviceaccount.com]
I0620 12:26:22.024461       1 server.go:225]    Instance Confidentiality Status 0
I0620 12:26:22.024475       1 server.go:228]      Looking up Firestore Collection foo for instanceID 5055893581146000589
E0620 12:26:22.082023       1 server.go:238] ERROR:  Could not find instanceID new Firestore Client 5055893581146000589
I0620 12:26:32.027930       1 server.go:174]      Found OIDC KeyID  19fe2a7b6795239606ca0a750794a7bd9fd95961
E0620 12:26:32.028261       1 server.go:187]      OIDC doc has Audience [https://tokenserver]   Issuer [https://accounts.google.com] and SubjectEmail [tokenclient@tc-b23369ac.iam.gserviceaccount.com]
I0620 12:26:32.028958       1 server.go:225]    Instance Confidentiality Status 0
I0620 12:26:32.029009       1 server.go:228]      Looking up Firestore Collection foo for instanceID 5055893581146000589
E0620 12:26:32.075300       1 server.go:238] ERROR:  Could not find instanceID new Firestore Client 5055893581146000589
I0620 12:26:42.023514       1 server.go:174]      Found OIDC KeyID  19fe2a7b6795239606ca0a750794a7bd9fd95961
E0620 12:26:42.023787       1 server.go:187]      OIDC doc has Audience [https://tokenserver]   Issuer [https://accounts.google.com] and SubjectEmail [tokenclient@tc-b23369ac.iam.gserviceaccount.com]
I0620 12:26:42.023816       1 server.go:225]    Instance Confidentiality Status 0
I0620 12:26:42.023830       1 server.go:228]      Looking up Firestore Collection foo for instanceID 5055893581146000589
E0620 12:26:42.091575       1 server.go:238] ERROR:  Could not find instanceID new Firestore Client 5055893581146000589
I0620 12:26:52.028794       1 server.go:174]      Found OIDC KeyID  19fe2a7b6795239606ca0a750794a7bd9fd95961
E0620 12:26:52.028971       1 server.go:187]      OIDC doc has Audience [https://tokenserver]   Issuer [https://accounts.google.com] and SubjectEmail [tokenclient@tc-b23369ac.iam.gserviceaccount.com]
I0620 12:26:52.028998       1 server.go:225]    Instance Confidentiality Status 0
I0620 12:26:52.029013       1 server.go:228]      Looking up Firestore Collection foo for instanceID 5055893581146000589
E0620 12:26:52.086587       1 server.go:238] ERROR:  Could not find instanceID new Firestore Client 5055893581146000589
I0620 12:27:02.023082       1 server.go:174]      Found OIDC KeyID  19fe2a7b6795239606ca0a750794a7bd9fd95961
E0620 12:27:02.023448       1 server.go:187]      OIDC doc has Audience [https://tokenserver]   Issuer [https://accounts.google.com] and SubjectEmail [tokenclient@tc-b23369ac.iam.gserviceaccount.com]
I0620 12:27:02.023520       1 server.go:225]    Instance Confidentiality Status 0
I0620 12:27:02.023598       1 server.go:228]      Looking up Firestore Collection foo for instanceID 5055893581146000589
E0620 12:27:02.087784       1 server.go:238] ERROR:  Could not find instanceID new Firestore Client 5055893581146000589
I0620 12:27:12.025111       1 server.go:174]      Found OIDC KeyID  19fe2a7b6795239606ca0a750794a7bd9fd95961
E0620 12:27:12.026089       1 server.go:187]      OIDC doc has Audience [https://tokenserver]   Issuer [https://accounts.google.com] and SubjectEmail [tokenclient@tc-b23369ac.iam.gserviceaccount.com]
I0620 12:27:12.026144       1 server.go:225]    Instance Confidentiality Status 0
I0620 12:27:12.026161       1 server.go:228]      Looking up Firestore Collection foo for instanceID 5055893581146000589
E0620 12:27:12.070092       1 server.go:238] ERROR:  Could not find instanceID new Firestore Client 5055893581146000589
I0620 12:27:22.023800       1 server.go:174]      Found OIDC KeyID  19fe2a7b6795239606ca0a750794a7bd9fd95961
E0620 12:27:22.024079       1 server.go:187]      OIDC doc has Audience [https://tokenserver]   Issuer [https://accounts.google.com] and SubjectEmail [tokenclient@tc-b23369ac.iam.gserviceaccount.com]
I0620 12:27:22.024132       1 server.go:225]    Instance Confidentiality Status 0
I0620 12:27:22.024174       1 server.go:228]      Looking up Firestore Collection foo for instanceID 5055893581146000589
I0620 12:27:22.092733       1 server.go:249]      TLS Peer IP Check
I0620 12:27:22.092863       1 server.go:261]     Verified PeerIP 34.136.60.156:34664
I0620 12:27:22.092937       1 server.go:277]      Using mTLS Client cert Peer IP and SerialNumber
I0620 12:27:22.093010       1 server.go:286]      Client Peer Address [34.136.60.156:34664] - Subject[tokenclienta@otherdomain.com] - SerialNumber [5] Validated
I0620 12:27:22.093075       1 server.go:297]      Looking up InstanceID using GCE APIs for instanceID 5055893581146000589
I0620 12:27:22.219159       1 server.go:313]      Found  VM instanceID "5055893581146000589"
I0620 12:27:22.219291       1 server.go:314]      Found  VM CreationTimestamp "2021-06-20T05:18:48.060-07:00"
I0620 12:27:22.219350       1 server.go:315]      Found  VM Fingerprint "suqYIWhtPQ8="
I0620 12:27:22.219387       1 server.go:316]      Found  VM CpuPlatform "Intel Haswell"
I0620 12:27:22.219446       1 server.go:319]      Found  VM ServiceAccount "tokenclient@tc-b23369ac.iam.gserviceaccount.com"
I0620 12:27:22.219525       1 server.go:325]      Found Registered External IP Address: 34.136.60.156
I0620 12:27:22.219686       1 server.go:336]      Found  VM Boot Disk Source "https://www.googleapis.com/compute/v1/projects/tc-b23369ac/zones/us-central1-a/disks/tokenclient"
I0620 12:27:22.398742       1 server.go:351]     Found Disk Image https://www.googleapis.com/compute/v1/projects/cos-cloud/global/images/cos-stable-81-12871-119-0
I0620 12:27:22.398811       1 server.go:363]      Derived Image Hash from metadata mSS9owqshEUCRpD5VSR+7vBN9wTcOG88lSa0PZdnHyo=
I0620 12:27:22.398826       1 server.go:395] ======= GetToken ---> dc9d5655-d1c2-11eb-95cf-0242ac110002
I0620 12:27:22.398834       1 server.go:401]      Got rpc: RequestID dc9d5655-d1c2-11eb-95cf-0242ac110002 for subject 107558527528007710711 and email tokenclient@tc-b23369ac.iam.gserviceaccount.com for instanceID 5055893581146000589
I0620 12:27:22.398975       1 server.go:419] <<<--- GetToken ======= dc9d5655-d1c2-11eb-95cf-0242ac110002
I0620 12:27:23.022055       1 server.go:174]      Found OIDC KeyID  19fe2a7b6795239606ca0a750794a7bd9fd95961
E0620 12:27:23.022222       1 server.go:187]      OIDC doc has Audience [https://tokenserver]   Issuer [https://accounts.google.com] and SubjectEmail [tokenclient@tc-b23369ac.iam.gserviceaccount.com]
I0620 12:27:23.022240       1 server.go:225]    Instance Confidentiality Status 0
I0620 12:27:23.022252       1 server.go:228]      Looking up Firestore Collection foo for instanceID 5055893581146000589
I0620 12:27:23.087515       1 server.go:249]      TLS Peer IP Check
I0620 12:27:23.087554       1 server.go:261]     Verified PeerIP 34.136.60.156:34664
I0620 12:27:23.088507       1 server.go:277]      Using mTLS Client cert Peer IP and SerialNumber
I0620 12:27:23.088574       1 server.go:286]      Client Peer Address [34.136.60.156:34664] - Subject[tokenclienta@otherdomain.com] - SerialNumber [5] Validated
I0620 12:27:23.088599       1 server.go:297]      Looking up InstanceID using GCE APIs for instanceID 5055893581146000589
I0620 12:27:23.210733       1 server.go:313]      Found  VM instanceID "5055893581146000589"
I0620 12:27:23.210776       1 server.go:314]      Found  VM CreationTimestamp "2021-06-20T05:18:48.060-07:00"
I0620 12:27:23.210792       1 server.go:315]      Found  VM Fingerprint "suqYIWhtPQ8="
I0620 12:27:23.211003       1 server.go:316]      Found  VM CpuPlatform "Intel Haswell"
I0620 12:27:23.211024       1 server.go:319]      Found  VM ServiceAccount "tokenclient@tc-b23369ac.iam.gserviceaccount.com"
I0620 12:27:23.211078       1 server.go:325]      Found Registered External IP Address: 34.136.60.156
I0620 12:27:23.211093       1 server.go:336]      Found  VM Boot Disk Source "https://www.googleapis.com/compute/v1/projects/tc-b23369ac/zones/us-central1-a/disks/tokenclient"
I0620 12:27:23.392152       1 server.go:351]     Found Disk Image https://www.googleapis.com/compute/v1/projects/cos-cloud/global/images/cos-stable-81-12871-119-0
I0620 12:27:23.392269       1 server.go:363]      Derived Image Hash from metadata mSS9owqshEUCRpD5VSR+7vBN9wTcOG88lSa0PZdnHyo=
I0620 12:27:23.392873       1 server.go:430] ======= MakeCredential ======== da48f901-02bc-4cb3-b0a5-e7408e36847b
I0620 12:27:23.393272       1 server.go:431]      Got AKName 000bdec56a29ce186cd28492931439e081ddb9ab2adf90cbeda85a6465d1c87989a1
I0620 12:27:23.393520       1 server.go:432]      Registry size 0
I0620 12:27:23.393589       1 server.go:435]      From InstanceID 5055893581146000589
I0620 12:27:23.581350       1 server.go:454]      Acquired PublicKey from GCP API: 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0L+xTVAysyRfNAzMO8QO
zWG11WTOnfTU/InyC0dpcF6txBbevdv7yVQB0tA/ZLf8JsEKU7hzxAhYrZ3RVnOd
hPONkkc2AH+ZENqkExb3i5Rwg6IKNztXGE3wV5EbWBtAURJdxCX1+dCg2vKThRwE
SH7AwutagNnK4zgUP0XNGMKXwHjpQSiL2QTqlePco9Svq+tqw0E4XtNFSaP6cCIp
KdT0a+KZj3eiy+IiUDXiusTgR8qLkuTueUv546BHvkBaSjM1dTad5QSX793yn1Oe
ZiFHwAPqb6VzrMmnX8+B0wymMZz8vb6Qqc0Q16vrubcHWepQ3glqyTlC7Z1Ia7VL
lQIDAQAB
-----END PUBLIC KEY-----
I0620 12:27:23.581385       1 server.go:456]      Decoding ekPub from client
I0620 12:27:23.582420       1 server.go:477]      EKPubPEM: 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0L+xTVAysyRfNAzMO8QO
zWG11WTOnfTU/InyC0dpcF6txBbevdv7yVQB0tA/ZLf8JsEKU7hzxAhYrZ3RVnOd
hPONkkc2AH+ZENqkExb3i5Rwg6IKNztXGE3wV5EbWBtAURJdxCX1+dCg2vKThRwE
SH7AwutagNnK4zgUP0XNGMKXwHjpQSiL2QTqlePco9Svq+tqw0E4XtNFSaP6cCIp
KdT0a+KZj3eiy+IiUDXiusTgR8qLkuTueUv546BHvkBaSjM1dTad5QSX793yn1Oe
ZiFHwAPqb6VzrMmnX8+B0wymMZz8vb6Qqc0Q16vrubcHWepQ3glqyTlC7Z1Ia7VL
lQIDAQAB
-----END PUBLIC KEY-----
I0620 12:27:23.582463       1 server.go:483]      Verified EkPub from GCE API matches ekPub from Client
I0620 12:27:23.582500       1 server.go:805]      --> Starting makeCredential()
I0620 12:27:23.582506       1 server.go:806]      Read (ekPub) from request
I0620 12:27:23.595930       1 server.go:824]      Read (akPub) from request
I0620 12:27:23.596034       1 server.go:846]      Decoded AkPub: 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtGfXCU4+94rAFog+qpOt
kLKZJWdKj2Q5N4nnpfhjnuKmj1tikpJnLukC2DWLH4VavgHvJ6JUnvZFIij7XFf5
C+1DfjcK5Cu4Tadw8+u43lnLag3NfVEa66IPhthh0XUqjmWnKdb6qzeMN4l9wRgs
zmWjb/VMsW041ubO/10AkMjI2UP39JrYNZGwcolAKZYtTpKc2+BXe//Q18VEH1Me
qJ9b9woCcXrzsyzmWwcEJshqx7jFY4gKxaTCChrKk2A0iOpKkglNN5EXaLXylSsG
HcnT+vf2kxcvtZZePw5Zyq6TNiqsUCDzQ62d3r6BHdjv8Uq1xVDhej/7Vfj9hci9
PQIDAQAB
-----END PUBLIC KEY-----
I0620 12:27:23.596054       1 server.go:849]      AK Default parameter match template
I0620 12:27:23.599698       1 server.go:858]      Loaded AK KeyName 000bdec56a29ce186cd28492931439e081ddb9ab2adf90cbeda85a6465d1c87989a1
I0620 12:27:23.599744       1 server.go:860]      MakeCredential Start
I0620 12:27:23.603413       1 server.go:867]      credBlob 0020be05d62d65db4a5d48928ceff48ef4fa651b78646c64e2fbc6d46f64b7eeea206634ca932a7191eb67910cf0
I0620 12:27:23.603446       1 server.go:868]      encryptedSecret0 c3341f2776d6fe62399c3b5bac1422d00373257cf27e8b89d1037fc0d4309b5c97dac3c9225e4f204007f569a5fd31fcab8cce78f9bae6e6679bbd45a8afbe50e167dd739b46b49e99e5423775a1a0d53bd76e28699ed7e00212273e1c2e79ab97edfd66078b004d97def954deba1c0f101ec3352b72b786f0034464b14a0ee2aceb193ec8500cd1ba70fe59d430b9192d99e94232dd975a681240b0d008d111d9cb29a668a1499b2a86aa672448f3bd9779cdf732e715ad3e7c372bdd86aebc511f2b74112b871a8f6020d6f668902f054ae3743fd3644f112854793d9a1cad83af5b4354c60e66138bb67d2d960967d79c06cc2069626c13298071fd662b0b
I0620 12:27:23.603466       1 server.go:869]      <-- End makeCredential()
I0620 12:27:23.606219       1 server.go:499]      Returning MakeCredentialResponse ======== da48f901-02bc-4cb3-b0a5-e7408e36847b
I0620 12:27:24.669773       1 server.go:174]      Found OIDC KeyID  19fe2a7b6795239606ca0a750794a7bd9fd95961
E0620 12:27:24.670194       1 server.go:187]      OIDC doc has Audience [https://tokenserver]   Issuer [https://accounts.google.com] and SubjectEmail [tokenclient@tc-b23369ac.iam.gserviceaccount.com]
I0620 12:27:24.670290       1 server.go:225]    Instance Confidentiality Status 0
I0620 12:27:24.670332       1 server.go:228]      Looking up Firestore Collection foo for instanceID 5055893581146000589
I0620 12:27:24.712723       1 server.go:249]      TLS Peer IP Check
I0620 12:27:24.712758       1 server.go:261]     Verified PeerIP 34.136.60.156:34664
I0620 12:27:24.712784       1 server.go:277]      Using mTLS Client cert Peer IP and SerialNumber
I0620 12:27:24.713425       1 server.go:286]      Client Peer Address [34.136.60.156:34664] - Subject[tokenclienta@otherdomain.com] - SerialNumber [5] Validated
I0620 12:27:24.713457       1 server.go:297]      Looking up InstanceID using GCE APIs for instanceID 5055893581146000589
I0620 12:27:24.837272       1 server.go:313]      Found  VM instanceID "5055893581146000589"
I0620 12:27:24.837317       1 server.go:314]      Found  VM CreationTimestamp "2021-06-20T05:18:48.060-07:00"
I0620 12:27:24.837334       1 server.go:315]      Found  VM Fingerprint "suqYIWhtPQ8="
I0620 12:27:24.837368       1 server.go:316]      Found  VM CpuPlatform "Intel Haswell"
I0620 12:27:24.837417       1 server.go:319]      Found  VM ServiceAccount "tokenclient@tc-b23369ac.iam.gserviceaccount.com"
I0620 12:27:24.837433       1 server.go:325]      Found Registered External IP Address: 34.136.60.156
I0620 12:27:24.837447       1 server.go:336]      Found  VM Boot Disk Source "https://www.googleapis.com/compute/v1/projects/tc-b23369ac/zones/us-central1-a/disks/tokenclient"
I0620 12:27:25.012403       1 server.go:351]     Found Disk Image https://www.googleapis.com/compute/v1/projects/cos-cloud/global/images/cos-stable-81-12871-119-0
I0620 12:27:25.013095       1 server.go:363]      Derived Image Hash from metadata mSS9owqshEUCRpD5VSR+7vBN9wTcOG88lSa0PZdnHyo=
I0620 12:27:25.013526       1 server.go:515] ======= ActivateCredential ======== da48f901-02bc-4cb3-b0a5-e7408e36847b
I0620 12:27:25.013865       1 server.go:516]      Secret dcEkXBAkjQ
I0620 12:27:25.014184       1 server.go:519]      From InstanceID 5055893581146000589
I0620 12:27:25.014503       1 server.go:726]      --> Starting verifyQuote()
I0620 12:27:25.014825       1 server.go:738]      Read and Decode (attestion)
I0620 12:27:25.015192       1 server.go:745]      Attestation ExtraData (nonce): dcEkXBAkjQ 
I0620 12:27:25.015521       1 server.go:746]      Attestation PCR#: [0] 
I0620 12:27:25.015890       1 server.go:747]      Attestation Hash: 2ba7022b59f2158786ea3ea29a7ad12ff0c6c9d6682da6555d8926075b643b1f 
I0620 12:27:25.016203       1 server.go:764]      Expected PCR Value:           --> 24af52a4f429b71a3184a6d64cddad17e54ea030e2aa6576bf3a5a3d8bd3328f
I0620 12:27:25.016501       1 server.go:765]      sha256 of Expected PCR Value: --> 2ba7022b59f2158786ea3ea29a7ad12ff0c6c9d6682da6555d8926075b643b1f
I0620 12:27:25.016821       1 server.go:767]      Decoding PublicKey for AK ========
I0620 12:27:25.017311       1 server.go:798]      Attestation Signature Verified 
I0620 12:27:25.017647       1 server.go:799]      <-- End verifyQuote()
I0620 12:27:25.017952       1 server.go:539]      Verified Quote
I0620 12:27:25.017969       1 server.go:544]      Returning ActivateCredentialResponse ======== da48f901-02bc-4cb3-b0a5-e7408e36847b
I0620 12:27:25.020034       1 server.go:174]      Found OIDC KeyID  19fe2a7b6795239606ca0a750794a7bd9fd95961
E0620 12:27:25.020342       1 server.go:187]      OIDC doc has Audience [https://tokenserver]   Issuer [https://accounts.google.com] and SubjectEmail [tokenclient@tc-b23369ac.iam.gserviceaccount.com]
I0620 12:27:25.020498       1 server.go:225]    Instance Confidentiality Status 0
I0620 12:27:25.020517       1 server.go:228]      Looking up Firestore Collection foo for instanceID 5055893581146000589
I0620 12:27:25.086048       1 server.go:249]      TLS Peer IP Check
I0620 12:27:25.086644       1 server.go:261]     Verified PeerIP 34.136.60.156:34664
I0620 12:27:25.086970       1 server.go:277]      Using mTLS Client cert Peer IP and SerialNumber
I0620 12:27:25.087276       1 server.go:286]      Client Peer Address [34.136.60.156:34664] - Subject[tokenclienta@otherdomain.com] - SerialNumber [5] Validated
I0620 12:27:25.087559       1 server.go:297]      Looking up InstanceID using GCE APIs for instanceID 5055893581146000589
I0620 12:27:25.289087       1 server.go:313]      Found  VM instanceID "5055893581146000589"
I0620 12:27:25.289129       1 server.go:314]      Found  VM CreationTimestamp "2021-06-20T05:18:48.060-07:00"
I0620 12:27:25.289146       1 server.go:315]      Found  VM Fingerprint "suqYIWhtPQ8="
I0620 12:27:25.289394       1 server.go:316]      Found  VM CpuPlatform "Intel Haswell"
I0620 12:27:25.289415       1 server.go:319]      Found  VM ServiceAccount "tokenclient@tc-b23369ac.iam.gserviceaccount.com"
I0620 12:27:25.289471       1 server.go:325]      Found Registered External IP Address: 34.136.60.156
I0620 12:27:25.289553       1 server.go:336]      Found  VM Boot Disk Source "https://www.googleapis.com/compute/v1/projects/tc-b23369ac/zones/us-central1-a/disks/tokenclient"
I0620 12:27:25.464987       1 server.go:351]     Found Disk Image https://www.googleapis.com/compute/v1/projects/cos-cloud/global/images/cos-stable-81-12871-119-0
I0620 12:27:25.465046       1 server.go:363]      Derived Image Hash from metadata mSS9owqshEUCRpD5VSR+7vBN9wTcOG88lSa0PZdnHyo=
I0620 12:27:25.465113       1 server.go:557] ======= OfferQuote ========  da48f901-02bc-4cb3-b0a5-e7408e36847b
I0620 12:27:25.465123       1 server.go:560]      From InstanceID 5055893581146000589
I0620 12:27:25.465137       1 server.go:571]      Returning OfferQuoteResponse ======== da48f901-02bc-4cb3-b0a5-e7408e36847b
I0620 12:27:25.507114       1 server.go:174]      Found OIDC KeyID  19fe2a7b6795239606ca0a750794a7bd9fd95961
E0620 12:27:25.507404       1 server.go:187]      OIDC doc has Audience [https://tokenserver]   Issuer [https://accounts.google.com] and SubjectEmail [tokenclient@tc-b23369ac.iam.gserviceaccount.com]
I0620 12:27:25.507961       1 server.go:225]    Instance Confidentiality Status 0
I0620 12:27:25.508320       1 server.go:228]      Looking up Firestore Collection foo for instanceID 5055893581146000589
I0620 12:27:25.560822       1 server.go:249]      TLS Peer IP Check
I0620 12:27:25.561451       1 server.go:261]     Verified PeerIP 34.136.60.156:34664
I0620 12:27:25.561922       1 server.go:277]      Using mTLS Client cert Peer IP and SerialNumber
I0620 12:27:25.562022       1 server.go:286]      Client Peer Address [34.136.60.156:34664] - Subject[tokenclienta@otherdomain.com] - SerialNumber [5] Validated
I0620 12:27:25.562091       1 server.go:297]      Looking up InstanceID using GCE APIs for instanceID 5055893581146000589
I0620 12:27:25.671880       1 server.go:313]      Found  VM instanceID "5055893581146000589"
I0620 12:27:25.671996       1 server.go:314]      Found  VM CreationTimestamp "2021-06-20T05:18:48.060-07:00"
I0620 12:27:25.672080       1 server.go:315]      Found  VM Fingerprint "suqYIWhtPQ8="
I0620 12:27:25.672096       1 server.go:316]      Found  VM CpuPlatform "Intel Haswell"
I0620 12:27:25.672109       1 server.go:319]      Found  VM ServiceAccount "tokenclient@tc-b23369ac.iam.gserviceaccount.com"
I0620 12:27:25.672156       1 server.go:325]      Found Registered External IP Address: 34.136.60.156
I0620 12:27:25.672172       1 server.go:336]      Found  VM Boot Disk Source "https://www.googleapis.com/compute/v1/projects/tc-b23369ac/zones/us-central1-a/disks/tokenclient"
I0620 12:27:25.832083       1 server.go:351]     Found Disk Image https://www.googleapis.com/compute/v1/projects/cos-cloud/global/images/cos-stable-81-12871-119-0
I0620 12:27:25.832137       1 server.go:363]      Derived Image Hash from metadata mSS9owqshEUCRpD5VSR+7vBN9wTcOG88lSa0PZdnHyo=
I0620 12:27:25.832231       1 server.go:586] ======= ProvideQuote ======== da48f901-02bc-4cb3-b0a5-e7408e36847b
I0620 12:27:25.832247       1 server.go:588]      From InstanceID 5055893581146000589
I0620 12:27:25.832257       1 server.go:726]      --> Starting verifyQuote()
I0620 12:27:25.832266       1 server.go:738]      Read and Decode (attestion)
I0620 12:27:25.832387       1 server.go:745]      Attestation ExtraData (nonce): a0b264bc-d261-437d-a932-3db68c701992 
I0620 12:27:25.832398       1 server.go:746]      Attestation PCR#: [0] 
I0620 12:27:25.832411       1 server.go:747]      Attestation Hash: 2ba7022b59f2158786ea3ea29a7ad12ff0c6c9d6682da6555d8926075b643b1f 
I0620 12:27:25.832423       1 server.go:764]      Expected PCR Value:           --> 24af52a4f429b71a3184a6d64cddad17e54ea030e2aa6576bf3a5a3d8bd3328f
I0620 12:27:25.832437       1 server.go:765]      sha256 of Expected PCR Value: --> 2ba7022b59f2158786ea3ea29a7ad12ff0c6c9d6682da6555d8926075b643b1f
I0620 12:27:25.832450       1 server.go:767]      Decoding PublicKey for AK ========
I0620 12:27:25.833447       1 server.go:798]      Attestation Signature Verified 
I0620 12:27:25.833478       1 server.go:799]      <-- End verifyQuote()
I0620 12:27:25.833516       1 server.go:612]      Returning ProvideQuoteResponse ======== da48f901-02bc-4cb3-b0a5-e7408e36847b
I0620 12:27:26.051185       1 server.go:174]      Found OIDC KeyID  19fe2a7b6795239606ca0a750794a7bd9fd95961
E0620 12:27:26.051466       1 server.go:187]      OIDC doc has Audience [https://tokenserver]   Issuer [https://accounts.google.com] and SubjectEmail [tokenclient@tc-b23369ac.iam.gserviceaccount.com]
I0620 12:27:26.051523       1 server.go:225]    Instance Confidentiality Status 0
I0620 12:27:26.051538       1 server.go:228]      Looking up Firestore Collection foo for instanceID 5055893581146000589
I0620 12:27:26.086764       1 server.go:249]      TLS Peer IP Check
I0620 12:27:26.087101       1 server.go:261]     Verified PeerIP 34.136.60.156:34664
I0620 12:27:26.087401       1 server.go:277]      Using mTLS Client cert Peer IP and SerialNumber
I0620 12:27:26.087669       1 server.go:286]      Client Peer Address [34.136.60.156:34664] - Subject[tokenclienta@otherdomain.com] - SerialNumber [5] Validated
I0620 12:27:26.087892       1 server.go:297]      Looking up InstanceID using GCE APIs for instanceID 5055893581146000589
I0620 12:27:26.233226       1 server.go:313]      Found  VM instanceID "5055893581146000589"
I0620 12:27:26.233645       1 server.go:314]      Found  VM CreationTimestamp "2021-06-20T05:18:48.060-07:00"
I0620 12:27:26.233880       1 server.go:315]      Found  VM Fingerprint "suqYIWhtPQ8="
I0620 12:27:26.234110       1 server.go:316]      Found  VM CpuPlatform "Intel Haswell"
I0620 12:27:26.234337       1 server.go:319]      Found  VM ServiceAccount "tokenclient@tc-b23369ac.iam.gserviceaccount.com"
I0620 12:27:26.234568       1 server.go:325]      Found Registered External IP Address: 34.136.60.156
I0620 12:27:26.234804       1 server.go:336]      Found  VM Boot Disk Source "https://www.googleapis.com/compute/v1/projects/tc-b23369ac/zones/us-central1-a/disks/tokenclient"
I0620 12:27:26.397698       1 server.go:351]     Found Disk Image https://www.googleapis.com/compute/v1/projects/cos-cloud/global/images/cos-stable-81-12871-119-0
I0620 12:27:26.398125       1 server.go:363]      Derived Image Hash from metadata mSS9owqshEUCRpD5VSR+7vBN9wTcOG88lSa0PZdnHyo=
I0620 12:27:26.398360       1 server.go:625] ======= ProvideSigningKey ======== da48f901-02bc-4cb3-b0a5-e7408e36847b
I0620 12:27:26.398597       1 server.go:626]      client provided uid: da48f901-02bc-4cb3-b0a5-e7408e36847b
I0620 12:27:26.398840       1 server.go:629]      From InstanceID 5055893581146000589
I0620 12:27:26.399079       1 server.go:636]      SigningKey -----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAskAZoYhW0Az0cMiJ5j/q
x2ILGFm12NbitcxFzGzRsap0qZeqtexKJlupRKGvaAp0rP5OhEdZmSfu82UO4Nuc
iylORXRKdad89IlGUPHsrraTlrZG8f9j2f/C36XRv+xUpgwA+3elPl7bTylNd/LI
EGz42xJGQ4v3NSgzlXh1SZtHROQajaKZTwscHc6NAJCBJ2wVmCv07jrfxsRos+Fn
SQCJfEuXyVFM0fhjR1hkJchlU2Sv2QQHgsJlc9S0eqtpc4InZX2dpZQa2zn5uHxU
1jb7Mu64nBCx2CltUUnohV4ixFpQKEVOiY0tCX+lWUhL1quGeG9SYHA7BMCtP+QX
/QIDAQAB
-----END PUBLIC KEY-----
I0620 12:27:26.399384       1 server.go:637]      SigningKey Attestation /1RDR4AXACIAC7fZnsWSnGeiDxFdRxDMcgYW5W9Zqs9WF5VQ8rWAF9W1AAAAAAAAAAfCfgAAAAkAAAAAASAWBREAFigAACIACxJ35Q0gD5WVgy5KiGEvrofsoicQlyixuP5SQ+mrqHTrACIAC8dsgoWKAifI6sA4N9H87xyJug0m6N4NxYEKsUCrK9LE
I0620 12:27:26.399601       1 server.go:638]      SigningKey Signature qmEFDw7Zov+qa8DQh+aXnGGN+XT7D2hULHSB+EsMH9o5FwjoJUBw5hK71wrNix6WHEmAZz8RuAHhAn637Nb1VegEzWUi11QP366NAv29Iy/pzWl63EBpWEFPha7BrtiGPadZ36DnImgbfAJW5QM0FvBaeOgdlr6FWBPczxRWY89U2IWaNJmAWDmAE5uFL3dYONrSDXBAhXKOuDOg+tu9hx7ItmPUwQRYPBd+0KAIv4wHDv0pyaDz3Fx4HLBORVBkIUedxg9XSvJrgAJPUx4WymKnsTjYBtBfw3jXeZ1YClpfj77+4T9mdTh+C2NZevNLblLrITVPDJvNUg47NNxo6A==
I0620 12:27:26.399849       1 server.go:645]      Read and Decode (attestion)
I0620 12:27:26.400152       1 server.go:650]      Attestation att.AttestedCertifyInfo.QualifiedName: c76c82858a0227c8eac03837d1fcef1c89ba0d26e8de0dc5810ab140ab2bd2c4
I0620 12:27:26.400371       1 server.go:658]      Decoding PublicKey for AK ======== da48f901-02bc-4cb3-b0a5-e7408e36847b
I0620 12:27:26.400859       1 server.go:677]      Attestation of Signing Key Verified
I0620 12:27:26.401177       1 server.go:709]      Attestation MatchesPublic true
I0620 12:27:26.401386       1 server.go:713]      Returning ProvideSigningKeyResponse ======== da48f901-02bc-4cb3-b0a5-e7408e36847b
```
