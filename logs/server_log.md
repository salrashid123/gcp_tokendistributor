### Sample TokenServer log
(in reverse order)


```logs
I0618 14:03:04.162539       1 server.go:709]      Returning ProvideSigningKeyResponse ======== d136c38d-0d5f-4fab-ba8b-3528b9b36a80
I0618 14:03:04.162524       1 server.go:705]      Attestation MatchesPublic true
I0618 14:03:04.162412       1 server.go:673]      Attestation of Signing Key Verified
I0618 14:03:04.157883       1 server.go:654]      Decoding PublicKey for AK ======== d136c38d-0d5f-4fab-ba8b-3528b9b36a80
I0618 14:03:04.157854       1 server.go:646]      Attestation att.AttestedCertifyInfo.QualifiedName: 3354525f71413005b32310b7f89cda41ddcae6f58875d4514c6f7b56f9a9f030
I0618 14:03:04.155688       1 server.go:641]      Read and Decode (attestion)
I0618 14:03:04.155641       1 server.go:634]      SigningKey Signature PrgLULe1KIgoEEVfufaSXSNEXC8vdzJIRVp0wYYp80pfg08Q/0vPrc8r9ANFHogWuMC2E16rpne8Bqyvv5ijEy9IOvVNP9dMyftBwPGYcosGXO+mT8S5AiTa4XXWlf6+lywx9k2MApjsKKewwKw7m2HiaoRmrmeSrABhHeX3fgcuTpxuEZN5ymVTA4m6FaO2M9dXfnmf1vNN6aGub/ryKO0keD+7CxgQ2mHS0DncWsiH5BhsCMobYylvAwo66IVOsruR5Fta4y/vokbM6kBWnMMSThaAlBh/PNMlNKOyc773+jexJD9bGL7Agy2u8xYB7/I8m4LdMcSXMqWZF4TEBg==
I0618 14:03:04.155501       1 server.go:633]      SigningKey Attestation /1RDR4AXACIAC2kZf8zS+8Uze0YD/SFxOWzL4QhTQSsq4J3skbGQDVYXAAAAAAAAAAGByQAAAAkAAAAAASAWBREAFigAACIAC0EGPfl8ZoddNbJ2D6lO1hEuBAJT3Yqc00d9xHrsdsqRACIACzNUUl9xQTAFsyMQt/ic2kHdyub1iHXUUUxve1b5qfAw
-----END PUBLIC KEY-----
aQIDAQAB
B7yX0Jufpdr/vyLY4B6jXUHyWVdmx7OvbH5bsx5rx3Q63yk4RIk8saCnMOo6bBNL
YIhmMj/Ktce50BtMpzlYgYJ69VrrCBKnYg92Uhutc/mr50OBClArJ5bpjPz0q3/s
kOKOpEunt8kYAv3p3HruIdA3r9OZ8d0cuayH2wVNW32uX5BBj0TiEeS1loFS8Ajd
Z8krJJved4n+Ex281AakEA+tHtRDj9PLjSZYOeuLlQYT609K5sjP47+SMCRHLqK0
+mgn/poWQayOBdaYLHurwVSbZOgiD5wm9LPRFF50ccokSwsRlaFce4WRcGvaGs4a
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5+ce3F9mgC3R3TWwvDHh
I0618 14:03:04.155472       1 server.go:632]      SigningKey -----BEGIN PUBLIC KEY-----
I0618 14:03:04.155464       1 server.go:625]      From InstanceID 221808688638269893
I0618 14:03:04.155455       1 server.go:622]      client provided uid: d136c38d-0d5f-4fab-ba8b-3528b9b36a80
I0618 14:03:04.155447       1 server.go:621] ======= ProvideSigningKey ======== d136c38d-0d5f-4fab-ba8b-3528b9b36a80
I0618 14:03:04.155431       1 server.go:359]      Derived Image Hash from metadata 2l1+GgcAz2uXy4eiVc+5EnzYEGpP1cLXzEuSNB1OVyQ=
I0618 14:03:04.155371       1 server.go:347]     Found Disk Image https://www.googleapis.com/compute/v1/projects/cos-cloud/global/images/cos-stable-81-12871-119-0
I0618 14:03:03.990470       1 server.go:332]      Found  VM Boot Disk Source "https://www.googleapis.com/compute/v1/projects/tc-78966d6a/zones/us-central1-a/disks/tokenclient"
I0618 14:03:03.990444       1 server.go:321]      Found Registered External IP Address: 35.225.46.21
I0618 14:03:03.990396       1 server.go:315]      Found  VM ServiceAccount "tokenclient@tc-78966d6a.iam.gserviceaccount.com"
I0618 14:03:03.990366       1 server.go:312]      Found  VM CpuPlatform "Intel Haswell"
I0618 14:03:03.990350       1 server.go:311]      Found  VM Fingerprint "ZQBUvABlSnM="
I0618 14:03:03.990306       1 server.go:310]      Found  VM CreationTimestamp "2021-06-18T07:01:16.023-07:00"
I0618 14:03:03.990269       1 server.go:309]      Found  VM instanceID "221808688638269893"
I0618 14:03:03.838445       1 server.go:293]      Looking up InstanceID using GCE APIs for instanceID 221808688638269893
I0618 14:03:03.838418       1 server.go:282]      Client Peer Address [35.225.46.21:33382] - Subject[tokenclienta@otherdomain.com] - SerialNumber [5] Validated
I0618 14:03:03.838357       1 server.go:273]      Using mTLS Client cert Peer IP and SerialNumber
I0618 14:03:03.837961       1 server.go:257]     Verified PeerIP 35.225.46.21:33382
I0618 14:03:03.837724       1 server.go:245]      TLS Peer IP Check
I0618 14:03:03.791145       1 server.go:224]      Looking up Firestore Collection foo for instanceID 221808688638269893
E0618 14:03:03.791111       1 server.go:186]      OIDC doc has Audience [https://tokenserver]   Issuer [https://accounts.google.com] and SubjectEmail [tokenclient@tc-78966d6a.iam.gserviceaccount.com]
I0618 14:03:03.790349       1 server.go:173]      Found OIDC KeyID  19fe2a7b6795239606ca0a750794a7bd9fd95961
I0618 14:03:03.479252       1 server.go:608]      Returning ProvideQuoteResponse ======== d136c38d-0d5f-4fab-ba8b-3528b9b36a80
I0618 14:03:03.479243       1 server.go:795]      <-- End verifyQuote()
I0618 14:03:03.479216       1 server.go:794]      Attestation Signature Verified 
I0618 14:03:03.478524       1 server.go:763]      Decoding PublicKey for AK ========
I0618 14:03:03.478506       1 server.go:761]      sha256 of Expected PCR Value: --> 2ba7022b59f2158786ea3ea29a7ad12ff0c6c9d6682da6555d8926075b643b1f
I0618 14:03:03.478471       1 server.go:760]      Expected PCR Value:           --> 24af52a4f429b71a3184a6d64cddad17e54ea030e2aa6576bf3a5a3d8bd3328f
I0618 14:03:03.478449       1 server.go:743]      Attestation Hash: 2ba7022b59f2158786ea3ea29a7ad12ff0c6c9d6682da6555d8926075b643b1f 
I0618 14:03:03.478362       1 server.go:742]      Attestation PCR#: [0] 
I0618 14:03:03.478344       1 server.go:741]      Attestation ExtraData (nonce): 2a11a844-2c97-4069-b5ba-b6db5597f9b1 
I0618 14:03:03.478307       1 server.go:734]      Read and Decode (attestion)
I0618 14:03:03.478298       1 server.go:722]      --> Starting verifyQuote()
I0618 14:03:03.478286       1 server.go:584]      From InstanceID 221808688638269893
I0618 14:03:03.478253       1 server.go:582] ======= ProvideQuote ======== d136c38d-0d5f-4fab-ba8b-3528b9b36a80
I0618 14:03:03.477276       1 server.go:359]      Derived Image Hash from metadata 2l1+GgcAz2uXy4eiVc+5EnzYEGpP1cLXzEuSNB1OVyQ=
I0618 14:03:03.477204       1 server.go:347]     Found Disk Image https://www.googleapis.com/compute/v1/projects/cos-cloud/global/images/cos-stable-81-12871-119-0
I0618 14:03:03.328320       1 server.go:332]      Found  VM Boot Disk Source "https://www.googleapis.com/compute/v1/projects/tc-78966d6a/zones/us-central1-a/disks/tokenclient"
I0618 14:03:03.328307       1 server.go:321]      Found Registered External IP Address: 35.225.46.21
I0618 14:03:03.328293       1 server.go:315]      Found  VM ServiceAccount "tokenclient@tc-78966d6a.iam.gserviceaccount.com"
I0618 14:03:03.328279       1 server.go:312]      Found  VM CpuPlatform "Intel Haswell"
I0618 14:03:03.328249       1 server.go:311]      Found  VM Fingerprint "ZQBUvABlSnM="
I0618 14:03:03.327881       1 server.go:310]      Found  VM CreationTimestamp "2021-06-18T07:01:16.023-07:00"
I0618 14:03:03.327843       1 server.go:309]      Found  VM instanceID "221808688638269893"
I0618 14:03:03.201966       1 server.go:293]      Looking up InstanceID using GCE APIs for instanceID 221808688638269893
I0618 14:03:03.201541       1 server.go:282]      Client Peer Address [35.225.46.21:33382] - Subject[tokenclienta@otherdomain.com] - SerialNumber [5] Validated
I0618 14:03:03.201084       1 server.go:273]      Using mTLS Client cert Peer IP and SerialNumber
I0618 14:03:03.200537       1 server.go:257]     Verified PeerIP 35.225.46.21:33382
I0618 14:03:03.199809       1 server.go:245]      TLS Peer IP Check
I0618 14:03:03.154425       1 server.go:224]      Looking up Firestore Collection foo for instanceID 221808688638269893
E0618 14:03:03.154397       1 server.go:186]      OIDC doc has Audience [https://tokenserver]   Issuer [https://accounts.google.com] and SubjectEmail [tokenclient@tc-78966d6a.iam.gserviceaccount.com]
I0618 14:03:03.154140       1 server.go:173]      Found OIDC KeyID  19fe2a7b6795239606ca0a750794a7bd9fd95961
I0618 14:03:03.119582       1 server.go:567]      Returning OfferQuoteResponse ======== d136c38d-0d5f-4fab-ba8b-3528b9b36a80
I0618 14:03:03.119566       1 server.go:556]      From InstanceID 221808688638269893
I0618 14:03:03.119547       1 server.go:553] ======= OfferQuote ========  d136c38d-0d5f-4fab-ba8b-3528b9b36a80
I0618 14:03:03.119405       1 server.go:359]      Derived Image Hash from metadata 2l1+GgcAz2uXy4eiVc+5EnzYEGpP1cLXzEuSNB1OVyQ=
I0618 14:03:03.119246       1 server.go:347]     Found Disk Image https://www.googleapis.com/compute/v1/projects/cos-cloud/global/images/cos-stable-81-12871-119-0
I0618 14:03:02.966455       1 server.go:332]      Found  VM Boot Disk Source "https://www.googleapis.com/compute/v1/projects/tc-78966d6a/zones/us-central1-a/disks/tokenclient"
I0618 14:03:02.966016       1 server.go:321]      Found Registered External IP Address: 35.225.46.21
I0618 14:03:02.965932       1 server.go:315]      Found  VM ServiceAccount "tokenclient@tc-78966d6a.iam.gserviceaccount.com"
I0618 14:03:02.965913       1 server.go:312]      Found  VM CpuPlatform "Intel Haswell"
I0618 14:03:02.965859       1 server.go:311]      Found  VM Fingerprint "ZQBUvABlSnM="
I0618 14:03:02.965825       1 server.go:310]      Found  VM CreationTimestamp "2021-06-18T07:01:16.023-07:00"
I0618 14:03:02.965239       1 server.go:309]      Found  VM instanceID "221808688638269893"
I0618 14:03:02.802702       1 server.go:293]      Looking up InstanceID using GCE APIs for instanceID 221808688638269893
I0618 14:03:02.802522       1 server.go:282]      Client Peer Address [35.225.46.21:33382] - Subject[tokenclienta@otherdomain.com] - SerialNumber [5] Validated
I0618 14:03:02.802393       1 server.go:273]      Using mTLS Client cert Peer IP and SerialNumber
I0618 14:03:02.802223       1 server.go:257]     Verified PeerIP 35.225.46.21:33382
I0618 14:03:02.801995       1 server.go:245]      TLS Peer IP Check
I0618 14:03:02.742881       1 server.go:224]      Looking up Firestore Collection foo for instanceID 221808688638269893
E0618 14:03:02.742847       1 server.go:186]      OIDC doc has Audience [https://tokenserver]   Issuer [https://accounts.google.com] and SubjectEmail [tokenclient@tc-78966d6a.iam.gserviceaccount.com]
I0618 14:03:02.742320       1 server.go:173]      Found OIDC KeyID  19fe2a7b6795239606ca0a750794a7bd9fd95961
I0618 14:03:02.739288       1 server.go:540]      Returning ActivateCredentialResponse ======== d136c38d-0d5f-4fab-ba8b-3528b9b36a80
I0618 14:03:02.739278       1 server.go:535]      Verified Quote
I0618 14:03:02.739250       1 server.go:795]      <-- End verifyQuote()
I0618 14:03:02.739219       1 server.go:794]      Attestation Signature Verified 
I0618 14:03:02.737636       1 server.go:763]      Decoding PublicKey for AK ========
I0618 14:03:02.737571       1 server.go:761]      sha256 of Expected PCR Value: --> 2ba7022b59f2158786ea3ea29a7ad12ff0c6c9d6682da6555d8926075b643b1f
I0618 14:03:02.737516       1 server.go:760]      Expected PCR Value:           --> 24af52a4f429b71a3184a6d64cddad17e54ea030e2aa6576bf3a5a3d8bd3328f
I0618 14:03:02.737435       1 server.go:743]      Attestation Hash: 2ba7022b59f2158786ea3ea29a7ad12ff0c6c9d6682da6555d8926075b643b1f 
I0618 14:03:02.737366       1 server.go:742]      Attestation PCR#: [0] 
I0618 14:03:02.737298       1 server.go:741]      Attestation ExtraData (nonce): LSjFbcXoEF 
I0618 14:03:02.737247       1 server.go:734]      Read and Decode (attestion)
I0618 14:03:02.737232       1 server.go:722]      --> Starting verifyQuote()
I0618 14:03:02.737179       1 server.go:515]      From InstanceID 221808688638269893
I0618 14:03:02.737162       1 server.go:512]      Secret LSjFbcXoEF
I0618 14:03:02.737149       1 server.go:511] ======= ActivateCredential ======== d136c38d-0d5f-4fab-ba8b-3528b9b36a80
I0618 14:03:02.737114       1 server.go:359]      Derived Image Hash from metadata 2l1+GgcAz2uXy4eiVc+5EnzYEGpP1cLXzEuSNB1OVyQ=
I0618 14:03:02.737059       1 server.go:347]     Found Disk Image https://www.googleapis.com/compute/v1/projects/cos-cloud/global/images/cos-stable-81-12871-119-0
I0618 14:03:02.581078       1 server.go:332]      Found  VM Boot Disk Source "https://www.googleapis.com/compute/v1/projects/tc-78966d6a/zones/us-central1-a/disks/tokenclient"
I0618 14:03:02.581032       1 server.go:321]      Found Registered External IP Address: 35.225.46.21
I0618 14:03:02.581018       1 server.go:315]      Found  VM ServiceAccount "tokenclient@tc-78966d6a.iam.gserviceaccount.com"
I0618 14:03:02.581005       1 server.go:312]      Found  VM CpuPlatform "Intel Haswell"
I0618 14:03:02.580993       1 server.go:311]      Found  VM Fingerprint "ZQBUvABlSnM="
I0618 14:03:02.580977       1 server.go:310]      Found  VM CreationTimestamp "2021-06-18T07:01:16.023-07:00"
I0618 14:03:02.580938       1 server.go:309]      Found  VM instanceID "221808688638269893"
I0618 14:03:02.436717       1 server.go:293]      Looking up InstanceID using GCE APIs for instanceID 221808688638269893
I0618 14:03:02.436692       1 server.go:282]      Client Peer Address [35.225.46.21:33382] - Subject[tokenclienta@otherdomain.com] - SerialNumber [5] Validated
I0618 14:03:02.436664       1 server.go:273]      Using mTLS Client cert Peer IP and SerialNumber
I0618 14:03:02.436642       1 server.go:257]     Verified PeerIP 35.225.46.21:33382
I0618 14:03:02.436601       1 server.go:245]      TLS Peer IP Check
I0618 14:03:02.373185       1 server.go:224]      Looking up Firestore Collection foo for instanceID 221808688638269893
E0618 14:03:02.373155       1 server.go:186]      OIDC doc has Audience [https://tokenserver]   Issuer [https://accounts.google.com] and SubjectEmail [tokenclient@tc-78966d6a.iam.gserviceaccount.com]
I0618 14:03:02.372635       1 server.go:173]      Found OIDC KeyID  19fe2a7b6795239606ca0a750794a7bd9fd95961
I0618 14:03:01.303550       1 server.go:495]      Returning MakeCredentialResponse ======== d136c38d-0d5f-4fab-ba8b-3528b9b36a80
I0618 14:03:01.301097       1 server.go:865]      <-- End makeCredential()
I0618 14:03:01.301030       1 server.go:864]      encryptedSecret0 0e6c8441380a6d1efd15bd4af55718531f28e53a0bdbe2a185553998f1ed61894df62ad217ea9313be3effa81fcd7c30f09c65738b00f91a700f97461f7a5df9e35f851029f04af4b3089877543dc3b8728dc4412a155db4e16201d2395dc775b49d35207db35a7cc86bd2a8ac2c2b6f9b9f1c66520d4aff1f6abc8c1e7213f6e73fdc7afac784c50cf9a8c9a14d6aacd87a1af9e1c02745fe3c870c1d8cb395b4ce70df7da3e3d67820ffdbb91491cc6179f4924dcdfc6441b4a31c2a9b241d112c822e451ccf8202a03cce6abbc2fdafbc95d441103b9772704c17168de154634007c23a59a2c829a88a21472d05f5a23f13d8ca0b6b56ef9e0f8c4f56b3aa
I0618 14:03:01.300998       1 server.go:863]      credBlob 00207a890b11c20fd56d6a31214c9b8c70c19e05cdabda263d11f6b4cfefbfa949a1068e380b4ee7dfee3cb55d2a
I0618 14:03:01.297764       1 server.go:856]      MakeCredential Start
I0618 14:03:01.297734       1 server.go:854]      Loaded AK KeyName 000bf0d0b4890652316cd2a46445b17e34ca909e05edb508a522c59cf4c13aeca0cf
I0618 14:03:01.294865       1 server.go:845]      AK Default parameter match template
-----END PUBLIC KEY-----
mwIDAQAB
EKvXAPE2tryvCNrToAdv4FxVq6YosqNU49vCeJLrJ5kgTnH5bW8pqOucqAhd9OmM
9+q9CSCQ3pztQIQHhiJ8Uojb8UeVkXkgWfBF2XFDrU5M4+DZwUjK0GD+77jMKEJM
3TQnbQK8N2HehOrVBCLf8Cyf6AitzAioOLDlZ4yApmwKvWoI5CvqmiPrT6yzC/bW
HsH+n72RlqEl3vzz0kEyyhERnm6Gd4Kr8LkDHX1HQ1m5WGMGNa4W6SHhCGu866pf
kJf0ns+W/0voi4k2rC1e3u+Ahqf4j8jWlGe14xOmwS/JQWNGgz7wUIoUJr1ihXNt
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsw9T6q74bUsuOuJJn+ou
-----BEGIN PUBLIC KEY-----
I0618 14:03:01.294825       1 server.go:842]      Decoded AkPub: 
I0618 14:03:01.294717       1 server.go:820]      Read (akPub) from request
I0618 14:03:01.283701       1 server.go:802]      Read (ekPub) from request
I0618 14:03:01.283695       1 server.go:801]      --> Starting makeCredential()
I0618 14:03:01.283675       1 server.go:479]      Verified EkPub from GCE API matches ekPub from Client
-----END PUBLIC KEY-----
+wIDAQAB
X/cB2y9/xKQR3KZk0Bs3yxz/bPLaljlaD/ImQYoy3Pb4CtLO0k12XWdLhkoiGyeH
1bdHBumeFIIfl/vpSW2svlMWHYtRMqCsMqJ/9TqP736J9KmhUVxSpHKXGNmT9gc5
OvH/RC2C0b0U9iGXvwuGOvdqCrYPHubrMMbu1wGtf1rbft7dF1dlp6PSnjNEpR99
R6fPwLRHkKuYieYhwiaaNuB86VWXOmgkLYQHGTuOFSBSkdo92MlHn104NqQpemwZ
aNkm/cTiCmk5WCbi8cSZf4mkdCVFsGLu7hyaaIE/BvB51yksLsgqgEQpAFULeWAM
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0M0WINcvrPwfK4GGPfXK
-----BEGIN PUBLIC KEY-----
I0618 14:03:01.283658       1 server.go:473]      EKPubPEM: 
I0618 14:03:01.283421       1 server.go:452]      Decoding ekPub from client
-----END PUBLIC KEY-----
+wIDAQAB
X/cB2y9/xKQR3KZk0Bs3yxz/bPLaljlaD/ImQYoy3Pb4CtLO0k12XWdLhkoiGyeH
1bdHBumeFIIfl/vpSW2svlMWHYtRMqCsMqJ/9TqP736J9KmhUVxSpHKXGNmT9gc5
OvH/RC2C0b0U9iGXvwuGOvdqCrYPHubrMMbu1wGtf1rbft7dF1dlp6PSnjNEpR99
R6fPwLRHkKuYieYhwiaaNuB86VWXOmgkLYQHGTuOFSBSkdo92MlHn104NqQpemwZ
aNkm/cTiCmk5WCbi8cSZf4mkdCVFsGLu7hyaaIE/BvB51yksLsgqgEQpAFULeWAM
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0M0WINcvrPwfK4GGPfXK
-----BEGIN PUBLIC KEY-----
I0618 14:03:01.283312       1 server.go:450]      Acquired PublicKey from GCP API: 
I0618 14:03:01.102252       1 server.go:431]      From InstanceID 221808688638269893
I0618 14:03:01.102241       1 server.go:428]      Registry size 0
I0618 14:03:01.102222       1 server.go:427]      Got AKName 000bf0d0b4890652316cd2a46445b17e34ca909e05edb508a522c59cf4c13aeca0cf
I0618 14:03:01.102197       1 server.go:426] ======= MakeCredential ======== d136c38d-0d5f-4fab-ba8b-3528b9b36a80
I0618 14:03:01.100906       1 server.go:359]      Derived Image Hash from metadata 2l1+GgcAz2uXy4eiVc+5EnzYEGpP1cLXzEuSNB1OVyQ=
I0618 14:03:01.100830       1 server.go:347]     Found Disk Image https://www.googleapis.com/compute/v1/projects/cos-cloud/global/images/cos-stable-81-12871-119-0
I0618 14:03:00.914042       1 server.go:332]      Found  VM Boot Disk Source "https://www.googleapis.com/compute/v1/projects/tc-78966d6a/zones/us-central1-a/disks/tokenclient"
I0618 14:03:00.913947       1 server.go:321]      Found Registered External IP Address: 35.225.46.21
I0618 14:03:00.913933       1 server.go:315]      Found  VM ServiceAccount "tokenclient@tc-78966d6a.iam.gserviceaccount.com"
I0618 14:03:00.913733       1 server.go:312]      Found  VM CpuPlatform "Intel Haswell"
I0618 14:03:00.913720       1 server.go:311]      Found  VM Fingerprint "ZQBUvABlSnM="
I0618 14:03:00.913705       1 server.go:310]      Found  VM CreationTimestamp "2021-06-18T07:01:16.023-07:00"
I0618 14:03:00.913664       1 server.go:309]      Found  VM instanceID "221808688638269893"
I0618 14:03:00.741929       1 server.go:293]      Looking up InstanceID using GCE APIs for instanceID 221808688638269893
I0618 14:03:00.741908       1 server.go:282]      Client Peer Address [35.225.46.21:33382] - Subject[tokenclienta@otherdomain.com] - SerialNumber [5] Validated
I0618 14:03:00.741878       1 server.go:273]      Using mTLS Client cert Peer IP and SerialNumber
I0618 14:03:00.741854       1 server.go:257]     Verified PeerIP 35.225.46.21:33382
I0618 14:03:00.741817       1 server.go:245]      TLS Peer IP Check
I0618 14:03:00.685070       1 server.go:224]      Looking up Firestore Collection foo for instanceID 221808688638269893
E0618 14:03:00.684989       1 server.go:186]      OIDC doc has Audience [https://tokenserver]   Issuer [https://accounts.google.com] and SubjectEmail [tokenclient@tc-78966d6a.iam.gserviceaccount.com]
I0618 14:03:00.684245       1 server.go:173]      Found OIDC KeyID  19fe2a7b6795239606ca0a750794a7bd9fd95961
I0618 14:03:00.394654       1 server.go:415] <<<--- GetToken ======= e3dc87b8-d03d-11eb-a9de-0242ac110002
I0618 14:03:00.394313       1 server.go:397]      Got rpc: RequestID e3dc87b8-d03d-11eb-a9de-0242ac110002 for subject 115989203236638951508 and email tokenclient@tc-78966d6a.iam.gserviceaccount.com for instanceID 221808688638269893
I0618 14:03:00.394228       1 server.go:391] ======= GetToken ---> e3dc87b8-d03d-11eb-a9de-0242ac110002
I0618 14:03:00.394161       1 server.go:359]      Derived Image Hash from metadata 2l1+GgcAz2uXy4eiVc+5EnzYEGpP1cLXzEuSNB1OVyQ=
I0618 14:03:00.394087       1 server.go:347]     Found Disk Image https://www.googleapis.com/compute/v1/projects/cos-cloud/global/images/cos-stable-81-12871-119-0
I0618 14:03:00.229149       1 server.go:332]      Found  VM Boot Disk Source "https://www.googleapis.com/compute/v1/projects/tc-78966d6a/zones/us-central1-a/disks/tokenclient"
I0618 14:03:00.228936       1 server.go:321]      Found Registered External IP Address: 35.225.46.21
I0618 14:03:00.228863       1 server.go:315]      Found  VM ServiceAccount "tokenclient@tc-78966d6a.iam.gserviceaccount.com"
I0618 14:03:00.228841       1 server.go:312]      Found  VM CpuPlatform "Intel Haswell"
I0618 14:03:00.228823       1 server.go:311]      Found  VM Fingerprint "ZQBUvABlSnM="
I0618 14:03:00.228778       1 server.go:310]      Found  VM CreationTimestamp "2021-06-18T07:01:16.023-07:00"
I0618 14:03:00.228731       1 server.go:309]      Found  VM instanceID "221808688638269893"
I0618 14:03:00.091970       1 server.go:293]      Looking up InstanceID using GCE APIs for instanceID 221808688638269893
I0618 14:03:00.091934       1 server.go:282]      Client Peer Address [35.225.46.21:33382] - Subject[tokenclienta@otherdomain.com] - SerialNumber [5] Validated
I0618 14:03:00.091906       1 server.go:273]      Using mTLS Client cert Peer IP and SerialNumber
I0618 14:03:00.091881       1 server.go:257]     Verified PeerIP 35.225.46.21:33382
I0618 14:03:00.091843       1 server.go:245]      TLS Peer IP Check
I0618 14:02:59.944696       1 server.go:224]      Looking up Firestore Collection foo for instanceID 221808688638269893
E0618 14:02:59.944672       1 server.go:186]      OIDC doc has Audience [https://tokenserver]   Issuer [https://accounts.google.com] and SubjectEmail [tokenclient@tc-78966d6a.iam.gserviceaccount.com]
I0618 14:02:59.944515       1 server.go:173]      Found OIDC KeyID  19fe2a7b6795239606ca0a750794a7bd9fd95961
E0618 14:02:49.982667       1 server.go:234] ERROR:  Could not find instanceID new Firestore Client 221808688638269893
I0618 14:02:49.943165       1 server.go:224]      Looking up Firestore Collection foo for instanceID 221808688638269893
E0618 14:02:49.943006       1 server.go:186]      OIDC doc has Audience [https://tokenserver]   Issuer [https://accounts.google.com] and SubjectEmail [tokenclient@tc-78966d6a.iam.gserviceaccount.com]
I0618 14:02:49.942551       1 server.go:173]      Found OIDC KeyID  19fe2a7b6795239606ca0a750794a7bd9fd95961
E0618 14:02:39.986307       1 server.go:234] ERROR:  Could not find instanceID new Firestore Client 221808688638269893
I0618 14:02:39.941381       1 server.go:224]      Looking up Firestore Collection foo for instanceID 221808688638269893
E0618 14:02:39.941222       1 server.go:186]      OIDC doc has Audience [https://tokenserver]   Issuer [https://accounts.google.com] and SubjectEmail [tokenclient@tc-78966d6a.iam.gserviceaccount.com]
I0618 14:02:39.940791       1 server.go:173]      Found OIDC KeyID  19fe2a7b6795239606ca0a750794a7bd9fd95961
E0618 14:02:30.023309       1 server.go:234] ERROR:  Could not find instanceID new Firestore Client 221808688638269893
I0618 14:02:29.941079       1 server.go:224]      Looking up Firestore Collection foo for instanceID 221808688638269893
E0618 14:02:29.941039       1 server.go:186]      OIDC doc has Audience [https://tokenserver]   Issuer [https://accounts.google.com] and SubjectEmail [tokenclient@tc-78966d6a.iam.gserviceaccount.com]
I0618 14:02:29.940068       1 server.go:173]      Found OIDC KeyID  19fe2a7b6795239606ca0a750794a7bd9fd95961
E0618 14:02:20.027713       1 server.go:234] ERROR:  Could not find instanceID new Firestore Client 221808688638269893
I0618 14:02:19.946913       1 server.go:224]      Looking up Firestore Collection foo for instanceID 221808688638269893
E0618 14:02:19.945239       1 server.go:186]      OIDC doc has Audience [https://tokenserver]   Issuer [https://accounts.google.com] and SubjectEmail [tokenclient@tc-78966d6a.iam.gserviceaccount.com]
I0618 14:02:19.944615       1 server.go:173]      Found OIDC KeyID  19fe2a7b6795239606ca0a750794a7bd9fd95961
E0618 14:02:10.038833       1 server.go:234] ERROR:  Could not find instanceID new Firestore Client 221808688638269893
I0618 14:02:09.947777       1 server.go:224]      Looking up Firestore Collection foo for instanceID 221808688638269893
E0618 14:02:09.947680       1 server.go:186]      OIDC doc has Audience [https://tokenserver]   Issuer [https://accounts.google.com] and SubjectEmail [tokenclient@tc-78966d6a.iam.gserviceaccount.com]
I0618 14:02:09.944216       1 server.go:173]      Found OIDC KeyID  19fe2a7b6795239606ca0a750794a7bd9fd95961
E0618 14:02:00.170253       1 server.go:234] ERROR:  Could not find instanceID new Firestore Client 221808688638269893
I0618 14:01:59.949841       1 server.go:224]      Looking up Firestore Collection foo for instanceID 221808688638269893
E0618 14:01:59.946866       1 server.go:186]      OIDC doc has Audience [https://tokenserver]   Issuer [https://accounts.google.com] and SubjectEmail [tokenclient@tc-78966d6a.iam.gserviceaccount.com]
I0618 14:01:59.946593       1 server.go:173]      Found OIDC KeyID  19fe2a7b6795239606ca0a750794a7bd9fd95961
     Startup args:  vmodule:  
     Startup args:  validatePeerSN:  true
     Startup args:  validatePeerIP:  true
     Startup args:  v:  20
     Startup args:  useTPM:  true
     Startup args:  useSecrets:  true
     Startup args:  useMTLS:  true
     Startup args:  useALTS:  false
     Startup args:  tsAudience:  https://tokenserver
     Startup args:  tlsKey:  projects/870060232564/secrets/tls_key
     Startup args:  tlsCertChain:  projects/870060232564/secrets/tls-ca
     Startup args:  tlsCert:  projects/870060232564/secrets/tls_crt
     Startup args:  stderrthreshold:  2
     Startup args:  pcr:  0
     Startup args:  logtostderr:  false
     Startup args:  log_dir:  
     Startup args:  log_backtrace_at:  :0
     Startup args:  jwtIssuedAtJitter:  5
     Startup args:  grpcport:  0.0.0.0:50051
     Startup args:  firestoreProjectId:  ts-3950a2df
     Startup args:  firestoreCollectionName:  foo
     Startup args:  expectedPCRValue:  24af52a4f429b71a3184a6d64cddad17e54ea030e2aa6576bf3a5a3d8bd3328f
     Startup args:  alsologtostderr:  true
I0618 13:50:50.555947       1 server.go:1038] Starting TokenService..
I0618 13:50:50.543025       1 server.go:984]      Enable mTLS...
I0618 13:50:50.395153       1 server.go:916]      Getting certs from Secrets Manager

```
