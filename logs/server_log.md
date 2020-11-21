```logs
2020-11-21T03:03:03.551181863Z I1121 03:03:03.550907       1 server.go:672]      Returning ProvideSigningKeyResponse ========
2020-11-21T03:03:03.551167613Z I1121 03:03:03.550891       1 server.go:668]      Attestation MatchesPublic true
2020-11-21T03:03:03.551148813Z I1121 03:03:03.550819       1 server.go:636]      Attestation of Signing Key Verified
2020-11-21T03:03:03.549576808Z I1121 03:03:03.549333       1 server.go:617]      Decoding PublicKey for AK ========
2020-11-21T03:03:03.549571778Z I1121 03:03:03.549324       1 server.go:609]      Attestation att.AttestedCertifyInfo.QualifiedName: 69ac27ac11da317dbee9a76c941e24bc751ad78a142ad020d09f8ad0c5e0ce34
2020-11-21T03:03:03.549566938Z I1121 03:03:03.549291       1 server.go:604]      Read and Decode (attestion)
2020-11-21T03:03:03.549560248Z I1121 03:03:03.549278       1 server.go:597]      SigningKey Signature E661FrR1MBOj5WuDiimmNDUHvbjBbe1igHZSNwT3VXl6hgcaEEIXhAYRnhy+uVlOeFO0BTEKWRJ2pS5j4eNPUdXLbpi9u/X3Nh/eaatpvLpL1+326mo4CEklmBW89JMFSh8s/KkBnXqXlPZrt/gRBxkhImV5YZs/fCYnsbRcDKsEWpsrOpoSH0U36uNHIto/c9bQiyl9BJiQt9z3+t7Yyz3SyHGx2V1EPaCbtTnNJovGlhZpFTbwKDXXISiA8pBjiLdlwFRp4Ta5uwwPDgsnP6Vaen+eFP4gfNoYGpBP2w2NMykgPhNmggLOMnZkVBQva3KwpbO4rtgjy2bwYWAXaA==
2020-11-21T03:03:03.549553548Z I1121 03:03:03.549262       1 server.go:596]      SigningKey Attestation /1RDR4AXACIAC85te683+jFOYqkMOir17FnTg1O+d7rVB/rvPyyO7TAnAAAAAAAAAAFPBAAAAAkAAAAAASAWBREAFigAACIAC0F0YJikdth/0MmBY8DQaoAVICqOvg6Thgupboy80gBjACIAC2msJ6wR2jF9vumnbJQeJLx1GteKFCrQINCfitDF4M40
2020-11-21T03:03:03.549547608Z 
2020-11-21T03:03:03.549542998Z -----END PUBLIC KEY-----
2020-11-21T03:03:03.549537958Z KQIDAQAB
2020-11-21T03:03:03.549532458Z dPyTWFhgmal1hhtcjOvN5/xFumLD24nCb+5CyX78KARAq3GnFSnow9lLPtAPu7Qp
2020-11-21T03:03:03.549527218Z 3eQffI5uMVTIG5muhifw0E7B3D5JQBz0T9j7AcCssbciw3S7oqrLEDzBsc12WfJj
2020-11-21T03:03:03.549522348Z XOKkP1KH7nJVDIncEaxaxV8po16TH7O5zZQGe0RXhrk5ahmlo8GEw5E9A84ItOCL
2020-11-21T03:03:03.549517288Z 9ketfNjdQH9XuBXeg2136qV7rzAqz7RcW4Cn9ZX5tJLtuck/7A9t9WYyXTwR1vuN
2020-11-21T03:03:03.549512058Z f42UheD1KkbRZIcfrgkzGWfH0PHpzzP7QkKOfbCnQA4sMLVBTCv9GMq1EdgkSViH
2020-11-21T03:03:03.549506648Z MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwCOh2qNW59nNw81PIfo4
2020-11-21T03:03:03.549501118Z I1121 03:03:03.549248       1 server.go:595]      SigningKey -----BEGIN PUBLIC KEY-----
2020-11-21T03:03:03.549495288Z I1121 03:03:03.549241       1 server.go:588]      From InstanceID 8030049439212453353
2020-11-21T03:03:03.549477308Z I1121 03:03:03.549233       1 server.go:585]      client provided uid: 42045bef-e12e-488f-a1d8-7ba5405fe6b1
2020-11-21T03:03:03.549460788Z I1121 03:03:03.549215       1 server.go:584] ======= ProvideSigningKey ========
2020-11-21T03:03:03.548998859Z E1121 03:03:03.548913       1 server.go:183]      OIDC doc has Audience [https://tokenserver]   Issuer [https://accounts.google.com] and SubjectEmail [tokenclient@tc-a681c707.iam.gserviceaccount.com]
2020-11-21T03:03:03.548316652Z I1121 03:03:03.548116       1 server.go:170]      Found OIDC KeyID  dedc012d07f52aedfd5f97784e1bcbe23c19724d
2020-11-21T03:03:03.390080695Z I1121 03:03:03.389737       1 server.go:571]      Returning ProvideQuoteResponse ========
2020-11-21T03:03:03.390069115Z I1121 03:03:03.389729       1 server.go:746]      <-- End verifyQuote()
2020-11-21T03:03:03.390063965Z I1121 03:03:03.389712       1 server.go:745]      Attestation Signature Verified 
2020-11-21T03:03:03.390051225Z I1121 03:03:03.389571       1 server.go:726]      Decoding PublicKey for AK ========
2020-11-21T03:03:03.390045565Z I1121 03:03:03.389561       1 server.go:724]      sha256 of Expected PCR Value: --> 00e0758c418aff8b359dbcf0fb9af040ca15e973b02e5630b5dca1775c7e130a
2020-11-21T03:03:03.390040565Z I1121 03:03:03.389552       1 server.go:723]      Expected PCR Value:           --> fcecb56acc303862b30eb342c4990beb50b5e0ab89722449c2d9a73f37b019fe
2020-11-21T03:03:03.390035595Z I1121 03:03:03.389541       1 server.go:706]      Attestation Hash: 00e0758c418aff8b359dbcf0fb9af040ca15e973b02e5630b5dca1775c7e130a 
2020-11-21T03:03:03.390030795Z I1121 03:03:03.389525       1 server.go:705]      Attestation PCR#: [0] 
2020-11-21T03:03:03.390025965Z I1121 03:03:03.389512       1 server.go:704]      Attestation ExtraData (nonce): 851ed301-138c-4c49-866a-3528dbc19cb9 
2020-11-21T03:03:03.390021215Z I1121 03:03:03.389475       1 server.go:697]      Read and Decode (attestion)
2020-11-21T03:03:03.390015215Z I1121 03:03:03.389466       1 server.go:685]      --> Starting verifyQuote()
2020-11-21T03:03:03.389998976Z I1121 03:03:03.389437       1 server.go:547]      From InstanceID 8030049439212453353
2020-11-21T03:03:03.389203678Z I1121 03:03:03.389085       1 server.go:545]      client provided uid: 42045bef-e12e-488f-a1d8-7ba5405fe6b1
2020-11-21T03:03:03.388778920Z I1121 03:03:03.388666       1 server.go:544] ======= ProvideQuote ========
2020-11-21T03:03:03.388761Z E1121 03:03:03.388554       1 server.go:183]      OIDC doc has Audience [https://tokenserver]   Issuer [https://accounts.google.com] and SubjectEmail [tokenclient@tc-a681c707.iam.gserviceaccount.com]
2020-11-21T03:03:03.388175741Z I1121 03:03:03.387923       1 server.go:170]      Found OIDC KeyID  dedc012d07f52aedfd5f97784e1bcbe23c19724d
2020-11-21T03:03:03.352540305Z I1121 03:03:03.352389       1 server.go:529]      Returning OfferQuoteResponse ========
2020-11-21T03:03:03.352535234Z I1121 03:03:03.352340       1 server.go:518]      From InstanceID 8030049439212453353
2020-11-21T03:03:03.352528855Z I1121 03:03:03.352332       1 server.go:515]      client provided uid: 42045bef-e12e-488f-a1d8-7ba5405fe6b1
2020-11-21T03:03:03.352499474Z I1121 03:03:03.352319       1 server.go:514] ======= OfferQuote ========
2020-11-21T03:03:03.352058565Z E1121 03:03:03.351951       1 server.go:183]      OIDC doc has Audience [https://tokenserver]   Issuer [https://accounts.google.com] and SubjectEmail [tokenclient@tc-a681c707.iam.gserviceaccount.com]
2020-11-21T03:03:03.351173967Z I1121 03:03:03.351009       1 server.go:170]      Found OIDC KeyID  dedc012d07f52aedfd5f97784e1bcbe23c19724d
2020-11-21T03:03:03.348284846Z I1121 03:03:03.348009       1 server.go:501]      Returning ActivateCredentialResponse ========
2020-11-21T03:03:03.348278776Z I1121 03:03:03.348001       1 server.go:496]      Verified Quote
2020-11-21T03:03:03.348263656Z I1121 03:03:03.347974       1 server.go:746]      <-- End verifyQuote()
2020-11-21T03:03:03.347738768Z I1121 03:03:03.347664       1 server.go:745]      Attestation Signature Verified 
2020-11-21T03:03:03.347241139Z I1121 03:03:03.347168       1 server.go:726]      Decoding PublicKey for AK ========
2020-11-21T03:03:03.346959560Z I1121 03:03:03.346862       1 server.go:724]      sha256 of Expected PCR Value: --> 00e0758c418aff8b359dbcf0fb9af040ca15e973b02e5630b5dca1775c7e130a
2020-11-21T03:03:03.346628391Z I1121 03:03:03.346553       1 server.go:723]      Expected PCR Value:           --> fcecb56acc303862b30eb342c4990beb50b5e0ab89722449c2d9a73f37b019fe
2020-11-21T03:03:03.346314882Z I1121 03:03:03.346219       1 server.go:706]      Attestation Hash: 00e0758c418aff8b359dbcf0fb9af040ca15e973b02e5630b5dca1775c7e130a 
2020-11-21T03:03:03.345970902Z I1121 03:03:03.345890       1 server.go:705]      Attestation PCR#: [0] 
2020-11-21T03:03:03.345671203Z I1121 03:03:03.345578       1 server.go:704]      Attestation ExtraData (nonce): xKQFDaFpLS 
2020-11-21T03:03:03.345322015Z I1121 03:03:03.345258       1 server.go:697]      Read and Decode (attestion)
2020-11-21T03:03:03.345004896Z I1121 03:03:03.344903       1 server.go:685]      --> Starting verifyQuote()
2020-11-21T03:03:03.344669947Z I1121 03:03:03.344605       1 server.go:481]      From InstanceID 8030049439212453353
2020-11-21T03:03:03.344390688Z I1121 03:03:03.344295       1 server.go:478]      Secret xKQFDaFpLS
2020-11-21T03:03:03.344039199Z I1121 03:03:03.343952       1 server.go:477]      client provided uid: 42045bef-e12e-488f-a1d8-7ba5405fe6b1
2020-11-21T03:03:03.343755699Z I1121 03:03:03.343662       1 server.go:476] ======= ActivateCredential ========
2020-11-21T03:03:03.342890632Z E1121 03:03:03.342804       1 server.go:183]      OIDC doc has Audience [https://tokenserver]   Issuer [https://accounts.google.com] and SubjectEmail [tokenclient@tc-a681c707.iam.gserviceaccount.com]
2020-11-21T03:03:03.342848922Z I1121 03:03:03.342582       1 server.go:170]      Found OIDC KeyID  dedc012d07f52aedfd5f97784e1bcbe23c19724d
2020-11-21T03:03:02.271340793Z I1121 03:03:02.271222       1 server.go:460]      Returning MakeCredentialResponse ========
2020-11-21T03:03:02.269789477Z I1121 03:03:02.269564       1 server.go:816]      <-- End makeCredential()
2020-11-21T03:03:02.269756848Z I1121 03:03:02.269548       1 server.go:815]      encryptedSecret0 8d9eb9b160b43db7686615c3a3699ae5895841bd6bc8bec3baed27d532d4b9db1704a12738ffedf90584a3e34e2abf7850e03e03a9ba1f9081d88608ef6ae41241be46bc9ee447280f282e0f2dd4436118d155964834d58b948041d92d478d11bc3c12e4b81bdaa72f1e6a4c774e6bb7ba1691358adcfa8b512fea143738d5e5f01c1d8ac8a698affebdeaa4c44d5ebf85ee73aa3ffa0cd7ca3fbf6af0bc9b82a5b80af0a08344d66137c2f3609b709c4b0f99fc0655f21dfb7f9bca44f1ad406cb277bc9a8e2887d6580d97217ef20bb040be0e46ca15724a9b05f591ca3ce34d27d5fb5a82534943824f11dbd53a35b51cad2a49e378054eff5962f4d65124
2020-11-21T03:03:02.269694617Z I1121 03:03:02.269501       1 server.go:814]      credBlob 00201c787cac876c44af38c34b7b9be73c5086cf6e8d570ca2d874ad389fbd82ba0fe9dff3a6345124773bdf668d
2020-11-21T03:03:02.265224840Z I1121 03:03:02.265068       1 server.go:807]      MakeCredential Start
2020-11-21T03:03:02.265188710Z I1121 03:03:02.265033       1 server.go:805]      Loaded AK KeyName 000b514bdd0fbb324daced8b40d94eeeffe856c2f8ad85dc11b44b1ce0fc98da45d7
2020-11-21T03:03:02.261515181Z I1121 03:03:02.261301       1 server.go:796]      AK Default parameter match template
2020-11-21T03:03:02.261510402Z -----END PUBLIC KEY-----
2020-11-21T03:03:02.261504962Z TQIDAQAB
2020-11-21T03:03:02.261500131Z 5UNGQri/IPLGFphpxVEV5NSuQV4eByqvQs3cHjUaNJcQOF3rgjphaPS639o0jVDH
2020-11-21T03:03:02.261495522Z +3ApdGC9x8lGwJ34YSFeOZUgtnsMcTvEChGLZYal/hMnVJJ/L+9NsmwzwPWjVfie
2020-11-21T03:03:02.261490981Z xObSnCwDr1C4E656M3dl5Xq+u+goL34p1yI6/yF4eI5txXu+SII3vrZ5ZAWz8RID
2020-11-21T03:03:02.261486371Z iGhBZhYZVqRdK9uySufCkGHPBWelcE8ZeSZMqE8r2vFAuOUe3oO7xLDoEykrKJ3O
2020-11-21T03:03:02.261481771Z loGv8NAcGIM1AN4bGIDZHyh9XuBrUMUscbfOgbPx/HCufkBnbA1DXlKDLpKY+q3h
2020-11-21T03:03:02.261476912Z MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0TcB+op9+5bPkjMV9oay
2020-11-21T03:03:02.261471992Z -----BEGIN PUBLIC KEY-----
2020-11-21T03:03:02.261464392Z I1121 03:03:02.261277       1 server.go:793]      Decoded AkPub: 
2020-11-21T03:03:02.261413682Z I1121 03:03:02.261178       1 server.go:771]      Read (akPub) from request
2020-11-21T03:03:02.203732678Z I1121 03:03:02.202861       1 server.go:753]      Read (ekPub) from request
2020-11-21T03:03:02.203727748Z I1121 03:03:02.202818       1 server.go:752]      --> Starting makeCredential()
2020-11-21T03:03:02.203723318Z I1121 03:03:02.202803       1 server.go:444]      Verified EkPub from GCE API matches ekPub from Client
2020-11-21T03:03:02.203718868Z -----END PUBLIC KEY-----
2020-11-21T03:03:02.203714228Z PQIDAQAB
2020-11-21T03:03:02.203709399Z bwxJUkfYN5QyuEXtMGDD/Y/aZSf0gSdOFjIipGmmCwZMRMBKHLjr1E3WBMUhHEzs
2020-11-21T03:03:02.203704839Z c87G7vHuMtyGWUbEY7NyyFGQBWvwX05qUBHGQ1Bon+GItSOxQaynEl0sESrrCrVP
2020-11-21T03:03:02.203700529Z 97Eq5rYy7T7zogmYZFRzIsQWdGpzvLXc3Y3xnJ2mWYVGv5Ky2OULV0gZRXIqIKrN
2020-11-21T03:03:02.203695939Z 0ENlpKCSFaO976LYprgbinuKdmoBLnK0eePSUZfyFqzpgtOcPUHT5pFeJlXMWVxL
2020-11-21T03:03:02.203691059Z 3DhcoEtEULGr33ScoLb/mnxwKrNEANO0pmNZ7S5Kx01T/kdZEdHNcLb855vSIlM5
2020-11-21T03:03:02.203670129Z MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAz06n5KxZ/L+mK4Ky9Ee4
2020-11-21T03:03:02.203651609Z -----BEGIN PUBLIC KEY-----
2020-11-21T03:03:02.203635209Z I1121 03:03:02.202783       1 server.go:438]      EKPubPEM: 
2020-11-21T03:03:02.202633562Z I1121 03:03:02.202283       1 server.go:417]      Decoding ekPub from client
2020-11-21T03:03:02.202629042Z -----END PUBLIC KEY-----
2020-11-21T03:03:02.202624421Z PQIDAQAB
2020-11-21T03:03:02.202619362Z bwxJUkfYN5QyuEXtMGDD/Y/aZSf0gSdOFjIipGmmCwZMRMBKHLjr1E3WBMUhHEzs
2020-11-21T03:03:02.202602661Z c87G7vHuMtyGWUbEY7NyyFGQBWvwX05qUBHGQ1Bon+GItSOxQaynEl0sESrrCrVP
2020-11-21T03:03:02.202597682Z 97Eq5rYy7T7zogmYZFRzIsQWdGpzvLXc3Y3xnJ2mWYVGv5Ky2OULV0gZRXIqIKrN
2020-11-21T03:03:02.202593092Z 0ENlpKCSFaO976LYprgbinuKdmoBLnK0eePSUZfyFqzpgtOcPUHT5pFeJlXMWVxL
2020-11-21T03:03:02.202588442Z 3DhcoEtEULGr33ScoLb/mnxwKrNEANO0pmNZ7S5Kx01T/kdZEdHNcLb855vSIlM5
2020-11-21T03:03:02.202582602Z MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAz06n5KxZ/L+mK4Ky9Ee4
2020-11-21T03:03:02.202576052Z -----BEGIN PUBLIC KEY-----
2020-11-21T03:03:02.202527551Z I1121 03:03:02.202244       1 server.go:415]      Acquired PublicKey from GCP API: 
2020-11-21T03:03:01.984777429Z I1121 03:03:01.984703       1 server.go:396]      From InstanceID 8030049439212453353
2020-11-21T03:03:01.984761858Z I1121 03:03:01.984669       1 server.go:393]      Registry size 0
2020-11-21T03:03:01.984433529Z I1121 03:03:01.984308       1 server.go:392]      Got AKName 000b514bdd0fbb324daced8b40d94eeeffe856c2f8ad85dc11b44b1ce0fc98da45d7
2020-11-21T03:03:01.984286321Z I1121 03:03:01.984106       1 server.go:391]      client provided uid: 42045bef-e12e-488f-a1d8-7ba5405fe6b1
2020-11-21T03:03:01.984273780Z I1121 03:03:01.984095       1 server.go:390] ======= MakeCredential ========
2020-11-21T03:03:01.984193010Z E1121 03:03:01.984050       1 server.go:183]      OIDC doc has Audience [https://tokenserver]   Issuer [https://accounts.google.com] and SubjectEmail [tokenclient@tc-a681c707.iam.gserviceaccount.com]
2020-11-21T03:03:01.983416673Z I1121 03:03:01.983140       1 server.go:170]      Found OIDC KeyID  dedc012d07f52aedfd5f97784e1bcbe23c19724d
2020-11-21T03:03:01.591925191Z I1121 03:03:01.591323       1 server.go:343]      Derived Image Hash from metadata w2d8AkY9UHODEvADIsUenCxD/Rl08Up6Z2adynF0jpI=
2020-11-21T03:03:01.591475623Z I1121 03:03:01.591266       1 server.go:331]     Found Disk Image https://www.googleapis.com/compute/v1/projects/cos-cloud/global/images/cos-stable-81-12871-119-0
2020-11-21T03:03:01.422926590Z I1121 03:03:01.422713       1 server.go:316]      Found  VM Boot Disk Source "https://www.googleapis.com/compute/v1/projects/tc-a681c707/zones/us-central1-a/disks/tokenclient"
2020-11-21T03:03:01.422921270Z I1121 03:03:01.422701       1 server.go:305]      Found Registered External IP Address: 34.121.169.149
2020-11-21T03:03:01.422915760Z I1121 03:03:01.422688       1 server.go:299]      Found  VM ServiceAccount "tokenclient@tc-a681c707.iam.gserviceaccount.com"
2020-11-21T03:03:01.422906040Z I1121 03:03:01.422676       1 server.go:296]      Found  VM CpuPlatform "Intel Haswell"
2020-11-21T03:03:01.422882401Z I1121 03:03:01.422660       1 server.go:295]      Found  VM Fingerprint "SHfLAXmCLh8="
2020-11-21T03:03:01.422874001Z I1121 03:03:01.422647       1 server.go:294]      Found  VM CreationTimestamp "2020-11-20T19:01:27.539-08:00"
2020-11-21T03:03:01.422819791Z I1121 03:03:01.422606       1 server.go:293]      Found  VM instanceID "8030049439212453353"
2020-11-21T03:03:01.235226724Z I1121 03:03:01.235043       1 server.go:277]      Looking up InstanceID using GCE APIs for instanceID 8030049439212453353
2020-11-21T03:03:01.235220983Z I1121 03:03:01.235011       1 server.go:270]      Client Peer Address [34.121.169.149:48956] - Subject[tokenclienta@otherdomain.com] - SerialNumber [5] Validated
2020-11-21T03:03:01.235214053Z I1121 03:03:01.234978       1 server.go:260]     Verified PeerIP 34.121.169.149:48956
2020-11-21T03:03:01.235172903Z I1121 03:03:01.234937       1 server.go:248]      TLS Client cert Peer IP and SerialNumber
2020-11-21T03:03:01.156744721Z I1121 03:03:01.155812       1 server.go:232]      Looking up Firestore Collection foo for instanceID 8030049439212453353
2020-11-21T03:03:01.156735410Z I1121 03:03:01.155802       1 server.go:230]      Got rpc: RequestID 10cd4b47-2ba6-11eb-b228-0242ac110002 for subject 114965907114681223971 and email tokenclient@tc-a681c707.iam.gserviceaccount.com for instanceID 8030049439212453353
2020-11-21T03:03:01.156677490Z E1121 03:03:01.155769       1 server.go:183]      OIDC doc has Audience [https://tokenserver]   Issuer [https://accounts.google.com] and SubjectEmail [tokenclient@tc-a681c707.iam.gserviceaccount.com]
2020-11-21T03:03:01.154699357Z I1121 03:03:01.154463       1 server.go:170]      Found OIDC KeyID  dedc012d07f52aedfd5f97784e1bcbe23c19724d
2020-11-21T03:02:51.238735697Z E1121 03:02:51.238561       1 server.go:241] ERROR:  Could not find instanceID new Firestore Client 8030049439212453353
2020-11-21T03:02:51.155533027Z I1121 03:02:51.155349       1 server.go:232]      Looking up Firestore Collection foo for instanceID 8030049439212453353
2020-11-21T03:02:51.155521757Z I1121 03:02:51.155340       1 server.go:230]      Got rpc: RequestID 0ad6b8f1-2ba6-11eb-b228-0242ac110002 for subject 114965907114681223971 and email tokenclient@tc-a681c707.iam.gserviceaccount.com for instanceID 8030049439212453353
2020-11-21T03:02:51.155479867Z E1121 03:02:51.155317       1 server.go:183]      OIDC doc has Audience [https://tokenserver]   Issuer [https://accounts.google.com] and SubjectEmail [tokenclient@tc-a681c707.iam.gserviceaccount.com]
2020-11-21T03:02:51.155294579Z I1121 03:02:51.155116       1 server.go:170]      Found OIDC KeyID  dedc012d07f52aedfd5f97784e1bcbe23c19724d
2020-11-21T03:02:41.225613677Z E1121 03:02:41.225498       1 server.go:241] ERROR:  Could not find instanceID new Firestore Client 8030049439212453353
2020-11-21T03:02:41.155291915Z I1121 03:02:41.155243       1 server.go:232]      Looking up Firestore Collection foo for instanceID 8030049439212453353
2020-11-21T03:02:41.155014195Z I1121 03:02:41.154918       1 server.go:230]      Got rpc: RequestID 04e14369-2ba6-11eb-b228-0242ac110002 for subject 114965907114681223971 and email tokenclient@tc-a681c707.iam.gserviceaccount.com for instanceID 8030049439212453353
2020-11-21T03:02:41.154795506Z E1121 03:02:41.154739       1 server.go:183]      OIDC doc has Audience [https://tokenserver]   Issuer [https://accounts.google.com] and SubjectEmail [tokenclient@tc-a681c707.iam.gserviceaccount.com]
2020-11-21T03:02:41.154297478Z I1121 03:02:41.154139       1 server.go:170]      Found OIDC KeyID  dedc012d07f52aedfd5f97784e1bcbe23c19724d
2020-11-21T03:02:31.229461236Z E1121 03:02:31.229253       1 server.go:241] ERROR:  Could not find instanceID new Firestore Client 8030049439212453353
2020-11-21T03:02:31.153601362Z I1121 03:02:31.153322       1 server.go:232]      Looking up Firestore Collection foo for instanceID 8030049439212453353
2020-11-21T03:02:31.153593731Z I1121 03:02:31.153310       1 server.go:230]      Got rpc: RequestID feeb0099-2ba5-11eb-b228-0242ac110002 for subject 114965907114681223971 and email tokenclient@tc-a681c707.iam.gserviceaccount.com for instanceID 8030049439212453353
2020-11-21T03:02:31.153559392Z E1121 03:02:31.153253       1 server.go:183]      OIDC doc has Audience [https://tokenserver]   Issuer [https://accounts.google.com] and SubjectEmail [tokenclient@tc-a681c707.iam.gserviceaccount.com]
2020-11-21T03:02:31.149848823Z I1121 03:02:31.149653       1 server.go:170]      Found OIDC KeyID  dedc012d07f52aedfd5f97784e1bcbe23c19724d
2020-11-21T03:02:21.230978751Z E1121 03:02:21.230789       1 server.go:241] ERROR:  Could not find instanceID new Firestore Client 8030049439212453353
2020-11-21T03:02:21.154445566Z I1121 03:02:21.154314       1 server.go:232]      Looking up Firestore Collection foo for instanceID 8030049439212453353
2020-11-21T03:02:21.154437705Z I1121 03:02:21.154280       1 server.go:230]      Got rpc: RequestID f8f59300-2ba5-11eb-b228-0242ac110002 for subject 114965907114681223971 and email tokenclient@tc-a681c707.iam.gserviceaccount.com for instanceID 8030049439212453353
2020-11-21T03:02:21.154416515Z E1121 03:02:21.154235       1 server.go:183]      OIDC doc has Audience [https://tokenserver]   Issuer [https://accounts.google.com] and SubjectEmail [tokenclient@tc-a681c707.iam.gserviceaccount.com]
2020-11-21T03:02:21.153363289Z I1121 03:02:21.153171       1 server.go:170]      Found OIDC KeyID  dedc012d07f52aedfd5f97784e1bcbe23c19724d
2020-11-21T03:02:11.256013622Z E1121 03:02:11.255762       1 server.go:241] ERROR:  Could not find instanceID new Firestore Client 8030049439212453353
2020-11-21T03:02:11.158436295Z I1121 03:02:11.157763       1 server.go:232]      Looking up Firestore Collection foo for instanceID 8030049439212453353
2020-11-21T03:02:11.158414735Z I1121 03:02:11.157746       1 server.go:230]      Got rpc: RequestID f2ff84b3-2ba5-11eb-b228-0242ac110002 for subject 114965907114681223971 and email tokenclient@tc-a681c707.iam.gserviceaccount.com for instanceID 8030049439212453353
2020-11-21T03:02:11.156328972Z E1121 03:02:11.155900       1 server.go:183]      OIDC doc has Audience [https://tokenserver]   Issuer [https://accounts.google.com] and SubjectEmail [tokenclient@tc-a681c707.iam.gserviceaccount.com]
2020-11-21T03:02:11.156059023Z I1121 03:02:11.155603       1 server.go:170]      Found OIDC KeyID  dedc012d07f52aedfd5f97784e1bcbe23c19724d
```
