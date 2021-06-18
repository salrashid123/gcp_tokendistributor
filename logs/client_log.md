### Sample TokenClient log
(in reverse order)

```logs
I0618 14:03:09.927658       1 client.go:559]      Worker 1 starting
I0618 14:03:09.927594       1 client.go:551]      >>>>>>>>>>>>>>> System Provisioned <<<<<<<<<<<<<<
I0618 14:03:04.176030       1 client.go:536]      SigningKey Response true
I0618 14:03:03.801625       1 client.go:523]      Returning SigningKey
I0618 14:03:03.792378       1 client.go:1267]      Unrestricted Key Signature Verified
I0618 14:03:03.791886       1 client.go:1259] Control Signature data with unrestriced Key:  28cePjxSoZ8G8raPXl0KT8oEIFDP0Na7UL60OC+Slc/OxJNuJvZLj7s9PRDvhJDhjnAosa/jCvWo1+czMKbB9blgVooXEn/biNuC7q6wltiEsdFgpkLOmXhT0fmVqG6ThprbHQjI58x7z94D2VVk0pHkMfYdnIcRzs/KvUBx8RSVy0u6Kr+Um6c/PIbOJy61aY7CpsxHsSVWv2ERgbLPGXmN4sIF/6gZ3AvcipJHe2OJH8PAjvHigjCilj3js4i9ELvjiAHHDdNrNFd5LuuLMdXcLPEOmJGqEDpW8+M5pJVzD3gzt76z4FNuWxjw3I1Vjs51ckYAufiCe9ecHHu5sw
I0618 14:03:03.785472       1 client.go:1250]      TPM based Hash for Unrestricted Key w6uP8Tcg6K2QR905Rms8iXTlksL6OD1KOWBxTK7wxPI=
-----END PUBLIC KEY-----
aQIDAQAB
B7yX0Jufpdr/vyLY4B6jXUHyWVdmx7OvbH5bsx5rx3Q63yk4RIk8saCnMOo6bBNL
YIhmMj/Ktce50BtMpzlYgYJ69VrrCBKnYg92Uhutc/mr50OBClArJ5bpjPz0q3/s
kOKOpEunt8kYAv3p3HruIdA3r9OZ8d0cuayH2wVNW32uX5BBj0TiEeS1loFS8Ajd
Z8krJJved4n+Ex281AakEA+tHtRDj9PLjSZYOeuLlQYT609K5sjP47+SMCRHLqK0
+mgn/poWQayOBdaYLHurwVSbZOgiD5wm9LPRFF50ccokSwsRlaFce4WRcGvaGs4a
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5+ce3F9mgC3R3TWwvDHh
-----BEGIN PUBLIC KEY-----
I0618 14:03:03.783620       1 client.go:1241]      ukPubPEM: 
I0618 14:03:03.778768       1 client.go:1218]      Certify Signature: 3eb80b50b7b528882810455fb9f6925d23445c2f2f773248455a74c18629f34a5f834f10ff4bcfadcf2bf403451e8816b8c0b6135eaba677bc06acafbf98a3132f483af54d3fd74cc9fb41c0f198728b065cefa64fc4b90224dae175d695febe972c31f64d8c0298ec28a7b0c0ac3b9b61e26a8466ae6792ac00611de5f77e072e4e9c6e119379ca65530389ba15a3b633d7577e799fd6f34de9a1ae6ffaf228ed24783fbb0b1810da61d2d039dc5ac887e4186c08ca1b63296f030a3ae8854eb2bb91e45b5ae32fefa246ccea40569cc3124e168094187f3cd32534a3b273bef7fa37b1243f5b18bec0832daef31601eff23c9b82dd31c49732a5991784c406,
I0618 14:03:03.778732       1 client.go:1217]      Certify Attestation: ff54434780170022000b69197fccd2fbc5337b4603fd2171396ccbe10853412b2ae09dec91b1900d5617000000000000000181c900000009000000000120160511001628000022000b41063df97c66875d35b2760fa94ed6112e040253dd8a9cd3477dc47aec76ca910022000b3354525f71413005b32310b7f89cda41ddcae6f58875d4514c6f7b56f9a9f030,
I0618 14:03:03.772475       1 client.go:1207]      ukeyName: 000b41063df97c66875d35b2760fa94ed6112e040253dd8a9cd3477dc47aec76ca91,
I0618 14:03:03.762038       1 client.go:1173]      Write (ukPriv) ========
I0618 14:03:03.761697       1 client.go:1168]      Write (ukPub) ========
I0618 14:03:03.760960       1 client.go:1166]      Unrestricted ukPriv: 00204449c276a7eaec0e4f4c7f5c0a42844b36f59c7884c4307d24ec9246ba0ec6f90010f138b533285f5ff42f0d8094c37f596ff983fa469cb73a47dcf9f13666abe3ebbda6a7a0d127b6266d5aa97e7acafc7a1d1abfb537a36f48e7cb0ef9c5c885a4b46a4ebcbcdade06a269fc1c557357d89a0feae1fb67bbc55ad6b21e35bcba57f00fd361c30bf18bc97a677d27fad78e76206729d0064f480b4e977847adebcba560b0017beb0967f6dc42e0c67ae7b62a867bd4f5ced2518a47b302dbea540ff0577762e5f8c4f02169be324d4e3604250ecade559c6b2d6ad0,
I0618 14:03:03.760834       1 client.go:1165]      Unrestricted ukPub: 0001000b00040072000000100014000b0800000000000100e7e71edc5f66802dd1dd35b0bc31e1fa6827fe9a1641ac8e05d6982c7babc1549b64e8220f9c26f4b3d1145e7471ca244b0b1195a15c7b8591706bda1ace1a67c92b249bde7789fe131dbcd406a4100fad1ed4438fd3cb8d265839eb8b950613eb4f4ae6c8cfe3bf923024472ea2b490e28ea44ba7b7c91802fde9dc7aee21d037afd399f1dd1cb9ac87db054d5b7dae5f90418f44e211e4b5968152f008dd608866323fcab5c7b9d01b4ca7395881827af55aeb0812a7620f76521bad73f9abe743810a502b2796e98cfcf4ab7fec07bc97d09b9fa5daffbf22d8e01ea35d41f2595766c7b3af6c7e5bb31e6bc7743adf293844893cb1a0a730ea3a6c134b69,
I0618 14:03:03.535548       1 client.go:1139] ======= SignwithUnrestrictedKey ========
I0618 14:03:03.535523       1 client.go:1136]      AK Verified Signature
I0618 14:03:03.535314       1 client.go:1115]      AK Signed Data nOOurXc57V6ogpX9W1czjx/nKg2gyKKxa1LYKaa4qCwgcRL3dv1FaRJ6Wq1qwSi8JTL9o5OqCl2F/TWQ6YjNqHmkXTNbLeVovPam+czs7s5tvAcyzlPBJ1B5Im5v3exPSITkXcUL4eYbHvbvRgiC3Y3uix+BVZl7gmYZRdySfLThh/96bUb26gS5UwxLu75KM6sTz5AtMxifHSX20PCGzPCjG27NJsBz6eYGU7OpwGb0XqE7OHHFuIcGgtgZJfWe+OOTXZQjNxkgbYcWzNiNziUmS/hgAIl4q68bJQrAHfpg/T20bOCsEcJLZONyT9fg4e09Rm3T0oUi/9Vtgothww==
I0618 14:03:03.529462       1 client.go:1106]      AK Issued Hash w6uP8Tcg6K2QR905Rms8iXTlksL6OD1KOWBxTK7wxPI=
I0618 14:03:03.524595       1 client.go:1057] ======= SignwithRestrictedKey ========
I0618 14:03:03.523245       1 client.go:1053]      AK keyName: 000bf0d0b4890652316cd2a46445b17e34ca909e05edb508a522c59cf4c13aeca0cf
I0618 14:03:03.515567       1 client.go:1027]      LoadUsingAuth ========
I0618 14:03:03.515162       1 client.go:1021]      Read (akPriv)
I0618 14:03:03.515072       1 client.go:1016]      Read (akPub)
I0618 14:03:03.506263       1 client.go:1003]      ContextLoad (ek)
I0618 14:03:03.506237       1 client.go:998]      PCR 0 Value 24af52a4f429b71a3184a6d64cddad17e54ea030e2aa6576bf3a5a3d8bd3328f 
I0618 14:03:03.493890       1 client.go:988]      --> Start signingKey
I0618 14:03:03.493557       1 client.go:517] =============== Providing SigningKey ===============
I0618 14:03:03.492626       1 client.go:514]      Provided Quote verified: true
I0618 14:03:03.165518       1 client.go:503] =============== Providing Quote ===============
I0618 14:03:03.161061       1 client.go:683]      <-- End Quote
I0618 14:03:03.161047       1 client.go:682]      Quote Sig 8f6b6807fac11135a9878d42fc648d0e32550304da178b8fce4ea85167691b932541ebf742c78a7c075578d083167708d7b844d69a0f2b53eb2564f4dc9e2fcdefffb932480acf25d65f0233d1d1904b747cb6a71338e9778507430915bad6c2f9955ac7f4120f7ca3e50e41b057984d50d0144d7440a12f4f0543048096f2d1af053302f5431d304d7269cf0e98e541772b560ab2ed4709fb20149f29bce03b0adcd278ef26ba620b485ef9e4fa7d5405b1b13f602225924c04db4906bc80d3ce74afcd930043fd9bb1065d0d681bd320cd52fe4eeb81d0d30ff0a1858bb2a4faade4ed2b06ebfa224b07d7e14d5e21558feabd08719a83498e80ae3a4cf100
I0618 14:03:03.161018       1 client.go:681]      Quote Hex ff54434780180022000b69197fccd2fbc5337b4603fd2171396ccbe10853412b2ae09dec91b1900d5617002432613131613834342d326339372d343036392d623562612d6236646235353937663962310000000000017f5f000000090000000001201605110016280000000001000b0301000000202ba7022b59f2158786ea3ea29a7ad12ff0c6c9d6682da6555d8926075b643b1f
I0618 14:03:03.153852       1 client.go:675]      AK keyName 000bf0d0b4890652316cd2a46445b17e34ca909e05edb508a522c59cf4c13aeca0cf
I0618 14:03:03.148800       1 client.go:663]      Read (akPriv) ========
I0618 14:03:03.148733       1 client.go:658]      Read (akPub) ========
I0618 14:03:03.145195       1 client.go:636]      LoadUsingAuth ========
I0618 14:03:03.135362       1 client.go:626]      ContextLoad (ek) ========
I0618 14:03:03.135282       1 client.go:621]      PCR 0 Value 24af52a4f429b71a3184a6d64cddad17e54ea030e2aa6576bf3a5a3d8bd3328f 
I0618 14:03:03.133327       1 client.go:611]      --> Start Quote
I0618 14:03:03.133252       1 client.go:497] =============== Generating Quote ===============
I0618 14:03:03.132912       1 client.go:495]      Quote Requested with nonce 2a11a844-2c97-4069-b5ba-b6db5597f9b1, pcr: 0
I0618 14:03:02.753789       1 client.go:485] =============== OfferQuote ===============
I0618 14:03:02.753402       1 client.go:484] =============== responseID:"e587bd9e-d03d-11eb-a6c7-0242ac110002" inResponseTo:"d136c38d-0d5f-4fab-ba8b-3528b9b36a80" verified:true
I0618 14:03:02.379097       1 client.go:683]      <-- End Quote
I0618 14:03:02.379080       1 client.go:682]      Quote Sig a7a37b027bd49a3d5cdee575974f811685ee2d567db597a2c68ce5c115b0e1641cb7b6154475ff7d2334175fb38fef41a92ec309bd8dd49f4c97b3b977ba0809a9a1d576de1d15cde74b415252ab085e5a2eb9019546c9b2548db42a66b33e9138a3b0d1101a5b41560fcd757cc6bf98a73a6f36be8d3ca4aedb8ff7ea124b77cefdc0be38283a3eb4614311f3ac205055086d26bd529ecf62ef395799d331aecc9ecb87a9f21492c04a1532375a8ce4bcc6ae99bb662dd3057726e24fb8a1c4d4161698340b035ac9a1fd82edd9227e09147cc44346c895c4e2e1bd6f2b83b4acd5253072adaebd75d906c0c8d0c20c4404b5412676370acbd9ccea35f31dbb
I0618 14:03:02.379053       1 client.go:681]      Quote Hex ff54434780180022000b69197fccd2fbc5337b4603fd2171396ccbe10853412b2ae09dec91b1900d5617000a4c536a466263586f45460000000000017c52000000090000000001201605110016280000000001000b0301000000202ba7022b59f2158786ea3ea29a7ad12ff0c6c9d6682da6555d8926075b643b1f
I0618 14:03:02.372923       1 client.go:675]      AK keyName 000bf0d0b4890652316cd2a46445b17e34ca909e05edb508a522c59cf4c13aeca0cf
I0618 14:03:02.367832       1 client.go:663]      Read (akPriv) ========
I0618 14:03:02.367770       1 client.go:658]      Read (akPub) ========
I0618 14:03:02.364589       1 client.go:636]      LoadUsingAuth ========
I0618 14:03:02.355948       1 client.go:626]      ContextLoad (ek) ========
I0618 14:03:02.355890       1 client.go:621]      PCR 0 Value 24af52a4f429b71a3184a6d64cddad17e54ea030e2aa6576bf3a5a3d8bd3328f 
I0618 14:03:02.354013       1 client.go:611]      --> Start Quote
I0618 14:03:02.348533       1 client.go:976]      <--  activateCredential()
I0618 14:03:02.335915       1 client.go:928]      ActivateCredentialUsingAuth
I0618 14:03:02.335890       1 client.go:926]      keyName 000bf0d0b4890652316cd2a46445b17e34ca909e05edb508a522c59cf4c13aeca0cf
I0618 14:03:02.327827       1 client.go:899]      LoadUsingAuth
I0618 14:03:02.327783       1 client.go:893]      Read (akPriv)
I0618 14:03:02.327712       1 client.go:888]      Read (akPub)
I0618 14:03:02.317648       1 client.go:877]      ContextLoad (ek)
I0618 14:03:02.317643       1 client.go:872]      --> activateCredential()
I0618 14:03:02.317629       1 client.go:461] =============== ActivateCredential  ===============
I0618 14:03:02.317551       1 client.go:459]      MakeCredential RPC RequestID [e4acaad6-d03d-11eb-a6c7-0242ac110002] InResponseTo ID [d136c38d-0d5f-4fab-ba8b-3528b9b36a80]
I0618 14:03:00.689167       1 client.go:866]      <-- CreateKeys()
I0618 14:03:00.686281       1 client.go:860]      Write (akPriv) ========
I0618 14:03:00.686209       1 client.go:855]      Write (akPub) ========
-----END PUBLIC KEY-----
mwIDAQAB
EKvXAPE2tryvCNrToAdv4FxVq6YosqNU49vCeJLrJ5kgTnH5bW8pqOucqAhd9OmM
9+q9CSCQ3pztQIQHhiJ8Uojb8UeVkXkgWfBF2XFDrU5M4+DZwUjK0GD+77jMKEJM
3TQnbQK8N2HehOrVBCLf8Cyf6AitzAioOLDlZ4yApmwKvWoI5CvqmiPrT6yzC/bW
HsH+n72RlqEl3vzz0kEyyhERnm6Gd4Kr8LkDHX1HQ1m5WGMGNa4W6SHhCGu866pf
kJf0ns+W/0voi4k2rC1e3u+Ahqf4j8jWlGe14xOmwS/JQWNGgz7wUIoUJr1ihXNt
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsw9T6q74bUsuOuJJn+ou
-----BEGIN PUBLIC KEY-----
I0618 14:03:00.686176       1 client.go:853]      akPubPEM: 
I0618 14:03:00.682671       1 client.go:831]      AK keyName 000bf0d0b4890652316cd2a46445b17e34ca909e05edb508a522c59cf4c13aeca0cf
I0618 14:03:00.673737       1 client.go:803]      LoadUsingAuth
I0618 14:03:00.664248       1 client.go:793]      ContextLoad (ek)
I0618 14:03:00.653002       1 client.go:782]      ContextSave (ek)
I0618 14:03:00.652990       1 client.go:780]      CredentialHash d3a22da3f53810f007de4f0144b2c39621ce2b166c4a138e4f5f44db08c49d3c
I0618 14:03:00.652954       1 client.go:779]      CredentialTicket d175b97e8a188df48ae77974c6acaa250a2beba7525ec32a29452f5abf028ab8
I0618 14:03:00.652938       1 client.go:778]      CredentialData.ParentName.Digest.Value bd545cb109e457801e7a0e514443e9603f737c7a8d6b23660a945b75c4472d10
I0618 14:03:00.652908       1 client.go:771]      akPriv: 0020a9e25d7da112c6d0402216b6d6e0795165c30498b134e271a024e74b8d57b4c00010255e8135d0117058a4af7d0790526bfe421d16de92e5de316a0b830f221d736d7abae2d15fbc0c9723d5a95aa496703d56f6cbdf728652f0c1e99c9c48e6306d4d537257e6de089b6dd14d1b5d09f80384701c9c5a063ba6b760c97e5f6a6ad3706f9238837944f52e31de91a9950e678829159a24a51225b148a617220b20d5b81254eba79514097b6d9084def8c2d76aa4bfa573acac542cc1b919fe6d43b35526dfe7be2b6998d53f858ef82483c3a5e48ea06ad9912ed007,
I0618 14:03:00.652854       1 client.go:770]      akPub: 0001000b00050072000000100014000b0800000000000100b30f53eaaef86d4b2e3ae2499fea2e9097f49ecf96ff4be88b8936ac2d5edeef8086a7f88fc8d69467b5e313a6c12fc9416346833ef0508a1426bd6285736d1ec1fe9fbd9196a125defcf3d24132ca11119e6e867782abf0b9031d7d474359b958630635ae16e921e1086bbcebaa5fdd34276d02bc3761de84ead50422dff02c9fe808adcc08a838b0e5678c80a66c0abd6a08e42bea9a23eb4facb30bf6d6f7eabd092090de9ced40840786227c5288dbf1479591792059f045d97143ad4e4ce3e0d9c148cad060feefb8cc28424c10abd700f136b6bcaf08dad3a0076fe05c55aba628b2a354e3dbc27892eb2799204e71f96d6f29a8eb9ca8085df4e98c9b,
I0618 14:03:00.560801       1 client.go:744]      CreateKeyUsingAuth
-----END PUBLIC KEY-----
+wIDAQAB
X/cB2y9/xKQR3KZk0Bs3yxz/bPLaljlaD/ImQYoy3Pb4CtLO0k12XWdLhkoiGyeH
1bdHBumeFIIfl/vpSW2svlMWHYtRMqCsMqJ/9TqP736J9KmhUVxSpHKXGNmT9gc5
OvH/RC2C0b0U9iGXvwuGOvdqCrYPHubrMMbu1wGtf1rbft7dF1dlp6PSnjNEpR99
R6fPwLRHkKuYieYhwiaaNuB86VWXOmgkLYQHGTuOFSBSkdo92MlHn104NqQpemwZ
aNkm/cTiCmk5WCbi8cSZf4mkdCVFsGLu7hyaaIE/BvB51yksLsgqgEQpAFULeWAM
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0M0WINcvrPwfK4GGPfXK
-----BEGIN PUBLIC KEY-----
I0618 14:03:00.560778       1 client.go:737]      ekPubPEM: 
I0618 14:03:00.560759       1 client.go:736]      ekPub Name: 000bbd545cb109e457801e7a0e514443e9603f737c7a8d6b23660a945b75c4472d10
&{26358699325054714453270425370159768334199488698711868654064094419507678467655452337052083261810739334614898058451380945100212917612069047510562434124814961116964583017378806515036636347928847890261537208792575370813928990504541982091898836846465807357379925206541946916711278858133216055437296768608605598203258064766934593914185876550766266036711288589538112343148121202551490998138893018240870349510043677008105974461630024630281598001205475420770255045095662873882272788505141827648690812284497235931721521881118236710530623219173261953972649630946727034476270963397473100882890075174868806565439990334421083850747 65537}
I0618 14:03:00.560613       1 client.go:723]      tpmEkPub: 
I0618 14:03:00.434074       1 client.go:705]      createPrimary
I0618 14:03:00.433977       1 client.go:700]     Current PCR 0 Value %!d(string=24af52a4f429b71a3184a6d64cddad17e54ea030e2aa6576bf3a5a3d8bd3328f) 
I0618 14:03:00.431830       1 client.go:690]      --> CreateKeys()
I0618 14:03:00.409174       1 client.go:407]      Tink AEAD Decrypted Text foo
I0618 14:03:00.409145       1 client.go:400]      Tink AEAD encrypted text AWrGuDmHWlLx/E0T1oDH/0Tdd/XHarbXVmbaKJtBh2LSp79U
I0618 14:03:00.408832       1 client.go:376]      Decoding as Tink
I0618 14:03:00.408708       1 client.go:363]      Received  Data: name:"secret2" type:TINK data:"\x08\xb9\xf0\x9a\xd6\x06\x12d\nX\n0type.googleapis.com/google.crypto.tink.AesGcmKey\x12\"\x1a \x0eӡ\xcc\x02\x9b~\xff\xde\xf4^\x10d\x91\xb2\x84\xa9\xf9\xad\n\x02\xaf\x8a`B\xaa(~]V\xa0\xb8\x18\x01\x10\x01\x18\xb9\xf0\x9a\xd6\x06 \x01"
I0618 14:03:00.408698       1 client.go:366]      Decoding as RAW fooobar
I0618 14:03:00.408656       1 client.go:363]      Received  Data: name:"secret1" data:"fooobar"
I0618 14:03:00.408626       1 client.go:358]      Received  toResponse: e3dc87b8-d03d-11eb-a9de-0242ac110002
I0618 14:02:59.927467       1 client.go:541]      Sleeping..
I0618 14:02:59.927310       1 client.go:285] Attempting to contact TokenServer [7]
E0618 14:02:49.995729       1 client.go:342] Error:   GetToken() from TokenService: rpc error: code = PermissionDenied desc = InstanceID not Found  rpc error: code = NotFound desc = "projects/ts-3950a2df/databases/(default)/documents/foo/221808688638269893" not found
I0618 14:02:49.927113       1 client.go:541]      Sleeping..
I0618 14:02:49.927054       1 client.go:285] Attempting to contact TokenServer [6]
E0618 14:02:39.998994       1 client.go:342] Error:   GetToken() from TokenService: rpc error: code = PermissionDenied desc = InstanceID not Found  rpc error: code = NotFound desc = "projects/ts-3950a2df/databases/(default)/documents/foo/221808688638269893" not found
I0618 14:02:39.926531       1 client.go:541]      Sleeping..
I0618 14:02:39.926088       1 client.go:285] Attempting to contact TokenServer [5]
E0618 14:02:30.036215       1 client.go:342] Error:   GetToken() from TokenService: rpc error: code = PermissionDenied desc = InstanceID not Found  rpc error: code = NotFound desc = "projects/ts-3950a2df/databases/(default)/documents/foo/221808688638269893" not found
I0618 14:02:29.925858       1 client.go:541]      Sleeping..
I0618 14:02:29.925792       1 client.go:285] Attempting to contact TokenServer [4]
2021-06-18 14:02:21 +0000 [info]: #0 Successfully sent gRPC to Stackdriver Logging API.
E0618 14:02:20.040253       1 client.go:342] Error:   GetToken() from TokenService: rpc error: code = PermissionDenied desc = InstanceID not Found  rpc error: code = NotFound desc = "projects/ts-3950a2df/databases/(default)/documents/foo/221808688638269893" not found
I0618 14:02:19.925527       1 client.go:541]      Sleeping..
I0618 14:02:19.925394       1 client.go:285] Attempting to contact TokenServer [3]
E0618 14:02:10.050660       1 client.go:342] Error:   GetToken() from TokenService: rpc error: code = PermissionDenied desc = InstanceID not Found  rpc error: code = NotFound desc = "projects/ts-3950a2df/databases/(default)/documents/foo/221808688638269893" not found
I0618 14:02:09.925250       1 client.go:541]      Sleeping..
I0618 14:02:09.925212       1 client.go:285] Attempting to contact TokenServer [2]
E0618 14:02:00.182574       1 client.go:342] Error:   GetToken() from TokenService: rpc error: code = PermissionDenied desc = InstanceID not Found  rpc error: code = NotFound desc = "projects/ts-3950a2df/databases/(default)/documents/foo/221808688638269893" not found
I0618 14:01:59.925060       1 client.go:541]      Sleeping..
I0618 14:01:59.925030       1 client.go:285] Attempting to contact TokenServer [1]
I0618 14:01:59.913375       1 client.go:248]      Enabling mTLS
I0618 14:01:59.826606       1 client.go:196]      Loading mTLS certs from Secrets
     Startup args:  vmodule:  
     Startup args:  v:  25
     Startup args:  useTPM:  true
     Startup args:  useSecrets:  true
     Startup args:  useMTLS:  true
     Startup args:  useALTS:  false
     Startup args:  unsealPcr:  0
     Startup args:  tsAudience:  https://tokenserver
     Startup args:  tokenServerServiceAccount:  
     Startup args:  tlsClientKey:  projects/97849079040/secrets/tls_key
     Startup args:  tlsClientCert:  projects/97849079040/secrets/tls_crt
     Startup args:  tlsCertChain:  projects/97849079040/secrets/tls-ca
     Startup args:  stderrthreshold:  2
     Startup args:  serviceAccount:  /path/to/svc.json
     Startup args:  servername:  tokenservice.esodemoapp2.com
     Startup args:  pollWaitSeconds:  10
     Startup args:  maxLoop:  360
     Startup args:  logtostderr:  false
     Startup args:  log_dir:  
     Startup args:  log_backtrace_at:  :0
     Startup args:  exchangeSigningKey:  true
     Startup args:  doAttestation:  true
     Startup args:  alsologtostderr:  true
I0618 14:01:59.711728       1 client.go:173]      Getting certs from Secrets Manager
     Startup args:  address:  34.67.176.155:50051
```
