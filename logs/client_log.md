### Sample TokenClient log
(in reverse order)

```log
...
...
I0620 12:26:21.999638       1 client.go:289] Attempting to contact TokenServer [42]
I0620 12:26:21.999681       1 client.go:697]      Sleeping..
E0620 12:26:22.080713       1 client.go:346] Error:   GetToken() from TokenService: rpc error: code = PermissionDenied desc = InstanceID not Found  rpc error: code = NotFound desc = "projects/ts-f793b75c/databases/(default)/documents/foo/5055893581146000589" not found
I0620 12:26:31.999823       1 client.go:289] Attempting to contact TokenServer [43]
I0620 12:26:31.999878       1 client.go:697]      Sleeping..
E0620 12:26:32.074081       1 client.go:346] Error:   GetToken() from TokenService: rpc error: code = PermissionDenied desc = InstanceID not Found  rpc error: code = NotFound desc = "projects/ts-f793b75c/databases/(default)/documents/foo/5055893581146000589" not found
I0620 12:26:42.000018       1 client.go:289] Attempting to contact TokenServer [44]
I0620 12:26:42.000054       1 client.go:697]      Sleeping..
E0620 12:26:42.090845       1 client.go:346] Error:   GetToken() from TokenService: rpc error: code = PermissionDenied desc = InstanceID not Found  rpc error: code = NotFound desc = "projects/ts-f793b75c/databases/(default)/documents/foo/5055893581146000589" not found
I0620 12:26:52.000264       1 client.go:289] Attempting to contact TokenServer [45]
I0620 12:26:52.000307       1 client.go:697]      Sleeping..
E0620 12:26:52.085778       1 client.go:346] Error:   GetToken() from TokenService: rpc error: code = PermissionDenied desc = InstanceID not Found  rpc error: code = NotFound desc = "projects/ts-f793b75c/databases/(default)/documents/foo/5055893581146000589" not found
I0620 12:27:02.000424       1 client.go:289] Attempting to contact TokenServer [46]
I0620 12:27:02.000475       1 client.go:697]      Sleeping..
E0620 12:27:02.087092       1 client.go:346] Error:   GetToken() from TokenService: rpc error: code = PermissionDenied desc = InstanceID not Found  rpc error: code = NotFound desc = "projects/ts-f793b75c/databases/(default)/documents/foo/5055893581146000589" not found
I0620 12:27:12.000597       1 client.go:289] Attempting to contact TokenServer [47]
I0620 12:27:12.000663       1 client.go:697]      Sleeping..
E0620 12:27:12.070367       1 client.go:346] Error:   GetToken() from TokenService: rpc error: code = PermissionDenied desc = InstanceID not Found  rpc error: code = NotFound desc = "projects/ts-f793b75c/databases/(default)/documents/foo/5055893581146000589" not found
I0620 12:27:22.000875       1 client.go:289] Attempting to contact TokenServer [48]
I0620 12:27:22.001277       1 client.go:697]      Sleeping..
I0620 12:27:22.399444       1 client.go:362]      Received  toResponse: dc9d5655-d1c2-11eb-95cf-0242ac110002
I0620 12:27:22.399474       1 client.go:367]      Received  Data: name:"secret1" data:"fooobar"
I0620 12:27:22.399505       1 client.go:370]      Decoding as RAW fooobar
I0620 12:27:22.399513       1 client.go:367]      Received  Data: name:"secret2" type:TINK data:"\x08\xb9\xf0\x9a\xd6\x06\x12d\nX\n0type.googleapis.com/google.crypto.tink.AesGcmKey\x12\"\x1a \x0eӡ\xcc\x02\x9b~\xff\xde\xf4^\x10d\x91\xb2\x84\xa9\xf9\xad\n\x02\xaf\x8a`B\xaa(~]V\xa0\xb8\x18\x01\x10\x01\x18\xb9\xf0\x9a\xd6\x06 \x01"
I0620 12:27:22.399546       1 client.go:380]      Decoding as Tink
I0620 12:27:22.400385       1 client.go:404]      Tink AEAD encrypted text AWrGuDnqX+ANzRzPVXfjN+UZcVgY/6EPREbNyQeazM5togJD
I0620 12:27:22.400414       1 client.go:411]      Tink AEAD Decrypted Text foo
I0620 12:27:22.421003       1 client.go:441] =============== Load EncryptionKey and Certifcate from NV ===============
I0620 12:27:22.575452       1 client.go:459]      Encryption PEM 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0L+xTVAysyRfNAzMO8QO
zWG11WTOnfTU/InyC0dpcF6txBbevdv7yVQB0tA/ZLf8JsEKU7hzxAhYrZ3RVnOd
hPONkkc2AH+ZENqkExb3i5Rwg6IKNztXGE3wV5EbWBtAURJdxCX1+dCg2vKThRwE
SH7AwutagNnK4zgUP0XNGMKXwHjpQSiL2QTqlePco9Svq+tqw0E4XtNFSaP6cCIp
KdT0a+KZj3eiy+IiUDXiusTgR8qLkuTueUv546BHvkBaSjM1dTad5QSX793yn1Oe
ZiFHwAPqb6VzrMmnX8+B0wymMZz8vb6Qqc0Q16vrubcHWepQ3glqyTlC7Z1Ia7VL
lQIDAQAB
-----END PUBLIC KEY-----
I0620 12:27:22.577727       1 client.go:481]      Load SigningKey and Certifcate 
I0620 12:27:22.698100       1 client.go:499]      Signing PEM 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxjSvTq5Rd5/0lo9iHDL+
MdANu/jZ/X7LAE9upDSd0ROi3K30G4Z2Pf31Suh6ZrWGpd5GKCK8jwhC5x9ldMlV
1wScPAhoPnuk9BzE6Vgv4RRs7U1TVpC4GoKMjn4QcdPsXH4lL3QYBeqkhAsYxwz5
Lzg9SvaEKRZpcqzVsgBQneppczTnr1P3UPrL02o4/1UTtDz74tLS/+aMZjWpIwdA
Hf+MKG0n8hSJlPVifAeic8TR1KCTSUuaKN3MmESdXSMYbgjbXM7lD8lrw/cOSndR
ZtFR85w6PrZVVhbbjRvZadau/6n9kJjUoZiBgOu2BMQ2O9VkyyUi2LgWgNbkohlm
DQIDAQAB
-----END PUBLIC KEY-----
I0620 12:27:22.702868       1 client.go:560]      AK Issued Hash w6uP8Tcg6K2QR905Rms8iXTlksL6OD1KOWBxTK7wxPI=
I0620 12:27:22.708225       1 client.go:569]      AK Signed Data FnhQvWIGu60kKkwkK+On7jZGLrSHZDXe9E8bJLvHKq5ZBd+2dIEPyOBsrpQq6FBbvoWY8K5VD6GXsKBc66xpi9dgPfONDUT8uLeYVE5tjP6kbVQ1YVP31xeTvUgUSgu5AvE6HV37yg0tamyjvK3gx5RLCWzn/miGKWKjVCodM5w8XrHiMelZPC3n/1/2svWvDP2SJ4dw9TjTm9JktLWyKErWwfwaBwYyque+OXYzSvPG3BxZN0Nf+fVWWSn6Sosc3FF3pEXnS5MxstasCxP5TjfY45S9fwyXatSeQvfbmlTSOgTJunmzzjT9FWTh1ZOuni+gX64AnMmPrq8oPCawNg==
I0620 12:27:22.708407       1 client.go:575]      Signature Verified
I0620 12:27:22.711327       1 client.go:591] =============== Create AK manually ===============
I0620 12:27:22.711351       1 client.go:846]      --> CreateKeys()
I0620 12:27:22.712964       1 client.go:856]     Current PCR 0 Value %!d(string=24af52a4f429b71a3184a6d64cddad17e54ea030e2aa6576bf3a5a3d8bd3328f) 
I0620 12:27:22.712986       1 client.go:861]      createPrimary
I0620 12:27:22.863759       1 client.go:879]      tpmEkPub: 
&{26352094570150208363257265599990946045561468446095548277083407918123681900737464986379446983354960010560414355371541121380455708589497235972713061301200011027702279985449479609774488584035332132760009882771714110051058585211589080570759246991350117443977443980190418229121594812389611161359588491805966239722721177948893635363233873925014426752131622308572149849763308876876306340173789310331488633548306855615762017804851617080916001673113410094283558518790232746346958503025590124434562565021912755971489377272156317860381185221394343935280090192789350005167879766451738966265716883865559341935330001833144612113301 65537}
I0620 12:27:22.863874       1 client.go:892]      ekPub Name: 000b53a7b9c62e6ebea87a6e4e95be99a2e3d89ab7f2995d8214fd4e67c967617779
I0620 12:27:22.863895       1 client.go:893]      ekPubPEM: 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0L+xTVAysyRfNAzMO8QO
zWG11WTOnfTU/InyC0dpcF6txBbevdv7yVQB0tA/ZLf8JsEKU7hzxAhYrZ3RVnOd
hPONkkc2AH+ZENqkExb3i5Rwg6IKNztXGE3wV5EbWBtAURJdxCX1+dCg2vKThRwE
SH7AwutagNnK4zgUP0XNGMKXwHjpQSiL2QTqlePco9Svq+tqw0E4XtNFSaP6cCIp
KdT0a+KZj3eiy+IiUDXiusTgR8qLkuTueUv546BHvkBaSjM1dTad5QSX793yn1Oe
ZiFHwAPqb6VzrMmnX8+B0wymMZz8vb6Qqc0Q16vrubcHWepQ3glqyTlC7Z1Ia7VL
lQIDAQAB
-----END PUBLIC KEY-----
I0620 12:27:22.863924       1 client.go:900]      CreateKeyUsingAuth
I0620 12:27:22.985846       1 client.go:926]      akPub: 0001000b00050072000000100014000b0800000000000100b467d7094e3ef78ac016883eaa93ad90b29925674a8f64393789e7a5f8639ee2a68f5b629292672ee902d8358b1f855abe01ef27a2549ef6452228fb5c57f90bed437e370ae42bb84da770f3ebb8de59cb6a0dcd7d511aeba20f86d861d1752a8e65a729d6faab378c37897dc1182cce65a36ff54cb16d38d6e6ceff5d0090c8c8d943f7f49ad83591b072894029962d4e929cdbe0577bffd0d7c5441f531ea89f5bf70a02717af3b32ce65b070426c86ac7b8c563880ac5a4c20a1aca93603488ea4a92094d37911768b5f2952b061dc9d3faf7f693172fb5965e3f0e59caae93362aac5020f343ad9ddebe811dd8eff14ab5c550e17a3ffb55f8fd85c8bd3d,
I0620 12:27:22.985879       1 client.go:927]      akPriv: 0020e356456db0446c4957a91896cbbf98d939d88c35af9ff2107618ddcfc3060d290010ee6ba1e6ee227a367a0064c812e9323044d58629ae81bdb05249894137bb19a6c2dde7d2f77c8b14b44b887f912c990fe151744dfc24e2102d6021bf0cde6e0431207ae6165ba5c7f694ca3b0c068b10eeb3abdba26b831dff4fb1c30d9d847939bc36f04ee8abf00ae91d93b51ac63995d50bbbfeafe0dc3c488accd93b8448b4bd76e7f27e16f8a84e6caacfca75eafb1b794a7f1ed03237747db14fa973d94d93bf6024f55bba628a7fb20754bcbf8174a1890848c9935bca,
I0620 12:27:22.985900       1 client.go:934]      CredentialData.ParentName.Digest.Value 53a7b9c62e6ebea87a6e4e95be99a2e3d89ab7f2995d8214fd4e67c967617779
I0620 12:27:22.985912       1 client.go:935]      CredentialTicket 30820dc2d7090ea410033de1f977661def5f93d770a848e262421bc3d3791033
I0620 12:27:22.985924       1 client.go:936]      CredentialHash 92eaf7eef2d9020d51d41cc579031006e05462e80924dcea5bd907e2e053a88e
I0620 12:27:22.985937       1 client.go:938]      ContextSave (ek)
I0620 12:27:22.995690       1 client.go:949]      ContextLoad (ek)
I0620 12:27:23.002581       1 client.go:959]      LoadUsingAuth
I0620 12:27:23.009783       1 client.go:987]      AK keyName 000bdec56a29ce186cd28492931439e081ddb9ab2adf90cbeda85a6465d1c87989a1
I0620 12:27:23.012947       1 client.go:1009]      akPubPEM: 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtGfXCU4+94rAFog+qpOt
kLKZJWdKj2Q5N4nnpfhjnuKmj1tikpJnLukC2DWLH4VavgHvJ6JUnvZFIij7XFf5
C+1DfjcK5Cu4Tadw8+u43lnLag3NfVEa66IPhthh0XUqjmWnKdb6qzeMN4l9wRgs
zmWjb/VMsW041ubO/10AkMjI2UP39JrYNZGwcolAKZYtTpKc2+BXe//Q18VEH1Me
qJ9b9woCcXrzsyzmWwcEJshqx7jFY4gKxaTCChrKk2A0iOpKkglNN5EXaLXylSsG
HcnT+vf2kxcvtZZePw5Zyq6TNiqsUCDzQ62d3r6BHdjv8Uq1xVDhej/7Vfj9hci9
PQIDAQAB
-----END PUBLIC KEY-----
I0620 12:27:23.012975       1 client.go:1011]      Write (akPub) ========
I0620 12:27:23.013064       1 client.go:1016]      Write (akPriv) ========
I0620 12:27:23.013302       1 client.go:1022]      <-- CreateKeys()
I0620 12:27:24.606966       1 client.go:615]      MakeCredential RPC RequestID [dd910920-d1c2-11eb-9291-0242ac110002] InResponseTo ID [da48f901-02bc-4cb3-b0a5-e7408e36847b]
I0620 12:27:24.607037       1 client.go:617] =============== ActivateCredential  ===============
I0620 12:27:24.607046       1 client.go:1028]      --> activateCredential()
I0620 12:27:24.607053       1 client.go:1033]      ContextLoad (ek)
I0620 12:27:24.615847       1 client.go:1044]      Read (akPub)
I0620 12:27:24.615926       1 client.go:1049]      Read (akPriv)
I0620 12:27:24.615954       1 client.go:1055]      LoadUsingAuth
I0620 12:27:24.624223       1 client.go:1082]      keyName 000bdec56a29ce186cd28492931439e081ddb9ab2adf90cbeda85a6465d1c87989a1
I0620 12:27:24.624247       1 client.go:1084]      ActivateCredentialUsingAuth
I0620 12:27:24.634370       1 client.go:1132]      <--  activateCredential()
I0620 12:27:24.640719       1 client.go:767]      --> Start Quote
I0620 12:27:24.642429       1 client.go:777]      PCR 0 Value 24af52a4f429b71a3184a6d64cddad17e54ea030e2aa6576bf3a5a3d8bd3328f 
I0620 12:27:24.642452       1 client.go:782]      ContextLoad (ek) ========
I0620 12:27:24.650509       1 client.go:792]      LoadUsingAuth ========
I0620 12:27:24.653640       1 client.go:814]      Read (akPub) ========
I0620 12:27:24.653716       1 client.go:819]      Read (akPriv) ========
I0620 12:27:24.658504       1 client.go:831]      AK keyName 000bdec56a29ce186cd28492931439e081ddb9ab2adf90cbeda85a6465d1c87989a1
I0620 12:27:24.663888       1 client.go:837]      Quote Hex ff54434780180022000bb7d99ec5929c67a20f115d4710cc720616e56f59aacf56179550f2b58017d5b5000a6463456b5842416b6a51000000000007bd2a000000090000000001201605110016280000000001000b0301000000202ba7022b59f2158786ea3ea29a7ad12ff0c6c9d6682da6555d8926075b643b1f
I0620 12:27:24.663916       1 client.go:838]      Quote Sig 058238167cfb55561f45ae901d1adf71dae96bd347a2f2af0de1a06b70c57a4d830a314a5a0df92dcb13c52693c65b7dd7e85badd02d608a85ff4018486f6a613e15f63e73493df4852c6cad5aa04784fe1b79b35bf1ed96064fb28f946cb5c3de0a183b1cef1b8f8821282b460ce27b580ff95d50b30027fd69c7d62719e2985721742b4192d48ac294b21efee1836b04ece80f7cb08f9cffc77e9c86b16e0eb6cbe57a5be4c16865a2d9b0056454b5bbf05931466cd621def328e887e7fb6db29f6bc64247ce0ab0994c84dd579539290961a0450689f49bf99c661e89d34bcc573a1f688b72d025f00d40247da7240fc68834e1169e3ea07f478da21afe0f
I0620 12:27:24.663927       1 client.go:839]      <-- End Quote
I0620 12:27:25.018047       1 client.go:640] =============== responseID:"de6872a3-d1c2-11eb-9291-0242ac110002" inResponseTo:"da48f901-02bc-4cb3-b0a5-e7408e36847b" verified:true
I0620 12:27:25.018438       1 client.go:641] =============== OfferQuote ===============
I0620 12:27:25.465756       1 client.go:651]      Quote Requested with nonce a0b264bc-d261-437d-a932-3db68c701992, pcr: 0
I0620 12:27:25.465801       1 client.go:653] =============== Generating Quote ===============
I0620 12:27:25.465810       1 client.go:767]      --> Start Quote
I0620 12:27:25.477733       1 client.go:777]      PCR 0 Value 24af52a4f429b71a3184a6d64cddad17e54ea030e2aa6576bf3a5a3d8bd3328f 
I0620 12:27:25.477953       1 client.go:782]      ContextLoad (ek) ========
I0620 12:27:25.486380       1 client.go:792]      LoadUsingAuth ========
I0620 12:27:25.489407       1 client.go:814]      Read (akPub) ========
I0620 12:27:25.489875       1 client.go:819]      Read (akPriv) ========
I0620 12:27:25.494395       1 client.go:831]      AK keyName 000bdec56a29ce186cd28492931439e081ddb9ab2adf90cbeda85a6465d1c87989a1
I0620 12:27:25.500321       1 client.go:837]      Quote Hex ff54434780180022000bb7d99ec5929c67a20f115d4710cc720616e56f59aacf56179550f2b58017d5b5002461306232363462632d643236312d343337642d613933322d336462363863373031393932000000000007c06e000000090000000001201605110016280000000001000b0301000000202ba7022b59f2158786ea3ea29a7ad12ff0c6c9d6682da6555d8926075b643b1f
I0620 12:27:25.500677       1 client.go:838]      Quote Sig 36cf1d71a243d8be411dea9d8e873feeb81e1cf399e1f183d921f639529a7c976b165b73fde28f21fcceefac238f683e316d3190b380cc61eb0e274d3f2ab34263a3b2ec43255982164b72ae86df6a69f78a7a290381afd6436feb1af7311114c240af0b22df9a8a3ac53ecbf1145924e3f15a7284ffeb7064a471e68ad010d860ddc2a56e0b9eb24178878066744c32548c4cfa922c4acd76127b384b9f2504f59f4dde0e191f0cd0755d13c1c9cc22fdc8694ad0582a74a4097c65d58102122a7a7772762b7b0f2cc95b99bd6232bb1d8244313062cb0ec5903ad30e4408f438f9269ef703e7e657ec0f0ed0e2da565520a21a3cccb4cd7129c6d66db09368
I0620 12:27:25.500973       1 client.go:839]      <-- End Quote
I0620 12:27:25.504948       1 client.go:659] =============== Providing Quote ===============
I0620 12:27:25.833922       1 client.go:670]      Provided Quote verified: true
I0620 12:27:25.833964       1 client.go:673] =============== Providing SigningKey ===============
I0620 12:27:25.833974       1 client.go:1144]      --> Start signingKey
I0620 12:27:25.835730       1 client.go:1154]      PCR 0 Value 24af52a4f429b71a3184a6d64cddad17e54ea030e2aa6576bf3a5a3d8bd3328f 
I0620 12:27:25.835830       1 client.go:1159]      ContextLoad (ek)
I0620 12:27:25.844481       1 client.go:1172]      Read (akPub)
I0620 12:27:25.844594       1 client.go:1177]      Read (akPriv)
I0620 12:27:25.844646       1 client.go:1183]      LoadUsingAuth ========
I0620 12:27:25.852000       1 client.go:1209]      AK keyName: 000bdec56a29ce186cd28492931439e081ddb9ab2adf90cbeda85a6465d1c87989a1
I0620 12:27:25.853385       1 client.go:1213] ======= SignwithRestrictedKey ========
I0620 12:27:25.858658       1 client.go:1262]      AK Issued Hash w6uP8Tcg6K2QR905Rms8iXTlksL6OD1KOWBxTK7wxPI=
I0620 12:27:25.864075       1 client.go:1271]      AK Signed Data gyc1hq9wSgIi3zIzqH463aZjeioXz22a/EcpXl6iM7we2jFaFKv+m5YiKMhLRV4GFJYeTvuJ/ZyX4OM+unbXff66sUriAt30UZ9z8XQD2HFlrbeOz4YBCIG582z5vV9i6v8wFLExQ9lwkeNpsSWwIdm8lcLMRMMjH58rbjEs2HzIRSL8ot3DWXJUEMcAmpqcZ+vmak6W5iSf6bQM5zfcqbNERfbvCnqfOYZr0VscjMlkgUu48i0QDxQvNJnuS7Gu21SAI0nuMuAmYGJ0J/JiJkPyb4Ib7a5CTfw0RPtdyFuhC9OkB7XklzlMnQNK4ihtcGS73qb9zuLzAMe5OoiloA==
I0620 12:27:25.864471       1 client.go:1292]      AK Verified Signature
I0620 12:27:25.864501       1 client.go:1295] ======= SignwithUnrestrictedKey ========
I0620 12:27:26.013363       1 client.go:1321]      Unrestricted ukPub: 0001000b00040072000000100014000b0800000000000100b24019a18856d00cf470c889e63feac7620b1859b5d8d6e2b5cc45cc6cd1b1aa74a997aab5ec4a265ba944a1af680a74acfe4e8447599927eef3650ee0db9c8b294e45744a75a77cf4894650f1ecaeb69396b646f1ff63d9ffc2dfa5d1bfec54a60c00fb77a53e5edb4f294d77f2c8106cf8db1246438bf7352833957875499b4744e41a8da2994f0b1c1dce8d009081276c15982bf4ee3adfc6c468b3e1674900897c4b97c9514cd1f86347586425c8655364afd9040782c26573d4b47aab69738227657d9da5941adb39f9b87c54d636fb32eeb89c10b1d8296d5149e8855e22c45a5028454e898d2d097fa559484bd6ab86786f5260703b04c0ad3fe417fd,
I0620 12:27:26.013396       1 client.go:1322]      Unrestricted ukPriv: 002053b1650829532c0d65ec941893a686fc1f90384a94d2b7405452719f245751a600107e6d254fd08aa959303624fbd8e7a96eaf950717ff58dc7ea382a981f504e32634581630e88d5952ee1883f2c2abe388134c984cda7bb6ef3e8934f783eb272547c809f3568278849a291b5a997614aef7d7c938c86259e3d4ac4d549b74318a859e4da6ab435b57090886dfc97b05c383655420217e20c1826ede731ec839c8d93f6cd0b3d613e1a2704cc0afd34205f688272e2446f4034eedebd0c30ae0070312cf199a25fa0d63e112a164e1d477b2234a18fd0d1aa278e5,
I0620 12:27:26.013435       1 client.go:1324]      Write (ukPub) ========
I0620 12:27:26.013547       1 client.go:1329]      Write (ukPriv) ========
I0620 12:27:26.022781       1 client.go:1363]      ukeyName: 000b1277e50d200f9595832e4a88612fae87eca227109728b1b8fe5243e9aba874eb,
I0620 12:27:26.028331       1 client.go:1373]      Certify Attestation: ff54434780170022000bb7d99ec5929c67a20f115d4710cc720616e56f59aacf56179550f2b58017d5b50000000000000007c27e00000009000000000120160511001628000022000b1277e50d200f9595832e4a88612fae87eca227109728b1b8fe5243e9aba874eb0022000bc76c82858a0227c8eac03837d1fcef1c89ba0d26e8de0dc5810ab140ab2bd2c4,
I0620 12:27:26.028372       1 client.go:1374]      Certify Signature: aa61050f0ed9a2ffaa6bc0d087e6979c618df974fb0f68542c7481f84b0c1fda391708e8254070e612bbd70acd8b1e961c4980673f11b801e1027eb7ecd6f555e804cd6522d7540fdfae8d02fdbd232fe9cd697adc406958414f85aec1aed8863da759dfa0e722681b7c0256e5033416f05a78e81d96be855813dccf145663cf54d8859a349980583980139b852f775838dad20d704085728eb833a0fadbbd871ec8b663d4c104583c177ed0a008bf8c070efd29c9a0f3dc5c781cb04e45506421479dc60f574af26b80024f531e16ca62a7b138d806d05fc378d7799d580a5a5f8fbefee13f6675387e0b63597af34b6e52eb21354f0c9bcd520e3b34dc68e8,
I0620 12:27:26.033068       1 client.go:1397]      ukPubPEM: 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAskAZoYhW0Az0cMiJ5j/q
x2ILGFm12NbitcxFzGzRsap0qZeqtexKJlupRKGvaAp0rP5OhEdZmSfu82UO4Nuc
iylORXRKdad89IlGUPHsrraTlrZG8f9j2f/C36XRv+xUpgwA+3elPl7bTylNd/LI
EGz42xJGQ4v3NSgzlXh1SZtHROQajaKZTwscHc6NAJCBJ2wVmCv07jrfxsRos+Fn
SQCJfEuXyVFM0fhjR1hkJchlU2Sv2QQHgsJlc9S0eqtpc4InZX2dpZQa2zn5uHxU
1jb7Mu64nBCx2CltUUnohV4ixFpQKEVOiY0tCX+lWUhL1quGeG9SYHA7BMCtP+QX
/QIDAQAB
-----END PUBLIC KEY-----
I0620 12:27:26.034751       1 client.go:1406]      TPM based Hash for Unrestricted Key w6uP8Tcg6K2QR905Rms8iXTlksL6OD1KOWBxTK7wxPI=
I0620 12:27:26.040521       1 client.go:1415] Control Signature data with unrestriced Key:  BkF39ZnUe/+rJsvzrWmZUMPawWVL1v5reQTYzGMaYY8iWk2XmhlCv0DucRNi5qGkuC6SZdB4ejmGKTRhki6Eg9q2y7trDxd5k+xBNiQ/bxSwT4d7ZR9XyzFiZg/O7cnZkWMEJsrk5Fosfr50AkDugsHnkNzveL4fTX1GzSPXVCGUJpevMs1Q67ahpfC8PBDW582NEhGSuxfVtVwQr1gvxoV9IAlKYOWlX6DT1/6WffX+2Ui5oNfVl9feZ/PsvvSLq4KCsOOq6KZsJMXUyOAtU/J2V98iVjxIhCfyxm/9qi048SHFQsoardrOBWIrABYDItoR1pbVFT3rSEMtv6uJcw
I0620 12:27:26.040950       1 client.go:1423]      Unrestricted Key Signature Verified
I0620 12:27:26.049245       1 client.go:679]      Returning SigningKey
I0620 12:27:26.401850       1 client.go:692]      SigningKey Response true
I0620 12:27:32.001518       1 client.go:707]      >>>>>>>>>>>>>>> System Provisioned <<<<<<<<<<<<<<
I0620 12:27:32.001588       1 client.go:715]      Worker 1 starting

```
