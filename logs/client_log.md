### Sample TokenClient log
(in reverse order)

```log
...
...
I0622 11:59:03.211109       1 client.go:289] Attempting to contact TokenServer [2]
I0622 11:59:03.211232       1 client.go:697]      Sleeping..
I0622 11:59:13.211605       1 client.go:289] Attempting to contact TokenServer [3]
I0622 11:59:13.211866       1 client.go:697]      Sleeping..
E0622 11:59:13.227746       1 client.go:346] Error:   GetToken() from TokenService: rpc error: code = Unavailable desc = connection error: desc = "transport: Error while dialing dial tcp 34.136.142.112:50051: i/o timeout"
I0622 11:59:23.212349       1 client.go:289] Attempting to contact TokenServer [4]
I0622 11:59:23.212376       1 client.go:697]      Sleeping..
E0622 11:59:23.227246       1 client.go:346] Error:   GetToken() from TokenService: rpc error: code = Unavailable desc = connection error: desc = "transport: Error while dialing dial tcp 34.136.142.112:50051: i/o timeout"
I0622 11:59:33.212629       1 client.go:289] Attempting to contact TokenServer [5]
I0622 11:59:33.212755       1 client.go:697]      Sleeping..
E0622 11:59:33.226890       1 client.go:346] Error:   GetToken() from TokenService: rpc error: code = Unavailable desc = connection error: desc = "transport: Error while dialing dial tcp 34.136.142.112:50051: i/o timeout"
I0622 11:59:43.212964       1 client.go:289] Attempting to contact TokenServer [6]
I0622 11:59:43.213026       1 client.go:697]      Sleeping..
E0622 11:59:43.227459       1 client.go:346] Error:   GetToken() from TokenService: rpc error: code = Unavailable desc = connection error: desc = "transport: Error while dialing dial tcp 34.136.142.112:50051: i/o timeout"
I0622 11:59:53.213247       1 client.go:289] Attempting to contact TokenServer [7]
I0622 11:59:53.213356       1 client.go:697]      Sleeping..
E0622 11:59:53.230068       1 client.go:346] Error:   GetToken() from TokenService: rpc error: code = Unavailable desc = connection error: desc = "transport: Error while dialing dial tcp 34.136.142.112:50051: i/o timeout"
I0622 12:00:03.213610       1 client.go:289] Attempting to contact TokenServer [8]
I0622 12:00:03.214323       1 client.go:697]      Sleeping..
E0622 12:00:03.228675       1 client.go:346] Error:   GetToken() from TokenService: rpc error: code = Unavailable desc = connection error: desc = "transport: Error while dialing dial tcp 34.136.142.112:50051: i/o timeout"
I0622 12:00:13.214568       1 client.go:289] Attempting to contact TokenServer [9]
I0622 12:00:13.214698       1 client.go:697]      Sleeping..
E0622 12:00:13.229047       1 client.go:346] Error:   GetToken() from TokenService: rpc error: code = Unavailable desc = connection error: desc = "transport: Error while dialing dial tcp 34.136.142.112:50051: i/o timeout"
I0622 12:00:23.215192       1 client.go:289] Attempting to contact TokenServer [10]
I0622 12:00:23.215317       1 client.go:697]      Sleeping..
E0622 12:00:23.230055       1 client.go:346] Error:   GetToken() from TokenService: rpc error: code = Unavailable desc = connection error: desc = "transport: Error while dialing dial tcp 34.136.142.112:50051: i/o timeout"
I0622 12:00:33.215680       1 client.go:289] Attempting to contact TokenServer [11]
I0622 12:00:33.215782       1 client.go:697]      Sleeping..
E0622 12:00:33.229467       1 client.go:346] Error:   GetToken() from TokenService: rpc error: code = Unavailable desc = connection error: desc = "transport: Error while dialing dial tcp 34.136.142.112:50051: i/o timeout"
I0622 12:00:43.216055       1 client.go:289] Attempting to contact TokenServer [12]
I0622 12:00:43.216805       1 client.go:697]      Sleeping..
E0622 12:00:43.230931       1 client.go:346] Error:   GetToken() from TokenService: rpc error: code = Unavailable desc = connection error: desc = "transport: Error while dialing dial tcp 34.136.142.112:50051: i/o timeout"
I0622 12:00:53.217168       1 client.go:289] Attempting to contact TokenServer [13]
I0622 12:00:53.217295       1 client.go:697]      Sleeping..
E0622 12:00:53.226848       1 client.go:346] Error:   GetToken() from TokenService: rpc error: code = Unavailable desc = connection error: desc = "transport: Error while dialing dial tcp 34.136.142.112:50051: i/o timeout"
E0622 12:01:00.317042       1 client.go:346] Error:   GetToken() from TokenService: rpc error: code = Unavailable desc = connection error: desc = "transport: Error while dialing dial tcp 34.136.142.112:50051: connect: connection refused"
I0622 12:01:03.217548       1 client.go:289] Attempting to contact TokenServer [14]
I0622 12:01:03.217584       1 client.go:697]      Sleeping..
E0622 12:01:03.230116       1 client.go:346] Error:   GetToken() from TokenService: rpc error: code = Unavailable desc = connection error: desc = "transport: Error while dialing dial tcp 34.136.142.112:50051: i/o timeout"
I0622 12:01:13.217786       1 client.go:289] Attempting to contact TokenServer [15]
I0622 12:01:13.217839       1 client.go:697]      Sleeping..
I0622 12:01:23.218037       1 client.go:289] Attempting to contact TokenServer [16]
I0622 12:01:23.218978       1 client.go:697]      Sleeping..
E0622 12:01:23.228485       1 client.go:346] Error:   GetToken() from TokenService: rpc error: code = Unavailable desc = connection error: desc = "transport: Error while dialing dial tcp 34.136.142.112:50051: i/o timeout"
E0622 12:01:30.348140       1 client.go:346] Error:   GetToken() from TokenService: rpc error: code = Unauthenticated desc = IssuedAt Identity document timestamp too old
I0622 12:01:33.219183       1 client.go:289] Attempting to contact TokenServer [17]
I0622 12:01:33.219233       1 client.go:697]      Sleeping..
E0622 12:01:33.230922       1 client.go:346] Error:   GetToken() from TokenService: rpc error: code = Unavailable desc = connection error: desc = "transport: Error while dialing dial tcp 34.136.142.112:50051: i/o timeout"
E0622 12:01:33.318500       1 client.go:346] Error:   GetToken() from TokenService: rpc error: code = PermissionDenied desc = InstanceID not Found  rpc error: code = NotFound desc = "projects/ts-1b7443bf/databases/(default)/documents/foo/8939838129032687278" not found
I0622 12:01:43.219488       1 client.go:289] Attempting to contact TokenServer [18]
I0622 12:01:43.219533       1 client.go:697]      Sleeping..
E0622 12:01:43.311823       1 client.go:346] Error:   GetToken() from TokenService: rpc error: code = PermissionDenied desc = InstanceID not Found  rpc error: code = NotFound desc = "projects/ts-1b7443bf/databases/(default)/documents/foo/8939838129032687278" not found
I0622 12:01:53.219727       1 client.go:289] Attempting to contact TokenServer [19]
I0622 12:01:53.219766       1 client.go:697]      Sleeping..
E0622 12:01:53.310599       1 client.go:346] Error:   GetToken() from TokenService: rpc error: code = PermissionDenied desc = InstanceID not Found  rpc error: code = NotFound desc = "projects/ts-1b7443bf/databases/(default)/documents/foo/8939838129032687278" not found
I0622 12:02:03.219945       1 client.go:289] Attempting to contact TokenServer [20]
I0622 12:02:03.219989       1 client.go:697]      Sleeping..
E0622 12:02:03.324502       1 client.go:346] Error:   GetToken() from TokenService: rpc error: code = PermissionDenied desc = InstanceID not Found  rpc error: code = NotFound desc = "projects/ts-1b7443bf/databases/(default)/documents/foo/8939838129032687278" not found
I0622 12:02:13.220332       1 client.go:289] Attempting to contact TokenServer [21]
I0622 12:02:13.220471       1 client.go:697]      Sleeping..
E0622 12:02:13.298984       1 client.go:346] Error:   GetToken() from TokenService: rpc error: code = PermissionDenied desc = InstanceID not Found  rpc error: code = NotFound desc = "projects/ts-1b7443bf/databases/(default)/documents/foo/8939838129032687278" not found
I0622 12:02:23.220590       1 client.go:289] Attempting to contact TokenServer [22]
I0622 12:02:23.220649       1 client.go:697]      Sleeping..
E0622 12:02:23.293066       1 client.go:346] Error:   GetToken() from TokenService: rpc error: code = PermissionDenied desc = InstanceID not Found  rpc error: code = NotFound desc = "projects/ts-1b7443bf/databases/(default)/documents/foo/8939838129032687278" not found
I0622 12:02:33.220794       1 client.go:289] Attempting to contact TokenServer [23]
I0622 12:02:33.220854       1 client.go:697]      Sleeping..
E0622 12:02:33.296032       1 client.go:346] Error:   GetToken() from TokenService: rpc error: code = PermissionDenied desc = InstanceID not Found  rpc error: code = NotFound desc = "projects/ts-1b7443bf/databases/(default)/documents/foo/8939838129032687278" not found
I0622 12:02:43.221026       1 client.go:289] Attempting to contact TokenServer [24]
I0622 12:02:43.221128       1 client.go:697]      Sleeping..
E0622 12:02:43.308076       1 client.go:346] Error:   GetToken() from TokenService: rpc error: code = PermissionDenied desc = InstanceID not Found  rpc error: code = NotFound desc = "projects/ts-1b7443bf/databases/(default)/documents/foo/8939838129032687278" not found
I0622 12:02:53.221285       1 client.go:289] Attempting to contact TokenServer [25]
I0622 12:02:53.221335       1 client.go:697]      Sleeping..
E0622 12:02:53.289623       1 client.go:346] Error:   GetToken() from TokenService: rpc error: code = PermissionDenied desc = InstanceID not Found  rpc error: code = NotFound desc = "projects/ts-1b7443bf/databases/(default)/documents/foo/8939838129032687278" not found
I0622 12:03:03.221509       1 client.go:289] Attempting to contact TokenServer [26]
I0622 12:03:03.221555       1 client.go:697]      Sleeping..
E0622 12:03:03.292013       1 client.go:346] Error:   GetToken() from TokenService: rpc error: code = PermissionDenied desc = InstanceID not Found  rpc error: code = NotFound desc = "projects/ts-1b7443bf/databases/(default)/documents/foo/8939838129032687278" not found
I0622 12:03:13.221693       1 client.go:289] Attempting to contact TokenServer [27]
I0622 12:03:13.221777       1 client.go:697]      Sleeping..
E0622 12:03:13.317501       1 client.go:346] Error:   GetToken() from TokenService: rpc error: code = PermissionDenied desc = InstanceID not Found  rpc error: code = NotFound desc = "projects/ts-1b7443bf/databases/(default)/documents/foo/8939838129032687278" not found
I0622 12:03:23.221951       1 client.go:289] Attempting to contact TokenServer [28]
I0622 12:03:23.222065       1 client.go:697]      Sleeping..
E0622 12:03:23.326464       1 client.go:346] Error:   GetToken() from TokenService: rpc error: code = PermissionDenied desc = InstanceID not Found  rpc error: code = NotFound desc = "projects/ts-1b7443bf/databases/(default)/documents/foo/8939838129032687278" not found
I0622 12:03:33.222353       1 client.go:289] Attempting to contact TokenServer [29]
I0622 12:03:33.223022       1 client.go:697]      Sleeping..
E0622 12:03:33.322968       1 client.go:346] Error:   GetToken() from TokenService: rpc error: code = PermissionDenied desc = InstanceID not Found  rpc error: code = NotFound desc = "projects/ts-1b7443bf/databases/(default)/documents/foo/8939838129032687278" not found
I0622 12:03:43.223141       1 client.go:289] Attempting to contact TokenServer [30]
I0622 12:03:43.223897       1 client.go:697]      Sleeping..
E0622 12:03:43.310407       1 client.go:346] Error:   GetToken() from TokenService: rpc error: code = PermissionDenied desc = InstanceID not Found  rpc error: code = NotFound desc = "projects/ts-1b7443bf/databases/(default)/documents/foo/8939838129032687278" not found
I0622 12:03:53.224195       1 client.go:289] Attempting to contact TokenServer [31]
I0622 12:03:53.224245       1 client.go:697]      Sleeping..
E0622 12:03:53.323718       1 client.go:346] Error:   GetToken() from TokenService: rpc error: code = PermissionDenied desc = InstanceID not Found  rpc error: code = NotFound desc = "projects/ts-1b7443bf/databases/(default)/documents/foo/8939838129032687278" not found
I0622 12:04:03.224389       1 client.go:289] Attempting to contact TokenServer [32]
I0622 12:04:03.224448       1 client.go:697]      Sleeping..
E0622 12:04:03.277354       1 client.go:346] Error:   GetToken() from TokenService: rpc error: code = PermissionDenied desc = InstanceID not Found  rpc error: code = NotFound desc = "projects/ts-1b7443bf/databases/(default)/documents/foo/8939838129032687278" not found
I0622 12:04:13.224692       1 client.go:289] Attempting to contact TokenServer [33]
I0622 12:04:13.224753       1 client.go:697]      Sleeping..
E0622 12:04:13.311899       1 client.go:346] Error:   GetToken() from TokenService: rpc error: code = PermissionDenied desc = InstanceID not Found  rpc error: code = NotFound desc = "projects/ts-1b7443bf/databases/(default)/documents/foo/8939838129032687278" not found
I0622 12:04:23.224903       1 client.go:289] Attempting to contact TokenServer [34]
I0622 12:04:23.225121       1 client.go:697]      Sleeping..
E0622 12:04:23.285093       1 client.go:346] Error:   GetToken() from TokenService: rpc error: code = PermissionDenied desc = InstanceID not Found  rpc error: code = NotFound desc = "projects/ts-1b7443bf/databases/(default)/documents/foo/8939838129032687278" not found
I0622 12:04:33.225381       1 client.go:289] Attempting to contact TokenServer [35]
I0622 12:04:33.225453       1 client.go:697]      Sleeping..
E0622 12:04:33.328875       1 client.go:346] Error:   GetToken() from TokenService: rpc error: code = PermissionDenied desc = InstanceID not Found  rpc error: code = NotFound desc = "projects/ts-1b7443bf/databases/(default)/documents/foo/8939838129032687278" not found
I0622 12:04:43.225655       1 client.go:289] Attempting to contact TokenServer [36]
I0622 12:04:43.225704       1 client.go:697]      Sleeping..
E0622 12:04:43.308754       1 client.go:346] Error:   GetToken() from TokenService: rpc error: code = PermissionDenied desc = InstanceID not Found  rpc error: code = NotFound desc = "projects/ts-1b7443bf/databases/(default)/documents/foo/8939838129032687278" not found
I0622 12:04:53.225878       1 client.go:289] Attempting to contact TokenServer [37]
I0622 12:04:53.225924       1 client.go:697]      Sleeping..
E0622 12:04:53.298698       1 client.go:346] Error:   GetToken() from TokenService: rpc error: code = PermissionDenied desc = InstanceID not Found  rpc error: code = NotFound desc = "projects/ts-1b7443bf/databases/(default)/documents/foo/8939838129032687278" not found
null
I0622 12:05:03.226120       1 client.go:289] Attempting to contact TokenServer [38]
I0622 12:05:03.226187       1 client.go:697]      Sleeping..
E0622 12:05:03.314370       1 client.go:346] Error:   GetToken() from TokenService: rpc error: code = PermissionDenied desc = InstanceID not Found  rpc error: code = NotFound desc = "projects/ts-1b7443bf/databases/(default)/documents/foo/8939838129032687278" not found
I0622 12:05:13.226371       1 client.go:289] Attempting to contact TokenServer [39]
I0622 12:05:13.226412       1 client.go:697]      Sleeping..
E0622 12:05:13.318061       1 client.go:346] Error:   GetToken() from TokenService: rpc error: code = PermissionDenied desc = InstanceID not Found  rpc error: code = NotFound desc = "projects/ts-1b7443bf/databases/(default)/documents/foo/8939838129032687278" not found
I0622 12:05:23.226609       1 client.go:289] Attempting to contact TokenServer [40]
I0622 12:05:23.226655       1 client.go:697]      Sleeping..
null
I0622 12:05:23.815397       1 client.go:362]      Received  toResponse: 1f641610-d352-11eb-b51d-0242ac110002
I0622 12:05:23.815581       1 client.go:367]      Received  Data: name:"secret1"  data:"fooobar"
I0622 12:05:23.815643       1 client.go:370]      Decoding as RAW fooobar
I0622 12:05:23.815674       1 client.go:367]      Received  Data: name:"secret2"  type:TINK  data:"\x08\xb9\xf0\x9a\xd6\x06\x12d\nX\n0type.googleapis.com/google.crypto.tink.AesGcmKey\x12\"\x1a \x0eӡ\xcc\x02\x9b~\xff\xde\xf4^\x10d\x91\xb2\x84\xa9\xf9\xad\n\x02\xaf\x8a`B\xaa(~]V\xa0\xb8\x18\x01\x10\x01\x18\xb9\xf0\x9a\xd6\x06 \x01"
I0622 12:05:23.815791       1 client.go:380]      Decoding as Tink
I0622 12:05:23.816021       1 client.go:404]      Tink AEAD encrypted text AWrGuDnrlnZl8INA9KlvGIl3N0xfa67S7KLaFsMvuJEcAwMa
I0622 12:05:23.816073       1 client.go:411]      Tink AEAD Decrypted Text foo
I0622 12:05:23.832189       1 client.go:441] =============== Load EncryptionKey and Certifcate from NV ===============
I0622 12:05:23.941344       1 client.go:459]      Encryption PEM 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAon140WZ75XDaoprRmmsa
4i7ueGtXkWIfNdTFpirNwRikslULGdh1V4zzPwm9CCJozsvWc9LVl4IM5/Fa2/eH
of4cxoPELkdAI1MR0qH84bqijTCCYl9DOT/IB2eZPAoJ9D8NYCmG5NdwNk4KOQg1
HshTEMAZ7Ruz7SgFJ1Jf9G/Fj8WtFY8lP0bb4jeO+tOhQbZ62Puw+ngRckdSTowM
l/mF8gLCSLIj2EcXEqrKsxJ/dqL/3egB7A7Wexxy0xwxPK15ppRWEmtjprbF2Riz
tgALlBqFTW7Lwl8NyubZOW2dYrf4F5Ph1wHwLTG9dNoyDuzpXltIphgwLJFheNPs
2QIDAQAB
-----END PUBLIC KEY-----
I0622 12:05:23.943565       1 client.go:481]      Load SigningKey and Certifcate 
I0622 12:05:24.021802       1 client.go:499]      Signing PEM 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5Ogtmk0I0GF77l7T4dXe
D7i/G2edQzaR0gzdJirquKzoALtysvEgAuA35zlc8iL0DXXTsLgq6SPIW8RHcWsh
c4HtOE9FExflmvY+vQ3vodi2XlwDKylWYgneDxXxCl9dnAA+fUmRqKIiRUPHk6QH
A/DLEvHfgtZgRX7OV0a6YSWAWN+wx9G1hwrcOvmQoY0Dg23CiAh4gBUe/7z/nAIs
0A4VIq0oHI+l5uQ+4WLvUIWNU9QQ89rRaSVMXAWIMCwZu++oT2Az3GGRbLpXtmrR
ilYbepZqXhYPOyMEG50HrfJmJEEOUEEn2z8Cz7JwZDOPO71tkUbKEjU6ayvg/Vjj
LwIDAQAB
-----END PUBLIC KEY-----
I0622 12:05:24.025807       1 client.go:560]      AK Issued Hash w6uP8Tcg6K2QR905Rms8iXTlksL6OD1KOWBxTK7wxPI=
I0622 12:05:24.030774       1 client.go:569]      AK Signed Data HnfUCVd2vCgmXiJ834QZ0BUGQZD5WPUXAVGzwfpAi7VLWniKp96uizV8ygln2O2RS/qkSOG29gCuKFDENWGLPKL1SeTwfAGtCqlmn6j+zHjmuAmMcCYS8zPTQHVP4DfGxo2sQxEJJ6tAAcvvP9O+6WhCIRVJvBt5pO2VUF9cqCWW3wD1rsvOxitxv3LQizfTJL3sjll/mNUIsEUXvNzEfFvZN/yA2noAzp78BMDoAAJkG4O4G+tCS+0tbZx9P05XIrHG4Y6BPWq219cM5VeMVqZdJRBKMp/qqWoSJe47FWm1oDTn7wWSgVyeAc5lunvSnCEj95s6wQpZVCryehDSdA==
I0622 12:05:24.031094       1 client.go:575]      Signature Verified
I0622 12:05:24.034509       1 client.go:591] =============== Create AK manually ===============
I0622 12:05:24.035056       1 client.go:846]      --> CreateKeys()
I0622 12:05:24.036667       1 client.go:856]     Current PCR 0 Value %!d(string=24af52a4f429b71a3184a6d64cddad17e54ea030e2aa6576bf3a5a3d8bd3328f) 
I0622 12:05:24.036723       1 client.go:861]      createPrimary
I0622 12:05:24.132609       1 client.go:879]      tpmEkPub: 
&{20512477926697847886762473633835154278537216751711082010481331619566349403631200349296771283598424715939130063315763781826417026955687218543240704530577327378623076250728582892878271503967584859565762381972158857127423615376680506963650827249450077352280774517276517767898168712856136911414495384081164531266140936666214165990012595042174024660991281746389357308286903805441573118891029162658935736484300659703088617550643868022163210451039886708564694564209370877460358400084154881167900520095431387569532773177629639266926642155398993169485768915972169414948105205096500088095637726045171333052087357525446022655193 65537}
I0622 12:05:24.132740       1 client.go:892]      ekPub Name: 000b2383e4506c650fdcd0ef4765082d180836b5a1801c00834465ee1d3bda08262e
I0622 12:05:24.132752       1 client.go:893]      ekPubPEM: 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAon140WZ75XDaoprRmmsa
4i7ueGtXkWIfNdTFpirNwRikslULGdh1V4zzPwm9CCJozsvWc9LVl4IM5/Fa2/eH
of4cxoPELkdAI1MR0qH84bqijTCCYl9DOT/IB2eZPAoJ9D8NYCmG5NdwNk4KOQg1
HshTEMAZ7Ruz7SgFJ1Jf9G/Fj8WtFY8lP0bb4jeO+tOhQbZ62Puw+ngRckdSTowM
l/mF8gLCSLIj2EcXEqrKsxJ/dqL/3egB7A7Wexxy0xwxPK15ppRWEmtjprbF2Riz
tgALlBqFTW7Lwl8NyubZOW2dYrf4F5Ph1wHwLTG9dNoyDuzpXltIphgwLJFheNPs
2QIDAQAB
-----END PUBLIC KEY-----
I0622 12:05:24.132781       1 client.go:900]      CreateKeyUsingAuth
I0622 12:05:24.291156       1 client.go:926]      akPub: 0001000b00050072000000100014000b0800000000000100c22bc0b1c6aafb37bc152b99f41d27d5432415ebfe11543867a4ab3dbb2733fd780ce84f322ce315294aee06afacaeed1df5b01302c634c08597039dabde78e21b33065e053a7ea43808a63de82dc4a916e520390bc3f6a5592e0b001aa62b0def4cbcafe812056e4249f1492db71536b475a3e6793823bf3528ffabd980ebb028e419b930de906958185c578c14ec324bd7cc43ea940944cd4242fa48970080d1517ebc3a2f8998f72de7e930b2b899c1cfc5b269efabab53ba442189d40b2b99a90962404ec7b427107188928b284ea2ba1e800897706dc0b2b862c77dba9c928ed83cfd54b8cad2731b04d47d5eedcfff1fa04537a3003e7dd0fca7547823,
I0622 12:05:24.291238       1 client.go:927]      akPriv: 0020fbe7dcfa3ac34f816efc7042597e38634f73a0295130de847a362f76b98ae64d00106e8a69b2cc798309897cb994a32f186d1046c21d62abcc329803b8f8b74fc9a9f105e68afa31957d10d14219bcf3c3ccf4dda4ae1827c339f92a11cea7c6b443105cc965c32b6199176fa46e86db20d3c3804860859fdf21320efbe813181b22a353053ecf89bf3536efbc366ade51272c44a5525b90b53aa0ed2a0911fca875c146438bff6cd5113b41e648580122a4a58214fe18c74cec32f11eb0174aa92187327f6a21c7ee275322cc00fb68323698dd9b8f3205c19b44f0,
I0622 12:05:24.291341       1 client.go:934]      CredentialData.ParentName.Digest.Value 2383e4506c650fdcd0ef4765082d180836b5a1801c00834465ee1d3bda08262e
I0622 12:05:24.291377       1 client.go:935]      CredentialTicket 602abcc0e1c3c45f92d1363cb251a3fdb1252ecd892e30e3a585cdde8149582c
I0622 12:05:24.291455       1 client.go:936]      CredentialHash 393f7baaa0e3a7355039e12427973abbaac0a74e4c20b1fa495e61a729913609
I0622 12:05:24.291543       1 client.go:938]      ContextSave (ek)
I0622 12:05:24.301065       1 client.go:949]      ContextLoad (ek)
I0622 12:05:24.309080       1 client.go:959]      LoadUsingAuth
I0622 12:05:24.316055       1 client.go:987]      AK keyName 000b38bf125fe251606c0df4ff0777c86d65423ad453ca148863fbae501bd5737d39
I0622 12:05:24.318492       1 client.go:1009]      akPubPEM: 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwivAscaq+ze8FSuZ9B0n
1UMkFev+EVQ4Z6SrPbsnM/14DOhPMizjFSlK7gavrK7tHfWwEwLGNMCFlwOdq954
4hszBl4FOn6kOAimPegtxKkW5SA5C8P2pVkuCwAapisN70y8r+gSBW5CSfFJLbcV
NrR1o+Z5OCO/NSj/q9mA67Ao5Bm5MN6QaVgYXFeMFOwyS9fMQ+qUCUTNQkL6SJcA
gNFRfrw6L4mY9y3n6TCyuJnBz8Wyae+rq1O6RCGJ1AsrmakJYkBOx7QnEHGIkoso
TqK6HoAIl3BtwLK4Ysd9upySjtg8/VS4ytJzGwTUfV7tz/8foEU3owA+fdD8p1R4
IwIDAQAB
-----END PUBLIC KEY-----
I0622 12:05:24.318528       1 client.go:1011]      Write (akPub) ========
I0622 12:05:24.318589       1 client.go:1016]      Write (akPriv) ========
I0622 12:05:24.318614       1 client.go:1022]      <-- CreateKeys()
null
I0622 12:05:26.002111       1 client.go:615]      MakeCredential RPC RequestID [206fac7b-d352-11eb-a211-0242ac110002] InResponseTo ID [40adda5d-3879-4e2b-8c47-5c459d629e75]
I0622 12:05:26.002173       1 client.go:617] =============== ActivateCredential  ===============
I0622 12:05:26.002189       1 client.go:1028]      --> activateCredential()
I0622 12:05:26.002194       1 client.go:1033]      ContextLoad (ek)
I0622 12:05:26.010509       1 client.go:1044]      Read (akPub)
I0622 12:05:26.010592       1 client.go:1049]      Read (akPriv)
I0622 12:05:26.010625       1 client.go:1055]      LoadUsingAuth
I0622 12:05:26.017828       1 client.go:1082]      keyName 000b38bf125fe251606c0df4ff0777c86d65423ad453ca148863fbae501bd5737d39
I0622 12:05:26.017857       1 client.go:1084]      ActivateCredentialUsingAuth
I0622 12:05:26.029292       1 client.go:1132]      <--  activateCredential()
I0622 12:05:26.036141       1 client.go:767]      --> Start Quote
I0622 12:05:26.038010       1 client.go:777]      PCR 0 Value 24af52a4f429b71a3184a6d64cddad17e54ea030e2aa6576bf3a5a3d8bd3328f 
I0622 12:05:26.038097       1 client.go:782]      ContextLoad (ek) ========
I0622 12:05:26.045971       1 client.go:792]      LoadUsingAuth ========
I0622 12:05:26.049087       1 client.go:814]      Read (akPub) ========
I0622 12:05:26.049322       1 client.go:819]      Read (akPriv) ========
I0622 12:05:26.053799       1 client.go:831]      AK keyName 000b38bf125fe251606c0df4ff0777c86d65423ad453ca148863fbae501bd5737d39
I0622 12:05:26.059602       1 client.go:837]      Quote Hex ff54434780180022000b1c9b1cbed577b835ba5bfb26dd4f1dbc510082aec7d45c20960f675ef12a6d9e000a54654d6150455a516c65000000000006ae89000000090000000001201605110016280000000001000b0301000000202ba7022b59f2158786ea3ea29a7ad12ff0c6c9d6682da6555d8926075b643b1f
I0622 12:05:26.059639       1 client.go:838]      Quote Sig 4c875eae1267ca4e82f6ae462120250812cc556355868f6e745f4377672ca1850e50a4d4b3dd154eb742175ac7331845514c8c41e4bc4cd84c43c7c70a8f5601d9352ef3e54a9233de4fc3e57304ed9c847f1dd55db1155768fe51840059b4f574b160a41cd45d18b663d94a62db0ed38ab631bd0d043d39183ec9e8d3dd17c67df76f4cef2fca8ea6c311a0f17a142523fde0b6b88780ec6b587e38e4caf4b24e839622695781f632af97f0b733aacd44d8e9729d4ed12cff729b03dd7b37571d82b7112bfbfb55ee8490d33769e96268ee224ca62dc43b81069ac2ff91d3d8b295577835d4cc3618644e50d14573bfac0c214f06443b564dccc60ff7077161
I0622 12:05:26.059652       1 client.go:839]      <-- End Quote
null
I0622 12:05:26.524586       1 client.go:640] =============== responseID:"2157ebb0-d352-11eb-a211-0242ac110002"  inResponseTo:"40adda5d-3879-4e2b-8c47-5c459d629e75"  verified:true
I0622 12:05:26.524651       1 client.go:641] =============== OfferQuote ===============
null
I0622 12:05:26.939051       1 client.go:651]      Quote Requested with nonce 3fd1cc63-4859-414a-b679-8d8c2556aae7, pcr: 0
I0622 12:05:26.939097       1 client.go:653] =============== Generating Quote ===============
I0622 12:05:26.939108       1 client.go:767]      --> Start Quote
I0622 12:05:26.951643       1 client.go:777]      PCR 0 Value 24af52a4f429b71a3184a6d64cddad17e54ea030e2aa6576bf3a5a3d8bd3328f 
I0622 12:05:26.951668       1 client.go:782]      ContextLoad (ek) ========
I0622 12:05:26.959791       1 client.go:792]      LoadUsingAuth ========
I0622 12:05:26.962997       1 client.go:814]      Read (akPub) ========
I0622 12:05:26.963051       1 client.go:819]      Read (akPriv) ========
I0622 12:05:26.967204       1 client.go:831]      AK keyName 000b38bf125fe251606c0df4ff0777c86d65423ad453ca148863fbae501bd5737d39
I0622 12:05:26.973064       1 client.go:837]      Quote Hex ff54434780180022000b1c9b1cbed577b835ba5bfb26dd4f1dbc510082aec7d45c20960f675ef12a6d9e002433666431636336332d343835392d343134612d623637392d386438633235353661616537000000000006b21a000000090000000001201605110016280000000001000b0301000000202ba7022b59f2158786ea3ea29a7ad12ff0c6c9d6682da6555d8926075b643b1f
I0622 12:05:26.973089       1 client.go:838]      Quote Sig 7b420d15c16042d92e0133becd59f3aa63f8b921acb9dd50492eeb315d3c56f2a2e3a62c2dc060ec10db8148ea6bd04de3a508b97cd34d5378d51070e86d641746a59bdca6a2d2672b20acde21177d3406f5fa0d7c7a99c1064f28c8ea37bfd361d1f44b1f1fc27247e9e1d8719bfcf5b504f34510d185446784fdadf4aebbadd72eb16e5264ac8d9366cc4210ebe1674dd4c390302feafac2a384cb19bb34e40a95b1fba75859a6cc49a1bec1afb6cc6b4e1f65e7b273f9655faf01d0dbd3166a23e8e6260bdbb550a786953d4de740bc93f954a99f1869b2e587794e460937b22ac08a617e54508d997d5e7ce1f5d4149207cbba4c9e4a3e8f9ae43f209d69
I0622 12:05:26.973098       1 client.go:839]      <-- End Quote
I0622 12:05:26.976015       1 client.go:659] =============== Providing Quote ===============
null
I0622 12:05:27.427877       1 client.go:670]      Provided Quote verified: true
I0622 12:05:27.427923       1 client.go:673] =============== Providing SigningKey ===============
I0622 12:05:27.427936       1 client.go:1144]      --> Start signingKey
I0622 12:05:27.429471       1 client.go:1154]      PCR 0 Value 24af52a4f429b71a3184a6d64cddad17e54ea030e2aa6576bf3a5a3d8bd3328f 
I0622 12:05:27.429541       1 client.go:1159]      ContextLoad (ek)
I0622 12:05:27.438027       1 client.go:1172]      Read (akPub)
I0622 12:05:27.438218       1 client.go:1177]      Read (akPriv)
I0622 12:05:27.438307       1 client.go:1183]      LoadUsingAuth ========
I0622 12:05:27.445467       1 client.go:1209]      AK keyName: 000b38bf125fe251606c0df4ff0777c86d65423ad453ca148863fbae501bd5737d39
I0622 12:05:27.446415       1 client.go:1213] ======= SignwithRestrictedKey ========
I0622 12:05:27.450916       1 client.go:1262]      AK Issued Hash w6uP8Tcg6K2QR905Rms8iXTlksL6OD1KOWBxTK7wxPI=
I0622 12:05:27.455922       1 client.go:1271]      AK Signed Data vwC4zl8cY3wR9J8j97a08COgB1hXHo+bnJBoP82gPWqvZyt0kdTb1BHIV9xq5I7WqqlK+Ko587ewc9rjk9PKKKWpw3sNtudOHCEsAcEZoJ4D1NapBN/VZsKXh37DroEZ8mwjrxVD8h/FVeeKwBLxCu6DxBSUDaQuIyVZlzCgERlPj6IetemOxGUDKySd+O3v6q9blxeg/szyMVs/ZmmbBG2L7B9f0/b4FirV/JKjdq35CrDrJPWvAztMwkaE9FlmhgnLukvDOme5KNRN7odmwxsbEQtQKR+Ij7SZ0mXLOJ0P3dqCDBDgcLn61kSKEv7XFOTUeZlNmPMEfcCWU43ITQ==
I0622 12:05:27.456083       1 client.go:1292]      AK Verified Signature
I0622 12:05:27.456113       1 client.go:1295] ======= SignwithUnrestrictedKey ========
I0622 12:05:27.517994       1 client.go:1321]      Unrestricted ukPub: 0001000b00040072000000100014000b0800000000000100e321638d2c58d2aef1536f0a8e97776c2ecb01ac976e3d48926c18280732140f2e3b70f982138d797c548b92f32ae3cd3d973f5804eb1be6fd13ae845e0224f8d2df392fe5a36c1012a433f1149008d31196319050c674805e8eabe8c29d046fe3dd91a741bb5a1f2f3aa391180ab21fdd8117c4376793cbc59a47d62a6200de8e85e79ddae92bde3d4eaa8796e08a37450f44e261fdeed61f1579e9a7bdd0e06df39e16170ede83ccd68eb5e66a62328584d0adf79b772d0ad7fdd3e90bc62c6597347eae99ab57bfb7bad5c17b3e25c417f7e3e08ade95e25eb51fe164dafd3ed6154b361adfd2c6deaafdbb6f253b00720103ddd6c675b9cd36cc65ec079f,
I0622 12:05:27.518033       1 client.go:1322]      Unrestricted ukPriv: 0020523965108b6b866a5c6fcaf56b6870c10c2e77b2359babd12f61ca093225967a001086305608e37845c80638e6928eea4acb85f6f787d8669a3ece542f245237831a1a91005175c221277c1c8cf8a55f1574e56989e3074fb5b7082635358032db46ff91f895df32b07e800d40548cb7a08771a8282e5122b193eb3e8d9c4e16e785857e9cf88551a56ed954e74be3754b7b15577f03673fedb6444224d7acf6320b951d53294b8929446c9c60150764808f612f3a63f632d13b0333c1228d312f14c3748b0a429dcc485ecff4697a0b556854237e9a3109453c619d,
I0622 12:05:27.518047       1 client.go:1324]      Write (ukPub) ========
I0622 12:05:27.518118       1 client.go:1329]      Write (ukPriv) ========
I0622 12:05:27.527622       1 client.go:1363]      ukeyName: 000b847f86e868aa98e22ccf5607c8fe95e4d879a3c9681b4934294864b81c28c8d5,
I0622 12:05:27.532947       1 client.go:1373]      Certify Attestation: ff54434780170022000b1c9b1cbed577b835ba5bfb26dd4f1dbc510082aec7d45c20960f675ef12a6d9e0000000000000006b44a00000009000000000120160511001628000022000b847f86e868aa98e22ccf5607c8fe95e4d879a3c9681b4934294864b81c28c8d50022000b4f34c3765f57fbb26eb958f67684b5413f7c39979fceca105e50c8145fa2f06f,
I0622 12:05:27.533017       1 client.go:1374]      Certify Signature: 31e27c0ed263c47a69c1a3b3f608f8bc514ecee3a483513cb77e3200e20e0449902896e7ff6630745d0e203064228a98f6b9bd790a2a771a0258c980e5211c3ec8c27b6e5c6c2044702d1de5b79e58141afb85b9af1adc69108b7946e96f89115bc57bfc036e6fb59cb6b8cb0a991fd578f58a75af826e5b097d8d1edaecb1c00e0e192d93de274d878ebb17f7766c68b0c591578a76bce9835718c53dddd42dadc3119fe7c9549f28cfe3683b7cf01e2ccc5b97c7c0e3bbddcbbd1b696c3546d96eb85e79c18019ce441cf29ae0c7cf9e496e9fb899cf808e728e6efd1a7caeb37abebdfe5453c4189b457c0e68f7fbd4f91c5e0ac5967f667c5bf5858dd345,
I0622 12:05:27.537106       1 client.go:1397]      ukPubPEM: 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4yFjjSxY0q7xU28Kjpd3
bC7LAayXbj1IkmwYKAcyFA8uO3D5ghONeXxUi5LzKuPNPZc/WATrG+b9E66EXgIk
+NLfOS/lo2wQEqQz8RSQCNMRljGQUMZ0gF6Oq+jCnQRv492Rp0G7Wh8vOqORGAqy
H92BF8Q3Z5PLxZpH1ipiAN6Oheed2ukr3j1OqoeW4Io3RQ9E4mH97tYfFXnpp73Q
4G3znhYXDt6DzNaOteZqYjKFhNCt95t3LQrX/dPpC8YsZZc0fq6Zq1e/t7rVwXs+
JcQX9+Pgit6V4l61H+Fk2v0+1hVLNhrf0sbeqv27byU7AHIBA93WxnW5zTbMZewH
nwIDAQAB
-----END PUBLIC KEY-----
I0622 12:05:27.539894       1 client.go:1406]      TPM based Hash for Unrestricted Key w6uP8Tcg6K2QR905Rms8iXTlksL6OD1KOWBxTK7wxPI=
I0622 12:05:27.545115       1 client.go:1415] Control Signature data with unrestriced Key:  QVQ89LRn1PScphvFPapaIuOLOkeSjvx66Poskk8I/6g3tZBGsUPbUrWHEtezpsbc+BTFvirtUtLYPKG94xKueFJyGyPaBb4tSj6rUasjD5C+S2vJ1meiSanjBsBXIyfkVaQg6Y640Z0kxQ4F/Gn3CBn3lPPhjUZaW+Y8JYv900ENP0tq9370jVr9d09jM3m6AlAZmS3jm3kVbHZxPT/LSUM9eD6bFmrIkhXDtZRGvTGUMZ9u/RYzPSaYdWDtt+KIlmd7fysfUSk2bmJFnFN7ucXSYNZCn91sthuT5Op7E1ZofFEske5is7KBvbuTObt55Q3g5w7zDu8SumJpY2yM6A
I0622 12:05:27.545442       1 client.go:1423]      Unrestricted Key Signature Verified
I0622 12:05:27.552396       1 client.go:679]      Returning SigningKey
null
I0622 12:05:28.087495       1 client.go:692]      SigningKey Response true
I0622 12:05:33.226834       1 client.go:707]      >>>>>>>>>>>>>>> System Provisioned <<<<<<<<<<<<<<
I0622 12:05:33.226916       1 client.go:715]      Worker 1 starting

```
