module main

go 1.14

require (
	cloud.google.com/go v0.81.0
	cloud.google.com/go/firestore v1.3.0
	cloud.google.com/go/logging v1.4.2 // indirect
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/golang/glog v0.0.0-20160126235308-23def4e6c14b
	github.com/golang/protobuf v1.5.2
	github.com/google/go-tpm v0.3.1
	github.com/google/go-tpm-tools v0.2.0
	github.com/google/tink/go v1.4.0
	github.com/google/uuid v1.1.2
	github.com/lestrrat/go-jwx v0.0.0-20180221005942-b7d4802280ae
	github.com/lestrrat/go-pdebug v0.0.0-20180220043741-569c97477ae8 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	golang.org/x/crypto v0.0.0-20200622213623-75b288015ac9
	golang.org/x/net v0.0.0-20210503060351-7fd8e65b6420
	google.golang.org/api v0.46.0
	google.golang.org/genproto v0.0.0-20210517163617-5e0236093d7a
	google.golang.org/grpc v1.37.1
	certparser v0.0.0	
	oid v0.0.0
	tokenservice v0.0.0
)

replace (
	certparser => ./src/util/certparser
	oid => ./src/util/certparser/oid
	tokenservice => ./src/tokenservice
)
