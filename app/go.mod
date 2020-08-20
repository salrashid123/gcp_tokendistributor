module main

go 1.14

require (
	cloud.google.com/go v0.58.0
	cloud.google.com/go/firestore v1.2.0
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/golang/glog v0.0.0-20160126235308-23def4e6c14b
	github.com/golang/protobuf v1.4.2
	github.com/google/go-tpm v0.2.1-0.20200701210658-e06fe77d4428
	github.com/google/go-tpm-tools v0.1.3-0.20200626093744-11f284793aa8
	github.com/google/uuid v1.1.1
	github.com/lestrrat/go-jwx v0.0.0-20180221005942-b7d4802280ae
	github.com/lestrrat/go-pdebug v0.0.0-20180220043741-569c97477ae8 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	golang.org/x/net v0.0.0-20200520182314-0ba52f642ac2
	google.golang.org/api v0.26.0
	google.golang.org/genproto v0.0.0-20200608115520-7c474a2e3482
	google.golang.org/grpc v1.29.1
	google.golang.org/protobuf v1.25.0 // indirect
	tokenservice v0.0.0

)

replace tokenservice => ./src/tokenservice
