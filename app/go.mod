module main

go 1.14

require (
	cloud.google.com/go v0.58.0
	cloud.google.com/go/datastore v1.1.0
	cloud.google.com/go/firestore v1.2.0 // indirect
	github.com/dgrijalva/jwt-go v3.2.0+incompatible

	github.com/google/uuid v1.1.1 // indirect
	github.com/lestrrat/go-jwx v0.0.0-20180221005942-b7d4802280ae
	github.com/lestrrat/go-pdebug v0.0.0-20180220043741-569c97477ae8 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	google.golang.org/api v0.26.0
	google.golang.org/genproto v0.0.0-20200608115520-7c474a2e3482
	google.golang.org/grpc v1.29.1
	tokenservice v0.0.0

	github.com/google/go-tpm v0.2.1-0.20191106030929-f0607eac7f8a
	github.com/google/go-tpm-tools v0.1.3-0.20200303025303-b83096c36b80

)

replace tokenservice => ./src/tokenservice
