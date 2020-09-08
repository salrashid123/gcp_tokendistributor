module main

go 1.14

require (
	cloud.google.com/go/firestore v1.3.0 // indirect
	github.com/dgrijalva/jwt-go v3.2.0+incompatible // indirect
	github.com/gogo/protobuf v1.3.1 // indirect
	github.com/golang/protobuf v1.4.2
	github.com/google/go-tpm v0.2.1-0.20191106030929-f0607eac7f8a
	github.com/google/go-tpm-tools v0.1.3-0.20200303025303-b83096c36b80
	github.com/google/uuid v1.1.2 // indirect
	github.com/lestrrat/go-jwx v0.0.0-20180221005942-b7d4802280ae // indirect
	github.com/lestrrat/go-pdebug v0.0.0-20180220043741-569c97477ae8 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	golang.org/x/net v0.0.0-20200904194848-62affa334b73 // indirect
	google.golang.org/api v0.31.0 // indirect
	tokenservice v0.0.0
)

replace tokenservice => ./src/tokenservice
