package main

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"

	"net"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"tokenservice"

	"github.com/golang/glog"

	"math/rand"
	"os"

	"cloud.google.com/go/firestore"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/google/go-tpm/tpm2"
	"github.com/lestrrat/go-jwx/jwk"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"github.com/google/uuid"
	"google.golang.org/api/compute/v1"
	secretmanagerpb "google.golang.org/genproto/googleapis/cloud/secretmanager/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/alts"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type gcpIdentityDoc struct {
	Google struct {
		ComputeEngine struct {
			InstanceCreationTimestamp int64  `json:"instance_creation_timestamp,omitempty"`
			InstanceID                string `json:"instance_id,omitempty"`
			InstanceName              string `json:"instance_name,omitempty"`
			ProjectID                 string `json:"project_id,omitempty"`
			ProjectNumber             int64  `json:"project_number,omitempty"`
			Zone                      string `json:"zone,omitempty"`
		} `json:"compute_engine"`
	} `json:"google"`
	Email           string `json:"email,omitempty"`
	EmailVerified   bool   `json:"email_verified,omitempty"`
	AuthorizedParty string `json:"azp,omitempty"`
	jwt.StandardClaims
}

type ServiceEntry struct {
	Description        string    `firestore:"description,omitempty"`
	Done               bool      `firestore:"done"`
	InstanceID         string    `firestore:"instanceid"`
	ClientProject      string    `firestore:"client_project"`
	ClientZone         string    `firestore:"client_zone"`
	ServiceAccountName string    `firestore:"service_account_name"`
	InitScriptHash     string    `firestore:"init_script_hash"`
	SealedRSAKey       []byte    `firestore:"rsa_key,omitempty"`
	SealedAESKey       []byte    `firestore:"aes_key,omitempty"`
	PCR                int64     `firestore:"pcr"`
	PCRValue           string    `firestore:"pcr_value,omitempty"`
	GCSObjectReference string    `firestore:"gcs_object,omitempty"`
	ProvidedAt         time.Time `firestore:"provided_at"`
}

type contextKey string
type server struct{}
type verifierserver struct{}
type healthServer struct {
	mu        sync.Mutex
	statusMap map[string]healthpb.HealthCheckResponse_ServingStatus
}

const (
	jwksURL   = "https://www.googleapis.com/oauth2/v3/certs"
	tpmDevice = "/dev/tpm0"
)

var (
	grpcport                = flag.String("grpcport", ":50051", "grpcport")
	tlsCert                 = flag.String("tlsCert", "tokenservice.crt", "TLS Certificate")
	tlsKey                  = flag.String("tlsKey", "tokenservice.key", "TLS Key")
	tlsCertChain            = flag.String("tlsCertChain", "tls-ca-chain.pem", "TLS CA Chain")
	tsAudience              = flag.String("tsAudience", "", "Audience value for the TokenService")
	useSecrets              = flag.Bool("useSecrets", false, "Use Google Secrets Manager for TLS Keys")
	useALTS                 = flag.Bool("useALTS", false, "Use Application Layer Transport Security")
	firestoreProjectId      = flag.String("firestoreProjectId", "", "firestoreProjectId where the sealed data is stored")
	firestoreCollectionName = flag.String("firestoreCollectionName", "", "firestoreCollectionName where the sealedData is Stored")

	expectedPCRValue = flag.String("expectedPCRValue", "fcecb56acc303862b30eb342c4990beb50b5e0ab89722449c2d9a73f37b019fe", "expectedPCRValue")
	pcr              = flag.Int("pcr", 0, "PCR Value to use")
	registry         = make(map[string]tokenservice.MakeCredentialRequest)
	nonces           = make(map[string]string)
	jwtSet           *jwk.Set
	hs               *health.Server
	rwc              io.ReadWriteCloser

	handleNames = map[string][]tpm2.HandleType{
		"all":       []tpm2.HandleType{tpm2.HandleTypeLoadedSession, tpm2.HandleTypeSavedSession, tpm2.HandleTypeTransient},
		"loaded":    []tpm2.HandleType{tpm2.HandleTypeLoadedSession},
		"saved":     []tpm2.HandleType{tpm2.HandleTypeSavedSession},
		"transient": []tpm2.HandleType{tpm2.HandleTypeTransient},
	}

	defaultKeyParams = tpm2.Public{
		Type:    tpm2.AlgRSA,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin |
			tpm2.FlagUserWithAuth | tpm2.FlagRestricted | tpm2.FlagSign,
		AuthPolicy: []byte{},
		RSAParameters: &tpm2.RSAParams{
			Sign: &tpm2.SigScheme{
				Alg:  tpm2.AlgRSASSA,
				Hash: tpm2.AlgSHA256,
			},
			KeyBits: 2048,
		},
	}
)

func (s *healthServer) Check(ctx context.Context, in *healthpb.HealthCheckRequest) (*healthpb.HealthCheckResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if in.Service == "" {
		return &healthpb.HealthCheckResponse{Status: healthpb.HealthCheckResponse_SERVING}, nil
	}
	s.statusMap["tokenservice.TokenServiceServer"] = healthpb.HealthCheckResponse_SERVING
	status, ok := s.statusMap[in.Service]
	if !ok {
		return &healthpb.HealthCheckResponse{Status: healthpb.HealthCheckResponse_UNKNOWN}, grpc.Errorf(codes.NotFound, "unknown service")
	}
	return &healthpb.HealthCheckResponse{Status: status}, nil
}

func (s *healthServer) Watch(in *healthpb.HealthCheckRequest, srv healthpb.Health_WatchServer) error {
	return status.Error(codes.Unimplemented, "Watch is not implemented")
}

func getKey(token *jwt.Token) (interface{}, error) {
	keyID, ok := token.Header["kid"].(string)
	if !ok {
		return nil, errors.New("expecting JWT header to have string kid")
	}
	if key := jwtSet.LookupKeyID(keyID); len(key) == 1 {
		glog.V(2).Infof("     Found OIDC KeyID  " + keyID)
		return key[0].Materialize()
	}
	return nil, errors.New("unable to find key")
}

func verifyGoogleIDToken(ctx context.Context, aud string, rawToken string) (gcpIdentityDoc, error) {
	token, err := jwt.ParseWithClaims(rawToken, &gcpIdentityDoc{}, getKey)
	if err != nil {
		glog.Errorf("     Error parsing JWT %v", err)
		return gcpIdentityDoc{}, err
	}
	if claims, ok := token.Claims.(*gcpIdentityDoc); ok && token.Valid {
		glog.Errorf("     OIDC doc has Audience [%s]   Issuer [%s] and SubjectEmail [%s]", claims.Audience, claims.StandardClaims.Issuer, claims.Email)
		return *claims, nil
	}
	return gcpIdentityDoc{}, errors.New("Error parsing JWT Claims")
}

func authUnaryInterceptor(
	ctx context.Context,
	req interface{},
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (interface{}, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	if len(md["authorization"]) > 0 {
		reqToken := md["authorization"][0]
		splitToken := strings.Split(reqToken, "Bearer")
		reqToken = strings.TrimSpace(splitToken[1])
		doc, err := verifyGoogleIDToken(ctx, *tsAudience, reqToken)
		if err != nil {
			glog.Errorf("   Authentication Header Not Sent")
			return nil, grpc.Errorf(codes.Unauthenticated, "authentication required")
		}

		if *useALTS {
			ai, err := alts.AuthInfoFromContext(ctx)
			if err != nil {
				glog.Errorf("   Unable to cross check with ALTS Peer Service Account")
				return nil, grpc.Errorf(codes.Unauthenticated, "Unable to cross check with ALTS Peer Service Account")
			}
			glog.V(2).Infof("     AuthInfo PeerServiceAccount: %v", ai.PeerServiceAccount())
			glog.V(2).Infof("     AuthInfo LocalServiceAccount: %v", ai.LocalServiceAccount())
			if doc.Email != ai.PeerServiceAccount() {
				glog.Errorf("   ALTS ServiceAccount does not match provided OIDC Token Email")
				return nil, grpc.Errorf(codes.Unauthenticated, "ALTS ServiceAccount does not match provided OIDC Token Email")
			}
		}
		newCtx := context.WithValue(ctx, contextKey("idtoken"), doc)
		newCtx = context.WithValue(newCtx, contextKey("subject"), doc.Subject)
		newCtx = context.WithValue(newCtx, contextKey("email"), doc.Email)
		newCtx = context.WithValue(newCtx, contextKey("instanceID"), doc.Google.ComputeEngine.InstanceID)
		return handler(newCtx, req)
	}
	return nil, grpc.Errorf(codes.Unauthenticated, "Authorization header not provided")
}

func (s *server) GetToken(ctx context.Context, in *tokenservice.TokenRequest) (*tokenservice.TokenResponse, error) {

	subject := ctx.Value(contextKey("subject")).(string)
	email := ctx.Value(contextKey("email")).(string)
	instanceID := ctx.Value(contextKey("instanceID")).(string)
	glog.V(2).Infof("     Got rpc: RequestID %s for subject %s and email %s for instanceID %s\n", in.RequestId, subject, email, instanceID)

	glog.V(2).Infof("     Looking up Firestore Collection %s for instanceID %s", *firestoreCollectionName, instanceID)

	fsclient, err := firestore.NewClient(ctx, *firestoreProjectId)
	if err != nil {
		glog.Errorf("ERROR:  Could not create new Firestore Client %v", err)
		return &tokenservice.TokenResponse{}, grpc.Errorf(codes.Internal, "Unable to create Firestore Client")
	}
	dsnap, err := fsclient.Collection(*firestoreCollectionName).Doc(instanceID).Get(ctx)
	if err != nil {
		glog.Errorf("ERROR:  Could not find instanceID new Firestore Client %s", instanceID)
		return &tokenservice.TokenResponse{}, grpc.Errorf(codes.NotFound, fmt.Sprintf("InstanceID not Found  %v", err))
	}

	var c ServiceEntry
	dsnap.DataTo(&c)

	glog.V(2).Infof("     Looking up InstanceID using GCE APIs for instanceID %s", instanceID)

	computeService, err := compute.NewService(ctx)
	if err != nil {
		glog.Errorf("ERROR:  Could not create Compute Engine API %v", err)
		return &tokenservice.TokenResponse{}, grpc.Errorf(codes.NotFound, fmt.Sprintf("Could not create ComputeClient %v", err))
	}

	cresp, err := computeService.Instances.Get(c.ClientProject, c.ClientZone, instanceID).Do()
	glog.V(2).Infof("     Found  VM instanceID %#v\n", strconv.FormatUint(cresp.Id, 10))
	glog.V(2).Infof("     Found  VM ServiceAccount %#v\n", cresp.ServiceAccounts[0].Email)
	var initScriptHash string
	for _, m := range cresp.Metadata.Items {
		if m.Key == "user-data" {
			hasher := sha256.New()
			hasher.Write([]byte(*m.Value))
			initScriptHash = base64.StdEncoding.EncodeToString(hasher.Sum(nil))
			glog.V(2).Infof("     Derived Image Hash from metadata %s", initScriptHash)
		}
	}
	if initScriptHash != c.InitScriptHash {
		glog.Errorf("   -------->  Error Init Script does not match got [%s]  expected [%s]", initScriptHash, c.InitScriptHash)
		return &tokenservice.TokenResponse{}, grpc.Errorf(codes.NotFound, fmt.Sprintf("Error:  Init Script does not match got [%s]  expected [%s]", initScriptHash, c.InitScriptHash))
	}
	if c.InitScriptHash == "" {
		glog.Errorf("   *********** NOTE: initscript is empty (non-COS VM or never set)...")
		// optionally just continue here if debugging
		return &tokenservice.TokenResponse{}, grpc.Errorf(codes.NotFound, fmt.Sprintf("Error:  Init Script is empty"))
	}

	respID, err := uuid.NewUUID()
	if err != nil {
		return &tokenservice.TokenResponse{}, grpc.Errorf(codes.Internal, "Unable to create UUID?!")
	}

	// TODO: since we've provided the token maybe update the Firestore "Done" field
	//       however, its better if this server does not have r/w access to firestore
	//       maybe update a different semaphore
	// e := &ServiceEntry{
	// 	Done:               false,
	// }
	// resp, err := client.Collection(*firestoreCollectionName).Doc(*clientVMId).Set(ctx, e)
	// if err != nil {
	// 	log.Printf("An error has occurred: %s", err)
	// }
	// log.Printf(resp.UpdateTime.String())

	return &tokenservice.TokenResponse{
		ResponseID:   respID.String(),
		InResponseTo: in.RequestId,
		SealedAESKey: c.SealedAESKey,
		SealedRSAKey: c.SealedRSAKey,
		Pcr:          c.PCR,
	}, nil
}

func main() {

	flag.Parse()

	argError := func(s string, v ...interface{}) {
		//flag.PrintDefaults()
		glog.Fatalf("Invalid Argument error: "+s, v...)
	}

	if *tsAudience == "" {
		argError("-tsAudience not specified")
	}

	var caCert []byte
	var caCertPool *x509.CertPool
	var certificate tls.Certificate
	var err error

	jwtSet, err = jwk.FetchHTTP(jwksURL)
	if err != nil {
		glog.Fatalf("Unable to load JWK Set: ", err)
	}

	lis, err := net.Listen("tcp", *grpcport)
	if err != nil {
		glog.Fatalf("failed to listen: %v", err)
	}

	sopts := []grpc.ServerOption{grpc.MaxConcurrentStreams(10)}
	if *useALTS {
		glog.V(2).Infof("     Using ALTS")

		altsTC := alts.NewServerCreds(alts.DefaultServerOptions())
		sopts = append(sopts, grpc.Creds(altsTC))
	} else {
		glog.V(2).Infof("     Using mTLS")
		if *useSecrets {
			glog.V(10).Infof("     Getting mTLS certs from Secrets Manager")

			ctx := context.Background()

			client, err := secretmanager.NewClient(ctx)
			if err != nil {
				glog.Fatalf("Error creating Secrets Client")
			}

			tlsCACert_name := fmt.Sprintf("%s/versions/latest", *tlsCertChain)
			tlsCACert_req := &secretmanagerpb.AccessSecretVersionRequest{
				Name: tlsCACert_name,
			}

			tlsCACert_result, err := client.AccessSecretVersion(ctx, tlsCACert_req)
			if err != nil {
				glog.Fatalf("failed to access  tlsCertChain secret version: %v", err)
			}
			caCert = tlsCACert_result.Payload.Data

			tlsCert_name := fmt.Sprintf("%s/versions/latest", *tlsCert)
			tlsCert_req := &secretmanagerpb.AccessSecretVersionRequest{
				Name: tlsCert_name,
			}

			tlsCert_result, err := client.AccessSecretVersion(ctx, tlsCert_req)
			if err != nil {
				glog.Fatalf("Error: failed to access tlsCert secret version: %v", err)
			}
			certPem := tlsCert_result.Payload.Data

			tlsKey_name := fmt.Sprintf("%s/versions/latest", *tlsKey)
			tlsKey_req := &secretmanagerpb.AccessSecretVersionRequest{
				Name: tlsKey_name,
			}

			tlsKey_result, err := client.AccessSecretVersion(ctx, tlsKey_req)
			if err != nil {
				glog.Fatalf("Error: failed to access tlsKey secret version: %v", err)
			}
			keyPem := tlsKey_result.Payload.Data

			certificate, err = tls.X509KeyPair(certPem, keyPem)
			if err != nil {
				glog.Fatalf("Error: could not load TLS Certificate chain: %s", err)
			}

		} else {
			glog.V(10).Infof("     Getting mTLS certs from files")

			caCert, err = ioutil.ReadFile(*tlsCertChain)
			if err != nil {
				glog.Fatalf("could not load TLS Certificate chain: %s", err)
			}

			certificate, err = tls.LoadX509KeyPair(*tlsCert, *tlsKey)
			if err != nil {
				glog.Fatalf("could not load server key pair: %s", err)
			}
		}

		caCertPool = x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)

		var tlsConfig tls.Config
		tlsConfig = tls.Config{
			ClientAuth:   tls.RequireAndVerifyClientCert,
			Certificates: []tls.Certificate{certificate},
			ClientCAs:    caCertPool,
		}

		ce := credentials.NewTLS(&tlsConfig)
		sopts = append(sopts, grpc.Creds(ce))
	}

	sopts = append(sopts, grpc.UnaryInterceptor(authUnaryInterceptor))
	sopts = append(sopts)
	s := grpc.NewServer(sopts...)

	tokenservice.RegisterTokenServiceServer(s, &server{})
	tokenservice.RegisterVerifierServer(s, &verifierserver{})
	healthpb.RegisterHealthServer(s, &healthServer{})

	rwc, err = tpm2.OpenTPM(tpmDevice)
	if err != nil {
		glog.Fatalf("can't open TPM %q: %v", tpmDevice, err)
	}
	defer func() {
		if err := rwc.Close(); err != nil {
			glog.Fatalf("can't close TPM %q: %v", tpmDevice, err)
		}
	}()
	var gracefulStop = make(chan os.Signal)
	signal.Notify(gracefulStop, syscall.SIGTERM)
	signal.Notify(gracefulStop, syscall.SIGINT)
	go func() {
		sig := <-gracefulStop
		glog.V(2).Infof("caught sig: %+v\n", sig)
		glog.V(2).Infof("Wait for 1 second to finish processing")
		time.Sleep(1 * time.Second)
		os.Exit(0)
	}()
	glog.V(2).Infof("Starting TokenService..")
	s.Serve(lis)
}

func (s *verifierserver) MakeCredential(ctx context.Context, in *tokenservice.MakeCredentialRequest) (*tokenservice.MakeCredentialResponse, error) {

	glog.V(2).Infof("======= MakeCredential ========")
	glog.V(5).Infof("     client provided uid: %s", in.Uid)
	glog.V(10).Infof("     Got AKName %s", in.AkName)
	glog.V(10).Infof("     Registry size %d\n", len(registry))

	idToken := ctx.Value(contextKey("idtoken")).(gcpIdentityDoc)
	glog.V(5).Infof("     From InstanceID %s", idToken.Google.ComputeEngine.InstanceID)

	newCtx := context.Background()

	computService, err := compute.NewService(newCtx)
	if err != nil {
		return &tokenservice.MakeCredentialResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Unable to Verify EK with GCP APIs %v", err))
	}

	req := computService.Instances.GetShieldedInstanceIdentity(idToken.Google.ComputeEngine.ProjectID, idToken.Google.ComputeEngine.Zone, idToken.Google.ComputeEngine.InstanceName)
	r, err := req.Do()
	if err != nil {
		return &tokenservice.MakeCredentialResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Unable to Recall Shielded Identity %v", err))
	}

	glog.V(10).Infof("     Acquired PublickKey from GCP API: \n%s", r.EncryptionKey.EkPub)

	glog.V(10).Infof("     Decoding ekPub from client")
	ekPub, err := tpm2.DecodePublic(in.EkPub)
	if err != nil {
		return &tokenservice.MakeCredentialResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Error DecodePublic EK %v", err))
	}

	ekPubKey, err := ekPub.Key()
	if err != nil {
		return &tokenservice.MakeCredentialResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Error extracting ekPubKey: %s", err))
	}
	ekBytes, err := x509.MarshalPKIXPublicKey(ekPubKey)
	if err != nil {
		return &tokenservice.MakeCredentialResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Unable to convert ekPub: %v", err))
	}

	ekPubPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: ekBytes,
		},
	)
	glog.V(10).Infof("     EKPubPEM: \n%v", string(ekPubPEM))

	if string(ekPubPEM) != r.EncryptionKey.EkPub {
		return &tokenservice.MakeCredentialResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("EkPub mismatchKey"))
	}

	glog.V(2).Infof("     Verified EkPub from GCE API matches ekPub from Client")

	registry[idToken.Google.ComputeEngine.InstanceID] = *in

	var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	b := make([]rune, 10)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	nonces[in.Uid] = string(b)
	//nonces[idToken.Google.ComputeEngine.InstanceID] = string(b)

	credBlob, encryptedSecret, err := makeCredential(nonces[in.Uid], in.EkPub, in.AkPub)
	if err != nil {
		return &tokenservice.MakeCredentialResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Unable to makeCredential"))
	}
	glog.V(2).Infof("     Returning MakeCredentialResponse ========")
	return &tokenservice.MakeCredentialResponse{
		Uid:             in.Uid,
		CredBlob:        credBlob,
		EncryptedSecret: encryptedSecret,
		Pcr:             int32(*pcr),
	}, nil
}

func (s *verifierserver) ActivateCredential(ctx context.Context, in *tokenservice.ActivateCredentialRequest) (*tokenservice.ActivateCredentialResponse, error) {

	glog.V(2).Infof("======= ActivateCredential ========")
	glog.V(5).Infof("     client provided uid: %s", in.Uid)
	glog.V(10).Infof("     Secret %s", in.Secret)

	idToken := ctx.Value(contextKey("idtoken")).(gcpIdentityDoc)
	glog.V(5).Infof("     From InstanceID %s", idToken.Google.ComputeEngine.InstanceID)

	verified := false
	var id string
	id = idToken.Google.ComputeEngine.InstanceID

	err := verifyQuote(id, nonces[in.Uid], in.Attestation, in.Signature)
	if err != nil {
		glog.Errorf("     Quote Verification Failed Quote: %v", err)
		return &tokenservice.ActivateCredentialResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Quote Verification Failed Quote: %v", err))
	} else {
		glog.V(2).Infof("     Verified Quote")
		verified = true
		delete(nonces, in.Uid)
	}

	glog.V(2).Infof("     Returning ActivateCredentialResponse ========")

	return &tokenservice.ActivateCredentialResponse{
		Uid:      in.Uid,
		Verified: verified,
	}, nil
}

func (s *verifierserver) OfferQuote(ctx context.Context, in *tokenservice.OfferQuoteRequest) (*tokenservice.OfferQuoteResponse, error) {
	glog.V(2).Infof("======= OfferQuote ========")
	glog.V(5).Infof("     client provided uid: %s", in.Uid)

	idToken := ctx.Value(contextKey("idtoken")).(gcpIdentityDoc)
	glog.V(5).Infof("     From InstanceID %s", idToken.Google.ComputeEngine.InstanceID)

	nonce := uuid.New().String()
	var id string

	id = idToken.Google.ComputeEngine.InstanceID

	glog.V(2).Infof("     Returning OfferQuoteResponse ========")
	nonces[id] = nonce
	return &tokenservice.OfferQuoteResponse{
		Uid:   in.Uid,
		Pcr:   int32(*pcr),
		Nonce: nonce,
	}, nil
}

func (s *verifierserver) ProvideQuote(ctx context.Context, in *tokenservice.ProvideQuoteRequest) (*tokenservice.ProvideQuoteResponse, error) {
	glog.V(2).Infof("======= ProvideQuote ========")
	glog.V(5).Infof("     client provided uid: %s", in.Uid)
	idToken := ctx.Value(contextKey("idtoken")).(gcpIdentityDoc)
	glog.V(5).Infof("     From InstanceID %s", idToken.Google.ComputeEngine.InstanceID)

	ver := false
	var id string

	id = idToken.Google.ComputeEngine.InstanceID

	val, ok := nonces[id]
	if !ok {
		glog.V(2).Infof("Unable to find nonce request for uid")
	} else {
		delete(nonces, id)
		err := verifyQuote(id, val, in.Attestation, in.Signature)
		if err == nil {
			ver = true
		} else {
			return &tokenservice.ProvideQuoteResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Unable to Verify Quote %v", err))
		}
	}

	glog.V(2).Infof("     Returning ProvideQuoteResponse ========")
	return &tokenservice.ProvideQuoteResponse{
		Uid:      in.Uid,
		Verified: ver,
	}, nil
}

func (s *verifierserver) ProvideSigningKey(ctx context.Context, in *tokenservice.ProvideSigningKeyRequest) (*tokenservice.ProvideSigningKeyResponse, error) {
	glog.V(2).Infof("======= ProvideSigningKey ========")
	glog.V(5).Infof("     client provided uid: %s", in.Uid)

	idToken := ctx.Value(contextKey("idtoken")).(gcpIdentityDoc)
	glog.V(5).Infof("     From InstanceID %s", idToken.Google.ComputeEngine.InstanceID)

	glog.V(5).Infof("     SigningKey %s\n", in.Signingkey)
	glog.V(5).Infof("     SigningKey Attestation %s\n", in.Attestation)
	glog.V(5).Infof("     SigningKey Signature %s\n", in.Signature)
	// TODO: use EK to verify Attestation and Signature
	// https://github.com/salrashid123/tpm2/tree/master/sign_certify_ak
	ver := true

	glog.V(2).Infof("     Returning ProvideSigningKeyResponse ========")
	return &tokenservice.ProvideSigningKeyResponse{
		Uid:      in.Uid,
		Verified: ver,
	}, nil
}

func verifyQuote(uid string, nonce string, attestation []byte, sigBytes []byte) (retErr error) {
	glog.V(2).Infof("     --> Starting verifyQuote()")

	nn := registry[uid]
	akPub := nn.AkPub

	glog.V(10).Infof("     Read and Decode (attestion)")
	att, err := tpm2.DecodeAttestationData(attestation)
	if err != nil {
		glog.Errorf("ERROR:  DecodeAttestationData(%v) failed: %v", attestation, err)
		return fmt.Errorf("DecodeAttestationData(%v) failed: %v", attestation, err)
	}

	glog.V(5).Infof("     Attestation ExtraData (nonce): %s ", string(att.ExtraData))
	glog.V(5).Infof("     Attestation PCR#: %v ", att.AttestedQuoteInfo.PCRSelection.PCRs)
	glog.V(5).Infof("     Attestation Hash: %v ", hex.EncodeToString(att.AttestedQuoteInfo.PCRDigest))

	if nonce != string(att.ExtraData) {
		glog.Errorf("     Nonce Value mismatch Got: (%s) Expected: (%v)", string(att.ExtraData), nonce)
		return fmt.Errorf("ERROR Nonce Value mismatch Got: (%s) Expected: (%v)", string(att.ExtraData), nonce)
	}

	sigL := tpm2.SignatureRSA{
		HashAlg:   tpm2.AlgSHA256,
		Signature: sigBytes,
	}
	decoded, err := hex.DecodeString(*expectedPCRValue)
	if err != nil {
		return fmt.Errorf("DecodeAttestationData(%v) failed: %v", attestation, err)
	}
	hash := sha256.Sum256(decoded)

	glog.V(5).Infof("     Expected PCR Value:           --> %s", *expectedPCRValue)
	glog.V(5).Infof("     sha256 of Expected PCR Value: --> %x", hash)

	glog.V(2).Infof("     Decoding PublicKey for AK ========")
	p, err := tpm2.DecodePublic(akPub)
	if err != nil {
		return fmt.Errorf("DecodePublic failed: %v", err)
	}
	rsaPub := rsa.PublicKey{E: int(p.RSAParameters.Exponent()), N: p.RSAParameters.Modulus()}
	hsh := crypto.SHA256.New()
	hsh.Write(attestation)
	if err := rsa.VerifyPKCS1v15(&rsaPub, crypto.SHA256, hsh.Sum(nil), sigL.Signature); err != nil {
		return fmt.Errorf("VerifyPKCS1v15 failed: %v", err)
	}

	if fmt.Sprintf("%x", hash) != hex.EncodeToString(att.AttestedQuoteInfo.PCRDigest) {
		return fmt.Errorf("Unexpected PCR hash Value expected: %s  Got %s", fmt.Sprintf("%x", hash), hex.EncodeToString(att.AttestedQuoteInfo.PCRDigest))
	}

	if nonce != string(att.ExtraData) {
		return fmt.Errorf("Unexpected secret Value expected: %v  Got %v", nonce, string(att.ExtraData))
	}
	glog.V(2).Infof("     Attestation Signature Verified ")
	glog.V(2).Infof("     <-- End verifyQuote()")
	return nil
}

func makeCredential(sec string, ekPubBytes []byte, akPubBytes []byte) (credBlob []byte, encryptedSecret []byte, retErr error) {

	glog.V(2).Infof("     --> Starting makeCredential()")
	glog.V(10).Infof("     Read (ekPub) from request")

	ekPub, err := tpm2.DecodePublic(ekPubBytes)
	if err != nil {
		return []byte(""), []byte(""), fmt.Errorf("Error DecodePublic AK %v", err)
	}

	ekh, keyName, err := tpm2.LoadExternal(rwc, ekPub, tpm2.Private{}, tpm2.HandleNull)
	if err != nil {
		return []byte(""), []byte(""), fmt.Errorf("Error loadingExternal EK %v", err)
	}
	defer tpm2.FlushContext(rwc, ekh)

	glog.V(10).Infof("     Read (akPub) from request")

	tPub, err := tpm2.DecodePublic(akPubBytes)
	if err != nil {
		return []byte(""), []byte(""), fmt.Errorf("Error DecodePublic AK %v", tPub)
	}

	ap, err := tPub.Key()
	if err != nil {
		return []byte(""), []byte(""), fmt.Errorf("akPub.Key() failed: %s", err)
	}
	akBytes, err := x509.MarshalPKIXPublicKey(ap)
	if err != nil {
		return []byte(""), []byte(""), fmt.Errorf("Unable to convert akPub: %v", err)
	}

	akPubPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: akBytes,
		},
	)
	glog.V(10).Infof("     Decoded AkPub: \n%v", string(akPubPEM))

	if tPub.MatchesTemplate(defaultKeyParams) {
		glog.V(10).Infof("     AK Default parameter match template")
	} else {
		return []byte(""), []byte(""), fmt.Errorf("AK does not have correct defaultParameters")
	}
	h, keyName, err := tpm2.LoadExternal(rwc, tPub, tpm2.Private{}, tpm2.HandleNull)
	if err != nil {
		return []byte(""), []byte(""), fmt.Errorf("Error loadingExternal AK %v", err)
	}
	defer tpm2.FlushContext(rwc, h)
	glog.V(10).Infof("     Loaded AK KeyName %s", hex.EncodeToString(keyName))

	glog.V(5).Infof("     MakeCredential Start")
	credential := []byte(sec)
	credBlob, encryptedSecret0, err := tpm2.MakeCredential(rwc, ekh, credential, keyName)
	if err != nil {
		glog.Errorf("ERROR in Make Credential %v", err)
		return []byte(""), []byte(""), fmt.Errorf("MakeCredential failed: %v", err)
	}
	glog.V(10).Infof("     credBlob %s", hex.EncodeToString(credBlob))
	glog.V(10).Infof("     encryptedSecret0 %s", hex.EncodeToString(encryptedSecret0))
	glog.V(2).Infof("     <-- End makeCredential()")
	return credBlob, encryptedSecret0, nil
}
