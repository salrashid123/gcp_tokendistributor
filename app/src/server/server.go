package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"net/url"

	"net"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"tokenservice"

	"github.com/golang/glog"

	"os"
	pb "tokenservice"

	"cloud.google.com/go/firestore"
	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	"github.com/lestrrat/go-jwx/jwk"
	"google.golang.org/api/compute/v1"
	secretmanagerpb "google.golang.org/genproto/googleapis/cloud/secretmanager/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
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
	Description        string       `firestore:"description,omitempty"`
	Done               bool         `firestore:"done"`
	InstanceID         string       `firestore:"instanceid"`
	ClientProject      string       `firestore:"client_project"`
	ClientZone         string       `firestore:"client_zone"`
	ServiceAccountName string       `firestore:"service_account_name"`
	InitScriptHash     string       `firestore:"init_script_hash"`
	ImageFingerprint   string       `firestore:"image_fingerprint"`
	GCSObjectReference string       `firestore:"gcs_object,omitempty"`
	Secrets            []*pb.Secret `firestore:"secrets,omitempty"`
	ProvidedAt         time.Time    `firestore:"provided_at"`
	PeerAddress        string       `firestore:"peer_address"`
	PeerSerialNumber   string       `firestore:"peer_serial_number"`
}

type contextKey string
type server struct{}
type verifierserver struct{}
type healthServer struct {
	mu        sync.Mutex
	statusMap map[string]healthpb.HealthCheckResponse_ServingStatus
}

const (
	jwksURL = "https://www.googleapis.com/oauth2/v3/certs"
)

var (
	grpcport     = flag.String("grpcport", ":50051", "grpcport")
	tlsCert      = flag.String("tlsCert", "tokenservice.crt", "TLS Certificate")
	tlsKey       = flag.String("tlsKey", "tokenservice.key", "TLS Key")
	tlsCertChain = flag.String("tlsCertChain", "tls-ca-chain.pem", "TLS CA Chain")
	tsAudience   = flag.String("tsAudience", "", "Audience value for the TokenService")
	useSecrets   = flag.Bool("useSecrets", false, "Use Google Secrets Manager for TLS Keys")
	useMTLS      = flag.Bool("useMTLS", false, "Use mTLS")

	validatePeerIP          = flag.Bool("validatePeerIP", false, "Validate each TokenClients origin IP")
	validatePeerSN          = flag.Bool("validatePeerSN", false, "Validate each TokenClients Certificate Serial Number")
	firestoreProjectId      = flag.String("firestoreProjectId", "", "firestoreProjectId where the sealed data is stored")
	firestoreCollectionName = flag.String("firestoreCollectionName", "", "firestoreCollectionName where the sealedData is Stored")
	jwtIssuedAtJitter       = flag.Int("jwtIssuedAtJitter", 4, "Validate the IssuedAt timestamp.  If issuedAt+jwtIssueAtJitter > now(), then reject")
	jwtSet                  *jwk.Set
	hs                      *health.Server
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
	// TODO: optionally use  claims.StandardClaims, issuedAt.  If issuedAt +  2seconds is passed,
	//       return an error even if expiresAt is valid.
	//       https://github.com/dgrijalva/jwt-go/blob/master/claims.go#L18
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

		issuedTime := time.Unix(doc.IssuedAt, 0)
		now := time.Now()
		if now.Sub(issuedTime).Seconds() > float64(*jwtIssuedAtJitter) {
			glog.Errorf("   IssuedAt Identity document timestamp too old")
			return nil, grpc.Errorf(codes.Unauthenticated, "IssuedAt Identity document timestamp too old")
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

	glog.V(2).Infof("     TLS Client cert Peer IP and SerialNumber")
	peer, ok := peer.FromContext(ctx)
	if ok {
		peerIPPort, _, err := net.SplitHostPort(peer.Addr.String())
		if err != nil {
			glog.Errorf("ERROR:  Could not Remote IP %s", instanceID)
			return &tokenservice.TokenResponse{}, grpc.Errorf(codes.NotFound, fmt.Sprintf("Could not Remote IP   %v", err))
		}
		if *validatePeerIP && (c.PeerAddress != peerIPPort) {
			glog.Errorf("ERROR:  Unregistered  Peer address: %s", peer.Addr.String())
			return &tokenservice.TokenResponse{}, grpc.Errorf(codes.NotFound, fmt.Sprintf("Unregistered  Peer address  %v", peer.Addr.String()))
		} else {
			glog.V(2).Infof("    Verified PeerIP %s\n", peer.Addr.String())
		}
		if *useMTLS {
			tlsInfo := peer.AuthInfo.(credentials.TLSInfo)
			v := tlsInfo.State.VerifiedChains[0][0].Subject.CommonName
			sn := tlsInfo.State.VerifiedChains[0][0].SerialNumber
			if *validatePeerSN && (sn.String() != c.PeerSerialNumber) {
				glog.Errorf("ERROR:  Unregistered  Client Certificate SN: %s", sn.String())
				return &tokenservice.TokenResponse{}, grpc.Errorf(codes.NotFound, fmt.Sprintf("Unregistered  Peer address  %v", sn.String()))
			}
			glog.V(2).Infof("     Client Peer Address [%v] - Subject[%v] - SerialNumber [%v] Validated\n", peer.Addr.String(), v, sn)
		}
	} else {
		glog.Errorf("ERROR:  Could not extract peerInfo from TLS")
		return &tokenservice.TokenResponse{}, grpc.Errorf(codes.NotFound, "ERROR:  Could not extract peerInfo from TLS")
	}

	glog.V(2).Infof("     Looking up InstanceID using GCE APIs for instanceID %s", instanceID)

	computeService, err := compute.NewService(ctx)
	if err != nil {
		glog.Errorf("ERROR:  Could not create Compute Engine API %v", err)
		return &tokenservice.TokenResponse{}, grpc.Errorf(codes.NotFound, fmt.Sprintf("Could not create ComputeClient %v", err))
	}

	cresp, err := computeService.Instances.Get(c.ClientProject, c.ClientZone, instanceID).Do()
	if err != nil {
		glog.Errorf("ERROR:  Could not find instanceID Using GCE API %s", instanceID)
		return &tokenservice.TokenResponse{}, grpc.Errorf(codes.NotFound, fmt.Sprintf("InstanceID not Found using GCE API %v", err))
	}
	//  For any of these parameters we just recalled using the GCE API, you can compare that to the values
	//  saved into Firestore.  For example, compare w/ PublicIP, Fingerprint VM Boot Disk we LGTMd at provisioning time
	//  with the live values here.
	glog.V(2).Infof("     Found  VM instanceID %#v\n", strconv.FormatUint(cresp.Id, 10))
	glog.V(2).Infof("     Found  VM CreationTimestamp %#v\n", cresp.CreationTimestamp)
	glog.V(2).Infof("     Found  VM Fingerprint %#v\n", cresp.Fingerprint)
	glog.V(2).Infof("     Found  VM CpuPlatform %#v\n", cresp.CpuPlatform)

	for _, sa := range cresp.ServiceAccounts {
		glog.V(2).Infof("     Found  VM ServiceAccount %#v\n", sa.Email)
	}

	for _, ni := range cresp.NetworkInterfaces {
		for _, ac := range ni.AccessConfigs {
			if ac.Type == "ONE_TO_ONE_NAT" {
				glog.V(2).Infof("     Found Registered External IP Address: %s", ac.NatIP)
				// optionally cross check with ac.NatIP,c.PeerAddress,peerIPPort  (they should all be the same if the tokenclient doesn't use a NAT gateway..)
				//  ac.NATIP:  this is the public ip of the tokenclient as viewed by the GCE API
				//  c.PeerAddress:  this is the public ip of the tokenclient that we provisioned
				//  peerIP:  this is the ip address as viewed by the socket connection
			}
		}
	}

	for _, d := range cresp.Disks {
		if d.Boot {
			glog.V(2).Infof("     Found  VM Boot Disk Source %#v\n", d.Source)
			u, err := url.Parse(d.Source)
			if err != nil {
				glog.Errorf("   -------->  ERROR:  Could not Parse Disk URL [%s] [%s]", d.Source, err)
				return &tokenservice.TokenResponse{}, grpc.Errorf(codes.NotFound, fmt.Sprintf("ERROR:  Could not find Disk URL [%s] [%s]", d.Source, err))
			}
			// yeah, i don't know of a better way to parse a GCP ResourceURL...
			// compute/v1/projects/mineral-minutia-820/zones/us-central1-a/disks/tpm-a
			vals := strings.Split(u.Path, "/")
			if len(vals) == 9 {
				dresp, err := computeService.Disks.Get(vals[4], vals[6], vals[8]).Do()
				if err != nil {
					glog.Errorf("   -------->  ERROR:  Could not find Disk [%s] [%s]", u.Path, err)
					return &tokenservice.TokenResponse{}, grpc.Errorf(codes.NotFound, fmt.Sprintf("ERROR:  Could not find Disk [%s] [%s]", u.Path, err))
				}
				glog.V(2).Infof("    Found Disk Image %s", dresp.SourceImage)
			}

		}
	}

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

	if cresp.Fingerprint != c.ImageFingerprint {
		glog.Errorf("   -------->  Error Image Fingerprint mismatch got [%s]  expected [%s]", cresp.Fingerprint, c.ImageFingerprint)
		return &tokenservice.TokenResponse{}, grpc.Errorf(codes.NotFound, fmt.Sprintf("Error:  ImageFingerpint does not match got [%s]  expected [%s]", cresp.Fingerprint, c.ImageFingerprint))
	}

	respID, err := uuid.NewUUID()
	if err != nil {
		return &tokenservice.TokenResponse{}, grpc.Errorf(codes.Internal, "Unable to create UUID")
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
		Secrets:      c.Secrets,
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

	if *useSecrets {
		glog.V(10).Infof("     Getting certs from Secrets Manager")

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

	if *useMTLS {
		glog.V(10).Infof("     Enable mTLS...")
		tlsConfig = tls.Config{
			ClientAuth:   tls.RequireAndVerifyClientCert,
			Certificates: []tls.Certificate{certificate},
			ClientCAs:    caCertPool,
		}
	} else {
		glog.V(10).Infof("     Enable TLS...")
		tlsConfig = tls.Config{
			Certificates: []tls.Certificate{certificate},
		}
	}

	ce := credentials.NewTLS(&tlsConfig)
	sopts = append(sopts, grpc.Creds(ce))

	sopts = append(sopts, grpc.UnaryInterceptor(authUnaryInterceptor))
	sopts = append(sopts)
	s := grpc.NewServer(sopts...)

	tokenservice.RegisterTokenServiceServer(s, &server{})

	healthpb.RegisterHealthServer(s, &healthServer{})

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
