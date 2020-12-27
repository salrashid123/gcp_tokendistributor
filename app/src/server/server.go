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
	"math/rand"
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
	"github.com/google/go-tpm/tpm2"
	"github.com/google/uuid"
	"github.com/lestrrat/go-jwx/jwk"
	"google.golang.org/api/compute/v1"
	secretmanagerpb "google.golang.org/genproto/googleapis/cloud/secretmanager/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/alts"
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
	PCR                int64        `firestore:"pcr"`
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
	tlsCertChain            = flag.String("tlsCertChain", "tls-ca.crt", "TLS CA Chain")
	tsAudience              = flag.String("tsAudience", "", "Audience value for the TokenService")
	useSecrets              = flag.Bool("useSecrets", false, "Use Google Secrets Manager for TLS Keys")
	useMTLS                 = flag.Bool("useMTLS", false, "Use mTLS")
	useALTS                 = flag.Bool("useALTS", false, "Use Application Layer Transport Security")
	validatePeerIP          = flag.Bool("validatePeerIP", false, "Validate each TokenClients origin IP")
	validatePeerSN          = flag.Bool("validatePeerSN", false, "Validate each TokenClients Certificate Serial Number")
	firestoreProjectId      = flag.String("firestoreProjectId", "", "firestoreProjectId where the sealed data is stored")
	firestoreCollectionName = flag.String("firestoreCollectionName", "", "firestoreCollectionName where the sealedData is Stored")
	jwtIssuedAtJitter       = flag.Int("jwtIssuedAtJitter", 1, "Validate the IssuedAt timestamp.  If issuedAt+jwtIssueAtJitter > now(), then reject")
	jwtSet                  *jwk.Set
	hs                      *health.Server

	rwc              io.ReadWriteCloser
	useTPM           = flag.Bool("useTPM", false, "Enable TPM operations")
	pcr              = flag.Int("pcr", 0, "PCR Value to use for attestation")
	registry         = make(map[string]tokenservice.MakeCredentialRequest)
	nonces           = make(map[string]string)
	expectedPCRValue = flag.String("expectedPCRValue", "fcecb56acc303862b30eb342c4990beb50b5e0ab89722449c2d9a73f37b019fe", "ExpectedPCRValue from Quote/Verify")
	handleNames      = map[string][]tpm2.HandleType{
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
	// TODO: check if the service is running or not...no reason they shoudn't be
	s.statusMap["tokenservice.TokenServiceServer"] = healthpb.HealthCheckResponse_SERVING
	s.statusMap["tokenservice.VerifierServer"] = healthpb.HealthCheckResponse_SERVING
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

		instanceID := doc.Google.ComputeEngine.InstanceID
		glog.V(10).Infof("     Looking up Firestore Collection %s for instanceID %s", *firestoreCollectionName, instanceID)

		fsclient, err := firestore.NewClient(ctx, *firestoreProjectId)
		if err != nil {
			glog.Errorf("ERROR:  Could not create new Firestore Client %v", err)
			return nil, grpc.Errorf(codes.PermissionDenied, "Unable to create Firestore Client")
		}
		dsnap, err := fsclient.Collection(*firestoreCollectionName).Doc(instanceID).Get(ctx)
		if err != nil {
			glog.Errorf("ERROR:  Could not find instanceID new Firestore Client %s", instanceID)
			return nil, grpc.Errorf(codes.PermissionDenied, fmt.Sprintf("InstanceID not Found  %v", err))
		}

		var c ServiceEntry
		err = dsnap.DataTo(&c)
		if err != nil {
			glog.Errorf("ERROR:  Could not find convert ServiceEntry for %s", instanceID)
			return nil, grpc.Errorf(codes.PermissionDenied, fmt.Sprintf("Could not find convert ServiceEntry  %v", err))
		}

		glog.V(20).Infof("     TLS Peer IP Check")
		peer, ok := peer.FromContext(ctx)
		if ok {
			peerIPPort, _, err := net.SplitHostPort(peer.Addr.String())
			if err != nil {
				glog.Errorf("ERROR:  Could not Remote IP %s", instanceID)
				return nil, grpc.Errorf(codes.PermissionDenied, fmt.Sprintf("Could not Remote IP   %v", err))
			}
			if *validatePeerIP && (c.PeerAddress != peerIPPort) {
				glog.Errorf("ERROR:  Unregistered  Peer address: %s", peer.Addr.String())
				return nil, grpc.Errorf(codes.PermissionDenied, fmt.Sprintf("Unregistered  Peer address  %v", peer.Addr.String()))
			} else {
				glog.V(20).Infof("    Verified PeerIP %s\n", peer.Addr.String())
			}
			if *useALTS {
				glog.V(20).Infof("     Using ALTS ServiceAccount Check")
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
			} else if *useMTLS {
				glog.V(20).Infof("     Using mTLS Client cert Peer IP and SerialNumber")
				tlsInfo := peer.AuthInfo.(credentials.TLSInfo)
				v := tlsInfo.State.VerifiedChains[0][0].Subject.CommonName
				sn := tlsInfo.State.VerifiedChains[0][0].SerialNumber
				if *validatePeerSN && (sn.String() != c.PeerSerialNumber) {
					glog.Errorf("ERROR:  Unregistered  Client Certificate SN: %s", sn.String())
					return nil, grpc.Errorf(codes.PermissionDenied, fmt.Sprintf("Unregistered  Peer address  %v", sn.String()))
				}
				glog.V(20).Infof("     Client Peer Address [%v] - Subject[%v] - SerialNumber [%v] Validated\n", peer.Addr.String(), v, sn)
			}
		} else {
			glog.Errorf("ERROR:  Could not extract peerInfo from TLS")
			return nil, grpc.Errorf(codes.PermissionDenied, "ERROR:  Could not extract peerInfo from TLS")
		}

		glog.V(2).Infof("     Looking up InstanceID using GCE APIs for instanceID %s", instanceID)

		computeService, err := compute.NewService(ctx)
		if err != nil {
			glog.Errorf("ERROR:  Could not create Compute Engine API %v", err)
			return nil, grpc.Errorf(codes.PermissionDenied, fmt.Sprintf("Could not create ComputeClient %v", err))
		}

		cresp, err := computeService.Instances.Get(c.ClientProject, c.ClientZone, instanceID).Do()
		if err != nil {
			glog.Errorf("ERROR:  Could not find instanceID Using GCE API %s", instanceID)
			return nil, grpc.Errorf(codes.PermissionDenied, fmt.Sprintf("InstanceID not Found using GCE API %v", err))
		}
		//  For any of these parameters we just recalled using the GCE API, you can compare that to the values
		//  saved into Firestore.  For example, compare w/ PublicIP, Fingerprint VM Boot Disk we LGTMd at provisioning time
		//  with the live values here.
		glog.V(20).Infof("     Found  VM instanceID %#v\n", strconv.FormatUint(cresp.Id, 10))
		glog.V(20).Infof("     Found  VM CreationTimestamp %#v\n", cresp.CreationTimestamp)
		glog.V(20).Infof("     Found  VM Fingerprint %#v\n", cresp.Fingerprint)
		glog.V(20).Infof("     Found  VM CpuPlatform %#v\n", cresp.CpuPlatform)

		for _, sa := range cresp.ServiceAccounts {
			glog.V(20).Infof("     Found  VM ServiceAccount %#v\n", sa.Email)
		}

		for _, ni := range cresp.NetworkInterfaces {
			for _, ac := range ni.AccessConfigs {
				if ac.Type == "ONE_TO_ONE_NAT" {
					glog.V(20).Infof("     Found Registered External IP Address: %s", ac.NatIP)
					// optionally cross check with ac.NatIP,c.PeerAddress,peerIPPort  (they should all be the same if the tokenclient doesn't use a NAT gateway..)
					//  ac.NATIP:  this is the public ip of the tokenclient as viewed by the GCE API
					//  c.PeerAddress:  this is the public ip of the tokenclient that we provisioned
					//  peerIP:  this is the ip address as viewed by the socket connection
				}
			}
		}

		for _, d := range cresp.Disks {
			if d.Boot {
				glog.V(20).Infof("     Found  VM Boot Disk Source %#v\n", d.Source)
				u, err := url.Parse(d.Source)
				if err != nil {
					glog.Errorf("   -------->  ERROR:  Could not Parse Disk URL [%s] [%s]", d.Source, err)
					return nil, grpc.Errorf(codes.PermissionDenied, fmt.Sprintf("ERROR:  Could not find Disk URL [%s] [%s]", d.Source, err))
				}
				// yeah, i don't know of a better way to parse a GCP ResourceURL...
				// compute/v1/projects/mineral-minutia-820/zones/us-central1-a/disks/tpm-a
				vals := strings.Split(u.Path, "/")
				if len(vals) == 9 {
					dresp, err := computeService.Disks.Get(vals[4], vals[6], vals[8]).Do()
					if err != nil {
						glog.Errorf("   -------->  ERROR:  Could not find Disk [%s] [%s]", u.Path, err)
						return nil, grpc.Errorf(codes.PermissionDenied, fmt.Sprintf("ERROR:  Could not find Disk [%s] [%s]", u.Path, err))
					}
					glog.V(20).Infof("    Found Disk Image %s", dresp.SourceImage)
				}

			}
		}

		var initScriptHash string
		for _, m := range cresp.Metadata.Items {
			if m.Key == "user-data" {
				hasher := sha256.New()
				hasher.Write([]byte(*m.Value))
				initScriptHash = base64.StdEncoding.EncodeToString(hasher.Sum(nil))
				glog.V(20).Infof("     Derived Image Hash from metadata %s", initScriptHash)
			}
		}

		if initScriptHash != c.InitScriptHash {
			glog.Errorf("   -------->  Error Init Script does not match got [%s]  expected [%s]", initScriptHash, c.InitScriptHash)
			return nil, grpc.Errorf(codes.PermissionDenied, fmt.Sprintf("Error:  Init Script does not match got [%s]  expected [%s]", initScriptHash, c.InitScriptHash))
		}

		if c.InitScriptHash == "" {
			glog.Errorf("   *********** NOTE: initscript is empty (non-COS VM or never set)...")
			// optionally just continue here if debugging
			return nil, grpc.Errorf(codes.PermissionDenied, fmt.Sprintf("Error:  Init Script is empty"))
		}

		if cresp.Fingerprint != c.ImageFingerprint {
			glog.Errorf("   -------->  Error Image Fingerprint mismatch got [%s]  expected [%s]", cresp.Fingerprint, c.ImageFingerprint)
			return nil, grpc.Errorf(codes.PermissionDenied, fmt.Sprintf("Error:  ImageFingerpint does not match got [%s]  expected [%s]", cresp.Fingerprint, c.ImageFingerprint))
		}

		newCtx := context.WithValue(ctx, contextKey("idtoken"), doc)
		newCtx = context.WithValue(newCtx, contextKey("serivceEntry"), c)
		newCtx = context.WithValue(newCtx, contextKey("subject"), doc.Subject)
		newCtx = context.WithValue(newCtx, contextKey("email"), doc.Email)
		newCtx = context.WithValue(newCtx, contextKey("instanceID"), doc.Google.ComputeEngine.InstanceID)
		return handler(newCtx, req)
	}
	return nil, grpc.Errorf(codes.Unauthenticated, "Authorization header not provided")
}

func (s *server) GetToken(ctx context.Context, in *tokenservice.TokenRequest) (*tokenservice.TokenResponse, error) {

	glog.V(10).Infof("======= GetToken ---> %s", in.RequestId)
	subject := ctx.Value(contextKey("subject")).(string)
	email := ctx.Value(contextKey("email")).(string)
	instanceID := ctx.Value(contextKey("instanceID")).(string)
	c := ctx.Value(contextKey("serivceEntry")).(ServiceEntry)

	glog.V(2).Infof("     Got rpc: RequestID %s for subject %s and email %s for instanceID %s\n", in.RequestId, subject, email, instanceID)

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
	glog.V(10).Infof("<<<--- GetToken ======= %s", in.RequestId)
	return &tokenservice.TokenResponse{
		ResponseID:   respID.String(),
		InResponseTo: in.RequestId,
		Secrets:      c.Secrets,
		Pcr:          &c.PCR,
	}, nil
}

func (s *verifierserver) MakeCredential(ctx context.Context, in *tokenservice.MakeCredentialRequest) (*tokenservice.MakeCredentialResponse, error) {

	glog.V(10).Infof("======= MakeCredential ======== %s", in.RequestId)
	glog.V(10).Infof("     Got AKName %s", in.AkName)
	glog.V(10).Infof("     Registry size %d\n", len(registry))

	idToken := ctx.Value(contextKey("idtoken")).(gcpIdentityDoc)
	glog.V(10).Infof("     From InstanceID %s", idToken.Google.ComputeEngine.InstanceID)

	if *useTPM == false {
		glog.V(2).Infof("     TPM Usage not enabled, exiting ")
		return &tokenservice.MakeCredentialResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("TPM Not Supported"))
	}
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

	glog.V(10).Infof("     Acquired PublicKey from GCP API: \n%s", r.EncryptionKey.EkPub)

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

	glog.V(10).Infof("     Verified EkPub from GCE API matches ekPub from Client")

	registry[idToken.Google.ComputeEngine.InstanceID] = *in

	var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	b := make([]rune, 10)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}

	nonces[idToken.Google.ComputeEngine.InstanceID] = string(b)

	credBlob, encryptedSecret, err := makeCredential(nonces[idToken.Google.ComputeEngine.InstanceID], in.EkPub, in.AkPub)
	if err != nil {
		return &tokenservice.MakeCredentialResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Unable to makeCredential"))
	}
	glog.V(10).Infof("     Returning MakeCredentialResponse ======== %s", in.RequestId)
	respID, err := uuid.NewUUID()
	if err != nil {
		return &tokenservice.MakeCredentialResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Unable to Create UUID"))
	}
	return &tokenservice.MakeCredentialResponse{
		ResponseID:      respID.String(),
		InResponseTo:    in.RequestId,
		CredBlob:        credBlob,
		EncryptedSecret: encryptedSecret,
		Pcr:             int32(*pcr),
	}, nil
}

func (s *verifierserver) ActivateCredential(ctx context.Context, in *tokenservice.ActivateCredentialRequest) (*tokenservice.ActivateCredentialResponse, error) {

	glog.V(10).Infof("======= ActivateCredential ======== %s", in.RequestId)
	glog.V(10).Infof("     Secret %s", in.Secret)

	idToken := ctx.Value(contextKey("idtoken")).(gcpIdentityDoc)
	glog.V(5).Infof("     From InstanceID %s", idToken.Google.ComputeEngine.InstanceID)

	if *useTPM == false {
		glog.V(2).Infof("     TPM Usage not enabled, exiting ")
		return &tokenservice.ActivateCredentialResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("TPM Not Supported"))
	}
	verified := false
	var id string
	id = idToken.Google.ComputeEngine.InstanceID

	if nonces[id] != in.Secret {
		glog.Errorf("     ActivateCredential failed:  provided Secret does not match expected Nonce")
		return &tokenservice.ActivateCredentialResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("ActivateCredential failed:  provided Secret does not match expected Nonce"))
	}

	err := verifyQuote(id, nonces[id], in.Attestation, in.Signature)
	if err != nil {
		glog.Errorf("     Quote Verification Failed Quote: %v", err)
		return &tokenservice.ActivateCredentialResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Quote Verification Failed Quote: %v", err))
	} else {
		glog.V(2).Infof("     Verified Quote")
		verified = true
		delete(nonces, in.RequestId)
	}

	glog.V(10).Infof("     Returning ActivateCredentialResponse ======== %s", in.RequestId)
	respID, err := uuid.NewUUID()
	if err != nil {
		return &tokenservice.ActivateCredentialResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Failed to create UUID: %v", err))
	}
	return &tokenservice.ActivateCredentialResponse{
		ResponseID:   respID.String(),
		InResponseTo: in.RequestId,
		Verified:     verified,
	}, nil
}

func (s *verifierserver) OfferQuote(ctx context.Context, in *tokenservice.OfferQuoteRequest) (*tokenservice.OfferQuoteResponse, error) {
	glog.V(10).Infof("======= OfferQuote ========  %s", in.RequestId)

	idToken := ctx.Value(contextKey("idtoken")).(gcpIdentityDoc)
	glog.V(10).Infof("     From InstanceID %s", idToken.Google.ComputeEngine.InstanceID)
	if *useTPM == false {
		glog.V(10).Infof("     TPM Usage not enabled, exiting ")
		return &tokenservice.OfferQuoteResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("TPM Not Supported"))
	}

	nonce := uuid.New().String()
	var id string

	id = idToken.Google.ComputeEngine.InstanceID

	glog.V(10).Infof("     Returning OfferQuoteResponse ======== %s", in.RequestId)
	nonces[id] = nonce
	respID, err := uuid.NewUUID()
	if err != nil {
		return &tokenservice.OfferQuoteResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Could not create UUID"))
	}
	return &tokenservice.OfferQuoteResponse{
		ResponseID:   respID.String(),
		InResponseTo: in.RequestId,
		Pcr:          int32(*pcr),
		Nonce:        nonce,
	}, nil
}

func (s *verifierserver) ProvideQuote(ctx context.Context, in *tokenservice.ProvideQuoteRequest) (*tokenservice.ProvideQuoteResponse, error) {
	glog.V(10).Infof("======= ProvideQuote ======== %s", in.RequestId)
	idToken := ctx.Value(contextKey("idtoken")).(gcpIdentityDoc)
	glog.V(10).Infof("     From InstanceID %s", idToken.Google.ComputeEngine.InstanceID)

	if *useTPM == false {
		glog.V(2).Infof("     TPM Usage not enabled, exiting ")
		return &tokenservice.ProvideQuoteResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("TPM Not Supported"))
	}
	ver := false
	var id string

	id = idToken.Google.ComputeEngine.InstanceID

	val, ok := nonces[id]
	if !ok {
		glog.V(10).Infof("Unable to find nonce request for uid")
	} else {
		delete(nonces, id)
		err := verifyQuote(id, val, in.Attestation, in.Signature)
		if err == nil {
			ver = true
		} else {
			return &tokenservice.ProvideQuoteResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Unable to Verify Quote %v", err))
		}
	}

	glog.V(10).Infof("     Returning ProvideQuoteResponse ======== %s", in.RequestId)
	respID, err := uuid.NewUUID()
	if err != nil {
		return &tokenservice.ProvideQuoteResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Could not create UUID"))
	}
	return &tokenservice.ProvideQuoteResponse{
		ResponseID:   respID.String(),
		InResponseTo: in.RequestId,
		Verified:     ver,
	}, nil
}

func (s *verifierserver) ProvideSigningKey(ctx context.Context, in *tokenservice.ProvideSigningKeyRequest) (*tokenservice.ProvideSigningKeyResponse, error) {
	glog.V(10).Infof("======= ProvideSigningKey ======== %s", in.RequestId)
	glog.V(10).Infof("     client provided uid: %s", in.RequestId)

	idToken := ctx.Value(contextKey("idtoken")).(gcpIdentityDoc)
	glog.V(10).Infof("     From InstanceID %s", idToken.Google.ComputeEngine.InstanceID)

	if *useTPM == false {
		glog.V(2).Infof("     TPM Usage not enabled, exiting ")
		return &tokenservice.ProvideSigningKeyResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("TPM Not Supported"))
	}

	glog.V(20).Infof("     SigningKey %s\n", in.Signingkey)
	glog.V(20).Infof("     SigningKey Attestation %s\n", base64.StdEncoding.EncodeToString(in.Attestation))
	glog.V(20).Infof("     SigningKey Signature %s\n", base64.StdEncoding.EncodeToString(in.Signature))

	if _, ok := registry[idToken.Google.ComputeEngine.InstanceID]; !ok {
		return &tokenservice.ProvideSigningKeyResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Could not find instanceID in registry %v"))
	}
	akPub := registry[idToken.Google.ComputeEngine.InstanceID].AkPubCert

	glog.V(20).Infof("     Read and Decode (attestion)")
	att, err := tpm2.DecodeAttestationData(in.Attestation)
	if err != nil {
		return &tokenservice.ProvideSigningKeyResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("DecodeAttestationData failed: %v", err))
	}
	glog.V(20).Infof("     Attestation att.AttestedCertifyInfo.QualifiedName: %s", hex.EncodeToString(att.AttestedCertifyInfo.QualifiedName.Digest.Value))

	sigL := tpm2.SignatureRSA{
		HashAlg:   tpm2.AlgSHA256,
		Signature: in.Signature,
	}

	// Verify signature of Attestation by using the PEM Public key for AK
	glog.V(10).Infof("     Decoding PublicKey for AK ======== %s", in.RequestId)

	block, _ := pem.Decode(akPub)
	if block == nil {
		return &tokenservice.ProvideSigningKeyResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Unable to decode akPubPEM %v", err))
	}

	r, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return &tokenservice.ProvideSigningKeyResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Unable to create rsa Key from PEM %v", err))
	}
	rsaPub := *r.(*rsa.PublicKey)

	hsh := crypto.SHA256.New()
	hsh.Write(in.Attestation)

	if err := rsa.VerifyPKCS1v15(&rsaPub, crypto.SHA256, hsh.Sum(nil), sigL.Signature); err != nil {
		return &tokenservice.ProvideSigningKeyResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("     VerifyPKCS1v15 failed: %v", err))
	}
	glog.V(20).Infof("     Attestation of Signing Key Verified")

	ablock, _ := pem.Decode(in.Signingkey)
	if ablock == nil {
		return &tokenservice.ProvideSigningKeyResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("     Unable to decode Signingkey"))
	}

	rra, err := x509.ParsePKIXPublicKey(ablock.Bytes)
	if err != nil {
		return &tokenservice.ProvideSigningKeyResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("     Unable to ParsePKIXPublicKey rsa Key from PEM %v", err))
	}
	arsaPub := *rra.(*rsa.PublicKey)

	params := tpm2.Public{
		Type:    tpm2.AlgRSA,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin |
			tpm2.FlagUserWithAuth | tpm2.FlagSign,
		AuthPolicy: []byte{},
		RSAParameters: &tpm2.RSAParams{
			Sign: &tpm2.SigScheme{
				Alg:  tpm2.AlgRSASSA,
				Hash: tpm2.AlgSHA256,
			},
			KeyBits:    2048,
			ModulusRaw: arsaPub.N.Bytes(),
		},
	}
	ok, err := att.AttestedCertifyInfo.Name.MatchesPublic(params)
	if err != nil {
		return &tokenservice.ProvideSigningKeyResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("     AttestedCertifyInfo.MatchesPublic(%v) failed: %v", att, err))
	}
	glog.V(20).Infof("     Attestation MatchesPublic %v", ok)

	ver := true

	glog.V(10).Infof("     Returning ProvideSigningKeyResponse ======== %s", in.RequestId)
	respID, err := uuid.NewUUID()
	if err != nil {
		return &tokenservice.ProvideSigningKeyResponse{}, grpc.Errorf(codes.FailedPrecondition, fmt.Sprintf("Could not create UUID"))
	}
	return &tokenservice.ProvideSigningKeyResponse{
		ResponseID:   respID.String(),
		InResponseTo: in.RequestId,
		Verified:     ver,
	}, nil
}

func verifyQuote(uid string, nonce string, attestation []byte, sigBytes []byte) (retErr error) {
	glog.V(20).Infof("     --> Starting verifyQuote()")

	if *useTPM == false {
		glog.Errorf("    TPM Usage not enabled, exiting")
		return fmt.Errorf("TPM Operation not supported")
	}

	if _, ok := registry[uid]; !ok {
		return fmt.Errorf("Could not find instanceID in registry %v")
	}
	akPub := registry[uid].AkPub

	glog.V(10).Infof("     Read and Decode (attestion)")
	att, err := tpm2.DecodeAttestationData(attestation)
	if err != nil {
		glog.Errorf("ERROR:  DecodeAttestationData(%v) failed: %v", attestation, err)
		return fmt.Errorf("DecodeAttestationData(%v) failed: %v", attestation, err)
	}

	glog.V(20).Infof("     Attestation ExtraData (nonce): %s ", string(att.ExtraData))
	glog.V(20).Infof("     Attestation PCR#: %v ", att.AttestedQuoteInfo.PCRSelection.PCRs)
	glog.V(20).Infof("     Attestation Hash: %v ", hex.EncodeToString(att.AttestedQuoteInfo.PCRDigest))

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

	glog.V(20).Infof("     Expected PCR Value:           --> %s", *expectedPCRValue)
	glog.V(20).Infof("     sha256 of Expected PCR Value: --> %x", hash)

	glog.V(20).Infof("     Decoding PublicKey for AK ========")
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

	var pcrMatch bool
	pcrMatch = false
	for _, a := range att.AttestedQuoteInfo.PCRSelection.PCRs {
		if a == *pcr {
			pcrMatch = true
			break
		}
	}
	if !pcrMatch {
		return fmt.Errorf("Unexpected PCR bank returned in AttestedQuoteInfo expected: %d  Got %v", *pcr, att.AttestedQuoteInfo.PCRSelection.PCRs)
	}

	if fmt.Sprintf("%x", hash) != hex.EncodeToString(att.AttestedQuoteInfo.PCRDigest) {
		return fmt.Errorf("Unexpected PCR hash Value expected: %s  Got %s", fmt.Sprintf("%x", hash), hex.EncodeToString(att.AttestedQuoteInfo.PCRDigest))
	}

	if nonce != string(att.ExtraData) {
		return fmt.Errorf("Unexpected secret Value expected: %v  Got %v", nonce, string(att.ExtraData))
	}
	glog.V(20).Infof("     Attestation Signature Verified ")
	glog.V(20).Infof("     <-- End verifyQuote()")
	return nil
}

func makeCredential(sec string, ekPubBytes []byte, akPubBytes []byte) (credBlob []byte, encryptedSecret []byte, retErr error) {

	glog.V(20).Infof("     --> Starting makeCredential()")
	glog.V(20).Infof("     Read (ekPub) from request")

	if *useTPM == false {
		glog.Errorf("    TPM Usage not enabled, exiting")
		return []byte(""), []byte(""), fmt.Errorf("TPM Operation not supported")
	}

	ekPub, err := tpm2.DecodePublic(ekPubBytes)
	if err != nil {
		return []byte(""), []byte(""), fmt.Errorf("Error DecodePublic AK %v", err)
	}

	ekh, keyName, err := tpm2.LoadExternal(rwc, ekPub, tpm2.Private{}, tpm2.HandleNull)
	if err != nil {
		return []byte(""), []byte(""), fmt.Errorf("Error loadingExternal EK %v", err)
	}
	defer tpm2.FlushContext(rwc, ekh)

	glog.V(20).Infof("     Read (akPub) from request")

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
	glog.V(20).Infof("     Decoded AkPub: \n%v", string(akPubPEM))

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
	glog.V(20).Infof("     Loaded AK KeyName %s", hex.EncodeToString(keyName))

	glog.V(20).Infof("     MakeCredential Start")
	credential := []byte(sec)
	credBlob, encryptedSecret0, err := tpm2.MakeCredential(rwc, ekh, credential, keyName)
	if err != nil {
		glog.Errorf("ERROR in Make Credential %v", err)
		return []byte(""), []byte(""), fmt.Errorf("MakeCredential failed: %v", err)
	}
	glog.V(20).Infof("     credBlob %s", hex.EncodeToString(credBlob))
	glog.V(20).Infof("     encryptedSecret0 %s", hex.EncodeToString(encryptedSecret0))
	glog.V(20).Infof("     <-- End makeCredential()")
	return credBlob, encryptedSecret0, nil
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
	var ce credentials.TransportCredentials
	var err error

	jwtSet, err = jwk.FetchHTTP(jwksURL)
	if err != nil {
		glog.Fatalf("Unable to load JWK Set: ", err)
	}

	lis, err := net.Listen("tcp", *grpcport)
	if err != nil {
		glog.Fatalf("failed to listen: %v", err)
	}

	if *useALTS && *useMTLS {
		glog.Fatal("must specify either --useALTS or --useMTLS")
	}

	sopts := []grpc.ServerOption{grpc.MaxConcurrentStreams(10)}

	caCertPool = x509.NewCertPool()

	var tlsConfig tls.Config

	if *useALTS {
		glog.V(10).Infof("     Enable ALTS...")

		ce = alts.NewServerCreds(alts.DefaultServerOptions())

	} else {

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
			caCertPool.AppendCertsFromPEM(caCert)

			if *useMTLS {
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

			}

		} else {
			glog.V(10).Infof("     Getting mTLS certs from files")

			caCert, err = ioutil.ReadFile(*tlsCertChain)
			if err != nil {
				glog.Fatalf("could not load TLS Certificate chain: %s", err)
			}
			caCertPool.AppendCertsFromPEM(caCert)

			certificate, err = tls.LoadX509KeyPair(*tlsCert, *tlsKey)
			if err != nil {
				glog.Fatalf("could not load server key pair: %s", err)
			}

		}

		if *useMTLS {
			glog.V(10).Infof("     Enable mTLS...")

			tlsConfig = tls.Config{
				ClientAuth:   tls.RequireAndVerifyClientCert,
				Certificates: []tls.Certificate{certificate},
				ClientCAs:    caCertPool,
			}
			ce = credentials.NewTLS(&tlsConfig)

		} else {
			glog.V(10).Infof("     Enable TLS...")
			tlsConfig = tls.Config{
				Certificates: []tls.Certificate{certificate},
			}
			ce = credentials.NewTLS(&tlsConfig)
		}
	}
	sopts = append(sopts, grpc.Creds(ce))

	if *useTPM {
		rwc, err = tpm2.OpenTPM(tpmDevice)
		if err != nil {
			glog.Errorf("ERROR Unable to openTPM: %v", err)
			return
		}
		defer func() {
			if err := rwc.Close(); err != nil {
				glog.Errorf("ERROR Can't close TPM %v", err)
			}
		}()
	}

	sopts = append(sopts, grpc.UnaryInterceptor(authUnaryInterceptor))
	sopts = append(sopts)
	s := grpc.NewServer(sopts...)

	tokenservice.RegisterTokenServiceServer(s, &server{})
	tokenservice.RegisterVerifierServer(s, &verifierserver{})

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
	flag.VisitAll(func(f *flag.Flag) {
		fmt.Printf("     Startup args:  %s:  %v\n", f.Name, f.Value)
	})
	glog.V(2).Infof("Starting TokenService..")
	s.Serve(lis)
}
