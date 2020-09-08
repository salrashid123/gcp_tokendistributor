package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	pb "tokenservice"

	"sync"

	"flag"
	"io/ioutil"

	"time"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"github.com/golang/glog"
	"github.com/golang/protobuf/proto"
	tpmpb "github.com/google/go-tpm-tools/proto"
	"github.com/google/go-tpm-tools/tpm2tools"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/uuid"
	"golang.org/x/net/context"
	"google.golang.org/api/idtoken"
	secretmanagerpb "google.golang.org/genproto/googleapis/cloud/secretmanager/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/oauth"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
)

const (
	tpmDevice = "/dev/tpm0"
)

type grpcTokenSource struct {
	oauth.TokenSource
	// Additional metadata attached as headers.
	quotaProject  string
	requestReason string
}

var (
	address        = flag.String("address", "", "host:port of gRPC server")
	tsAudience     = flag.String("tsAudience", "https://tokenservice", "Audience for the token")
	tlsCertChain   = flag.String("tlsCertChain", "", "root CA Certificate for TLS")
	tlsClientCert  = flag.String("tlsClientCert", "", "ClientCertificate Cert for TLS")
	tlsClientKey   = flag.String("tlsClientKey", "", "ClientCertificate Key for TLS")
	useSecrets     = flag.Bool("useSecrets", false, "Use Google Secrets Manager for TLS Keys")
	sniServerName  = flag.String("servername", "tokenservice.esodemoapp2.com", "SNIServer Name assocaited with the server")
	serviceAccount = flag.String("serviceAccount", "/path/to/svc.json", "Path to the service account JSOn file")
	useMTLS        = flag.Bool("useMTLS", false, "Use mTLS")

	tokenServerServiceAccount = flag.String("tokenServerServiceAccount", "", "ServiceAccount for ALTS TokenService")
	maxLoop                   = flag.Int("maxLoop", 360, "Number of reattempts to contact the TokenServer")
	pollWaitSeconds           = flag.Int("pollWaitSeconds", 10, "Number of seconds delay bettween retries")

	isProvisioned = false

	pcr         = flag.Int("unsealPcr", 0, "pcr value to unseal against")
	handleNames = map[string][]tpm2.HandleType{
		"all":       []tpm2.HandleType{tpm2.HandleTypeLoadedSession, tpm2.HandleTypeSavedSession, tpm2.HandleTypeTransient},
		"loaded":    []tpm2.HandleType{tpm2.HandleTypeLoadedSession},
		"saved":     []tpm2.HandleType{tpm2.HandleTypeSavedSession},
		"transient": []tpm2.HandleType{tpm2.HandleTypeTransient},
	}
	rwc io.ReadWriteCloser
)

func main() {

	flag.Parse()
	var wg sync.WaitGroup

	var tlsConfig tls.Config
	var ce credentials.TransportCredentials

	rootCAs := x509.NewCertPool()
	var clientCerts tls.Certificate

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
		pem := tlsCACert_result.Payload.Data
		if !rootCAs.AppendCertsFromPEM(pem) {
			glog.Fatalf("ERROR no root CA certs parsed from file ")
		}

		if *useMTLS {
			glog.V(10).Infof("     Loading mTLS certs from Secrets")
			tlsCert_name := fmt.Sprintf("%s/versions/latest", *tlsClientCert)
			tlsCert_req := &secretmanagerpb.AccessSecretVersionRequest{
				Name: tlsCert_name,
			}

			tlsCert_result, err := client.AccessSecretVersion(ctx, tlsCert_req)
			if err != nil {
				glog.Fatalf("Error: failed to access tlsCert secret version: %v", err)
			}
			certPem := tlsCert_result.Payload.Data

			tlsKey_name := fmt.Sprintf("%s/versions/latest", *tlsClientKey)
			tlsKey_req := &secretmanagerpb.AccessSecretVersionRequest{
				Name: tlsKey_name,
			}

			tlsKey_result, err := client.AccessSecretVersion(ctx, tlsKey_req)
			if err != nil {
				glog.Fatalf("Error: failed to access tlsKey secret version: %v", err)
			}
			keyPem := tlsKey_result.Payload.Data

			clientCerts, err = tls.X509KeyPair(certPem, keyPem)
			if err != nil {
				glog.Fatalf("Error: could not load TLS Certificate chain: %s", err)
			}
		}

	} else {
		var err error

		if *useMTLS {
			glog.V(10).Infof("     Loading mTLS certs from File")
			clientCerts, err = tls.LoadX509KeyPair(
				*tlsClientCert,
				*tlsClientKey,
			)
		}
		pem, err := ioutil.ReadFile(*tlsCertChain)
		if err != nil {
			glog.Fatalf("ERROR failed to load root CA certificates  error=%v", err)
		}
		if !rootCAs.AppendCertsFromPEM(pem) {
			glog.Fatalf("ERROR no root CA certs parsed from file ")
		}
	}

	if *useMTLS {
		glog.V(10).Infof("     Enabling mTLS")
		tlsConfig = tls.Config{
			ServerName:   *sniServerName,
			ClientAuth:   tls.RequireAndVerifyClientCert,
			Certificates: []tls.Certificate{clientCerts},
			RootCAs:      rootCAs,
		}
	} else {
		glog.V(10).Infof("     Enabling TLS")
		tlsConfig = tls.Config{
			ServerName: *sniServerName,
			RootCAs:    rootCAs,
		}
	}
	ce = credentials.NewTLS(&tlsConfig)

	ctx := context.Background()

	attempt := 0
	for attempt < *maxLoop && !isProvisioned {
		attempt++
		glog.V(2).Infof("Attempting to contact TokenServer [%d]", attempt)
		if !isProvisioned {
			go func() {
				// tok, err := idTokenSource.Token()
				// if err != nil {
				// 	log.Fatal(err)
				// }
				// glog.V(2).Infof("IdToken %s", tok)

				//idTokenSource, err := idtoken.NewTokenSource(ctx, *tsAudience, idtoken.WithCredentialsFile(*serviceAccount))
				idTokenSource, err := idtoken.NewTokenSource(ctx, *tsAudience)
				if err != nil {
					glog.Errorf("ERROR: Unable to create TokenSource: %v\n", err)
					return
				}

				var conn *grpc.ClientConn
				conn, err = grpc.Dial(*address,
					grpc.WithTransportCredentials(ce),
					grpc.WithPerRPCCredentials(grpcTokenSource{
						TokenSource: oauth.TokenSource{
							idTokenSource,
						},
					}),
				)
				if err != nil {
					glog.Errorf("ERROR:   Could not connect to TokenServer: %v", err)
					return
				}

				defer conn.Close()

				c := pb.NewTokenServiceClient(conn)

				var customMetadata = metadata.MD{
					"key": []string{"value"},
				}

				ctx = metadata.NewOutgoingContext(context.Background(), customMetadata)

				var header, trailer metadata.MD

				var p peer.Peer

				reqID, err := uuid.NewUUID()
				if err != nil {
					glog.Errorf("Error creating UUID: %v", err)
					return
				}

				tr := &pb.TokenRequest{
					RequestId: reqID.String(),
					ProcessID: reqID.URN(),
				}

				r, err := c.GetToken(ctx, tr, grpc.Header(&header), grpc.Trailer(&trailer), grpc.Peer(&p))
				if err != nil {
					glog.Errorf("Error:   GetToken() from TokenService: %v", err)
					return
				}

				glog.V(20).Infof("     Received  toResponse: %s\n", r.InResponseTo)

				for _, ss := range r.GetSecrets() {
					glog.V(20).Infof("     Received  Data: %s\n", ss)
					switch ss.Type {
					case pb.Secret_RAW:
						glog.V(20).Infof("     Decoding as RAW %s", string(ss.Data))
					case pb.Secret_TPM:
						glog.V(20).Infof("     Decoding with TPM")
						decdata, err := decodeWithTPM(ss.Data)
						if err != nil {
							glog.Errorf("Error:   GetToken() Could not decode TPM based secret: %v", err)
							return
						}
						glog.V(20).Infof("     Decoded data %s", decdata)
					case pb.Secret_TINK:
						glog.V(20).Infof("     Decoding as TINK %s", string(ss.Data))
						//TODO: Decode as TINK
					default:
						glog.Errorf("Error:   GetToken() Unknown Secret Type secret: %v", ss.Type)
						return
					}

				}

				isProvisioned = true
			}()
			glog.V(5).Infof("     Sleeping..")
			time.Sleep(10 * time.Second)
		}
	}

	if !isProvisioned {
		glog.Fatalf("Maximum retries exceeded; exiting\n")
		return
	}

	glog.V(5).Infof("     >>>>>>>>>>>>>>> System Provisioned <<<<<<<<<<<<<<")
	wg.Add(1)
	go worker(1, &wg)
	wg.Wait()
}

func worker(id int, wg *sync.WaitGroup) {
	defer wg.Done()
	glog.V(2).Infof("     Worker %d starting\n", id)
	// just sleep for an hour
	// we already have the remote secrets from TokenServer in memory, do something with it here
	time.Sleep(3600 * time.Second)
	fmt.Printf("     Worker %d done\n", id)
}

func decodeWithTPM(sealedBlob []byte) (b []byte, err error) {
	rwc, err = tpm2.OpenTPM(tpmDevice)
	if err != nil {
		glog.Errorf("ERROR Unable to openTPM: %v", err)
		return []byte(""), err
	}
	defer func() {
		if err := rwc.Close(); err != nil {
			glog.Errorf("ERROR Can't close TPM %v", err)
		}
	}()

	totalHandles := 0
	for _, handleType := range handleNames["all"] {
		handles, err := tpm2tools.Handles(rwc, handleType)
		if err != nil {
			glog.V(20).Infof("Getting TPM handles: %v", err)
			return []byte(""), err
		}
		for _, handle := range handles {
			if err = tpm2.FlushContext(rwc, handle); err != nil {
				glog.Errorf("flushing handle 0x%x: %v", handle, err)
			}
			glog.V(20).Infof("Handle 0x%x flushed\n", handle)
			totalHandles++
		}
	}
	ek, err := tpm2tools.EndorsementKeyRSA(rwc)
	defer ek.Close()
	if err != nil {
		glog.Errorf("ERROR:   Unable to load EK from TPM: %v\n", err)
		return []byte(""), err
	}
	defer tpm2.FlushContext(rwc, ek.Handle())

	blob := &tpmpb.ImportBlob{}

	err = proto.Unmarshal(sealedBlob, blob)
	if err != nil {
		glog.Errorf("Unmarshalling error: %v\n", err)
		return []byte(""), err
	}
	akey, err := ek.Import(blob)
	if err != nil {
		glog.Errorf("ERROR Unable to Import sealed AES data: %v\n", err)
		return []byte(""), err
	}
	return akey, nil
}
