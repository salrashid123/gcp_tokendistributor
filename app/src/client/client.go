package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
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
	"google.golang.org/grpc/credentials/alts"
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
	address                   = flag.String("address", "tokenservice.esodemoapp2.com:50051", "host:port of gRPC server")
	tsAudience                = flag.String("tsAudience", "https://tokenservice", "Audience for the token")
	tlsCertChain              = flag.String("tlsCertChain", "", "root CA Certificate for TLS")
	tlsClientCert             = flag.String("tlsClientCert", "", "ClientCertificate Cert for TLS")
	tlsClientKey              = flag.String("tlsClientKey", "", "ClientCertificate Key for TLS")
	useSecrets                = flag.Bool("useSecrets", false, "Use Google Secrets Manager for TLS Keys")
	sniServerName             = flag.String("servername", "tokenservice.esodemoapp2.com", "SNIServer Name assocaited with the server")
	serviceAccount            = flag.String("serviceAccount", "/home/srashid/gcp_misc/certs/mineral-minutia-820-e9a7c8665867.json", "Path to the service account JSOn file")
	useALTS                   = flag.Bool("useALTS", false, "Use ALTS")
	useTPM                    = flag.Bool("useTPM", false, "Use TPM to unseal data")
	doAttestation             = flag.Bool("doAttestation", false, "Start offer to Make/Activate Credential flow")
	exchangeSigningKey        = flag.Bool("exchangeSigningKey", false, "Offer RSA Signing Key (requires --doAttestation)")
	tokenServerServiceAccount = flag.String("tokenServerServiceAccount", "", "ServiceAccount for ALTS TokenService")
	maxLoop                   = flag.Int("maxLoop", 360, "Number of reattempts to contact the TokenServer")
	pollWaitSeconds           = flag.Int("pollWaitSeconds", 10, "Number of seconds delay bettween retries")
	pcr                       = flag.Int("unsealPcr", 0, "pcr value to unseal against")
	handleNames               = map[string][]tpm2.HandleType{
		"all":       []tpm2.HandleType{tpm2.HandleTypeLoadedSession, tpm2.HandleTypeSavedSession, tpm2.HandleTypeTransient},
		"loaded":    []tpm2.HandleType{tpm2.HandleTypeLoadedSession},
		"saved":     []tpm2.HandleType{tpm2.HandleTypeSavedSession},
		"transient": []tpm2.HandleType{tpm2.HandleTypeTransient},
	}
	rwc             io.ReadWriteCloser
	emptyPassword   = ""
	importedKeyFile = "/dev/shm/importedKey.bin"
	akPubFile       = "/dev/shm/akPub.bin"
	akPrivFile      = "/dev/shm/akPriv.bin"
	signPubFile     = "/dev/shm/signPub.bin"
	signPrivFile    = "/dev/shm/signPriv.bin"
	ekFile          = "/dev/shm/ek.bin"

	isProvisioned     = false
	defaultEKTemplate = tpm2.Public{
		Type:    tpm2.AlgRSA,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin |
			tpm2.FlagAdminWithPolicy | tpm2.FlagRestricted | tpm2.FlagDecrypt,
		AuthPolicy: []byte{
			0x83, 0x71, 0x97, 0x67, 0x44, 0x84,
			0xB3, 0xF8, 0x1A, 0x90, 0xCC, 0x8D,
			0x46, 0xA5, 0xD7, 0x24, 0xFD, 0x52,
			0xD7, 0x6E, 0x06, 0x52, 0x0B, 0x64,
			0xF2, 0xA1, 0xDA, 0x1B, 0x33, 0x14,
			0x69, 0xAA,
		},
		RSAParameters: &tpm2.RSAParams{
			Symmetric: &tpm2.SymScheme{
				Alg:     tpm2.AlgAES,
				KeyBits: 128,
				Mode:    tpm2.AlgCFB,
			},
			KeyBits:    2048,
			ModulusRaw: make([]byte, 256),
		},
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

	unrestrictedKeyParams = tpm2.Public{
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
			KeyBits: 2048,
		},
	}
)

func main() {

	flag.Parse()
	var wg sync.WaitGroup

	var tlsConfig tls.Config
	var ce credentials.TransportCredentials

	if *useALTS {
		glog.V(2).Infof("     Using ALTS")
		ce = alts.NewClientCreds(&alts.ClientOptions{
			TargetServiceAccounts: []string{*tokenServerServiceAccount},
		})
	} else {
		glog.V(2).Infof("     Using mTLS")
		rootCAs := x509.NewCertPool()
		var clientCerts tls.Certificate

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
			pem := tlsCACert_result.Payload.Data
			if !rootCAs.AppendCertsFromPEM(pem) {
				glog.Fatalf("ERROR no root CA certs parsed from file ")
			}

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

		} else {
			var err error
			clientCerts, err = tls.LoadX509KeyPair(
				*tlsClientCert,
				*tlsClientKey,
			)
			pem, err := ioutil.ReadFile(*tlsCertChain)
			if err != nil {
				glog.Fatalf("ERROR failed to load root CA certificates  error=%v", err)
			}
			if !rootCAs.AppendCertsFromPEM(pem) {
				glog.Fatalf("ERROR no root CA certs parsed from file ")
			}
		}
		tlsConfig = tls.Config{
			ServerName:   *sniServerName,
			ClientAuth:   tls.RequireAndVerifyClientCert,
			Certificates: []tls.Certificate{clientCerts},
			RootCAs:      rootCAs,
		}
		ce = credentials.NewTLS(&tlsConfig)
	}

	ctx := context.Background()

	//idTokenSource, err := idtoken.NewTokenSource(ctx, *tsAudience, idtoken.WithCredentialsFile(*serviceAccount))
	idTokenSource, err := idtoken.NewTokenSource(ctx, *tsAudience)
	if err != nil {
		glog.Errorf("ERROR: Unable to create TokenSource: %v\n", err)
		return
	}

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

				if *useALTS {
					ai, err := alts.AuthInfoFromPeer(&p)
					if err != nil {
						glog.Errorf("ERROR:  Unable to get client AuthInfoFromPeer = _, %v: \n", err)
						return
					} else {
						glog.V(2).Infof("     AuthInfo PeerServiceAccount: %v\n", ai.PeerServiceAccount())
						glog.V(2).Infof("     AuthInfo LocalServiceAccount: %v\n", ai.LocalServiceAccount())
						// TODO: compare tokenServerServiceAccount values here with the one in args
					}
				}

				glog.V(20).Infof("     Received  toResponse: %s\n", r.InResponseTo)

				//  Yes!!, we got the token back successfully.
				//  First decode the AES key using tpm2.Import() or..not if you don't use the TPM
				var akey []byte
				var sig string
				if *useTPM == true {
					rwc, err = tpm2.OpenTPM(tpmDevice)
					if err != nil {
						glog.Errorf("ERROR Unable to openTPM: %v", err)
						return
					}
					defer func() {
						if err := rwc.Close(); err != nil {
							glog.Fatalf("ERROR Can't close TPM %v", err)
						}
					}()

					totalHandles := 0
					for _, handleType := range handleNames["all"] {
						handles, err := tpm2tools.Handles(rwc, handleType)
						if err != nil {
							glog.V(20).Infof("Getting TPM handles: %v", err)
							return
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
						return
					}
					defer tpm2.FlushContext(rwc, ek.Handle())
					blob := &tpmpb.ImportBlob{}

					err = proto.Unmarshal(r.SealedAESKey, blob)
					if err != nil {
						glog.Errorf("Unmarshalling error: %v\n", err)
						return
					}
					akey, err = ek.Import(blob)
					if err != nil {
						glog.Errorf("ERROR Unable to Import sealed AES data: %v\n", err)
						return
					}
					err = proto.Unmarshal(r.SealedRSAKey, blob)
					if err != nil {
						glog.Errorf("unmarshaling error: %v\n ", err)
						return
					}
					rkey, err := ek.ImportSigningKey(blob)

					if err != nil {
						glog.Errorf("Error ImportSigningKey:  %v\n", err)
						return
					}
					defer tpm2.FlushContext(rwc, rkey.Handle())
					glog.V(2).Infof("     Unsealed RSA PrivateKey \n")

					// START: the following section simply saves and loads
					//  the RSA keyHandle just incase you need to save it to
					//  somewhere locally (only within memory, for example)
					//  "ContextSave returns an encrypted version of the session,
					//   object or sequence context for storage outside of the TPM"
					//  (for use in another routine)
					// https://godoc.org/github.com/google/go-tpm/tpm2#ContextSave
					glog.V(2).Infof("     Saving ImportedRSAKey Handle")
					keyHandle := rkey.Handle()
					keyBytes, err := tpm2.ContextSave(rwc, keyHandle)
					if err != nil {
						glog.Errorf("ContextSave failed for keyHandle: %v", err)
						return
					}
					tpm2.FlushContext(rwc, keyHandle)
					rkey.Close()

					glog.V(2).Infof("     Loading RSAKey Handle")
					kh, err := tpm2.ContextLoad(rwc, keyBytes)
					if err != nil {
						glog.Errorf("ContextLoad failed for kh: %v", err)
						return
					}
					// End Sample Save/Load

					// ok, now use key to sign some sample data
					// note, the string we're using to sign is "foobar"
					// which just happens to be the same string in line ~212
					// of provisioner.go.   This step doesn't really prove anything
					// other than the Alice can send that signature to
					// Bob and bob can see he got same signature for the same string
					data := []byte("foobar")
					h := sha256.New()
					h.Write(data)
					d := h.Sum(nil)

					defer tpm2.FlushContext(rwc, kh)

					khDigest, khValidation, err := tpm2.Hash(rwc, tpm2.AlgSHA256, data, tpm2.HandleOwner)
					if err != nil {
						glog.Errorf("Hash failed unexpectedly: %v", err)
						return
					}

					glog.V(5).Infof("     TPM based Hash %s", base64.StdEncoding.EncodeToString(khDigest))
					session, _, err := tpm2.StartAuthSession(
						rwc,
						/*tpmkey=*/ tpm2.HandleNull,
						/*bindkey=*/ tpm2.HandleNull,
						/*nonceCaller=*/ make([]byte, 32),
						/*encryptedSalt=*/ nil,
						/*sessionType=*/ tpm2.SessionPolicy,
						/*symmetric=*/ tpm2.AlgNull,
						/*authHash=*/ tpm2.AlgSHA256)
					defer tpm2.FlushContext(rwc, session)
					if err != nil {
						glog.Errorf("Error: StartAuthSession failed: %v\n", err)
						return
					}

					var signed *tpm2.Signature

					bindPCRValue := int(r.Pcr)

					if bindPCRValue >= 0 && bindPCRValue <= 23 {
						if err = tpm2.PolicyPCR(rwc, session, nil, tpm2.PCRSelection{tpm2.AlgSHA256, []int{bindPCRValue}}); err != nil {
							glog.Errorf("ERROR: PolicyPCR failed: %vn", err)
							return
						}
						signed, err = tpm2.SignWithSession(rwc, session, kh, "", d[:], khValidation, &tpm2.SigScheme{
							Alg:  tpm2.AlgRSASSA,
							Hash: tpm2.AlgSHA256,
						})
						if err != nil {
							glog.Errorf("ERROR:  Unable to SignWithSession with TPM: %v\n", err)
							return
						}
					} else {
						signed, err = tpm2.Sign(rwc, kh, "", d[:], khValidation, &tpm2.SigScheme{
							Alg:  tpm2.AlgRSASSA,
							Hash: tpm2.AlgSHA256,
						})
						if err != nil {
							glog.Errorf("ERROR: Unable to Sign with TPM: %v\n", err)
							return
						}
					}
					sig = base64.StdEncoding.EncodeToString(signed.RSA.Signature)

				} else {
					akey = r.SealedAESKey

					block, _ := pem.Decode(r.SealedRSAKey)
					priv, _ := x509.ParsePKCS1PrivateKey(block.Bytes)
					data := []byte("foobar")
					h := sha256.New()
					h.Write(data)
					d := h.Sum(nil)

					sigBytes, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, d)
					if err != nil {
						glog.Errorf("Unable to sign RSA %v\n", err)
						return
					}
					sig = base64.StdEncoding.EncodeToString(sigBytes)
				}

				rawKey := r.RawKey
				glog.V(20).Infof("     Received  RawKey: %s\n", string(rawKey))

				hasher := sha256.New()
				hasher.Write([]byte(akey))
				encsha := base64.StdEncoding.EncodeToString(hasher.Sum(nil))

				glog.V(2).Infof("     Unsealed AES Key with hash: %v\n", encsha)
				glog.V(2).Infof("Signed control data %v", sig)

				// ************************************

				/// ***********************************************************************************************************

				// ok, we've imported the RSA and AES keys.  Now optionally
				// perform Remote Attestation (i.,e generate and exchange Attestation key)
				// Then optionally offer the tokenServer a QuoteRequest
				// Then generate an unrestricted Signing key, sign it with EK and
				// use that to repeatedly sign arbitrary text that you can use later
				// You can also use the AK to sign known hash values.
				if *doAttestation && *useTPM {
					totalHandles := 0
					for _, handleType := range handleNames["all"] {
						handles, err := tpm2tools.Handles(rwc, handleType)
						if err != nil {
							glog.Errorf("ERROR getting handles: %v", err)
							return
						}
						for _, handle := range handles {
							if err = tpm2.FlushContext(rwc, handle); err != nil {
								glog.Errorf("flushing handle 0x%x: %v", handle, err)
							}
							glog.V(20).Infof("Handle 0x%x flushed\n", handle)
							totalHandles++
						}
					}

					// First create attestation keys
					akName, ekPub, akPub, err := createKeys()
					if err != nil {
						glog.Errorf("ERROR:     Unable to generate EK/AK: %v", err)
						return
					}
					u := uuid.New().String()

					req := &pb.MakeCredentialRequest{
						Uid:    u,
						AkName: akName,
						EkPub:  ekPub,
						AkPub:  akPub,
					}

					v := pb.NewVerifierClient(conn)

					rr, err := v.MakeCredential(ctx, req)
					if err != nil {
						glog.Errorf("Error MakeCredential: %v", err)
						return
					}
					time.Sleep(1 * time.Second)
					glog.V(5).Infof("     MakeCredential RPC Response with provided uid [%s]", rr.Uid)

					glog.V(5).Infof("=============== ActivateCredential  ===============")
					secret, err := activateCredential(rr.Uid, rr.CredBlob, rr.EncryptedSecret)
					if err != nil {
						glog.Errorf("ERROR:  could not activateCredential: %v", err)
						return
					}
					attestation, signature, err := quote(int(r.Pcr), secret)
					if err != nil {
						glog.Errorf("ERROR:  Unable to generate quote: %v", err)
						return
					}
					areq := &pb.ActivateCredentialRequest{
						Uid:         u,
						Secret:      secret,
						Attestation: attestation,
						Signature:   signature,
					}
					ar, err := v.ActivateCredential(ctx, areq)
					if err != nil {
						glog.Errorf("could not call ActivateCredential: %v", err)
						return
					}

					glog.V(5).Infof("=============== %v", ar)
					glog.V(5).Infof("=============== OfferQuote ===============")

					aqr := &pb.OfferQuoteRequest{
						Uid: u,
					}
					qr, err := v.OfferQuote(ctx, aqr)
					if err != nil {
						glog.Errorf("ERROR Could not call OfferQuote: %v", err)
						return
					}
					glog.V(5).Infof("     Quote Requested with nonce %s, pcr: %d", qr.Nonce, qr.Pcr)

					glog.V(5).Infof("=============== Generating Quote ===============")
					att, ssig, err := quote(int(qr.Pcr), qr.Nonce)
					if err != nil {
						glog.Errorf("ERROR  could not create Quote: %v", err)
						return
					}
					glog.V(5).Infof("=============== Providing Quote ===============")
					pqr := &pb.ProvideQuoteRequest{
						Uid:         u,
						Attestation: att,
						Signature:   ssig,
					}
					pqesp, err := v.ProvideQuote(ctx, pqr)
					if err != nil {
						glog.Errorf("ERROR Could not provideQuote: %v", err)
						return
					}
					glog.V(5).Infof("     Provided Quote verified: %t", pqesp.Verified)

					if *exchangeSigningKey {
						glog.V(5).Infof("=============== Providing SigningKey ===============")
						key, att, attsig, err := signingKey(*pcr)
						if err != nil {
							glog.Errorf("ERROR Could not signingKey: %v", err)
							return
						}
						glog.V(2).Infof("     Returning SigningKey")

						pskreq := &pb.ProvideSigningKeyRequest{
							Uid:         u,
							Signingkey:  key,
							Attestation: att,
							Signature:   attsig,
						}
						pskresp, err := v.ProvideSigningKey(ctx, pskreq)
						if err != nil {
							glog.Errorf("ERROR Could not ProvideSigningKey: %v", err)
							return
						}
						glog.V(2).Infof("     SigningKey Response %v", pskresp.Verified)
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
	// we already have the remote secrets from TPMServer in memory, do something with it here
	time.Sleep(3600 * time.Second)
	fmt.Printf("     Worker %d done\n", id)
}

func quote(reqPCR int, secret string) (attestation []byte, signature []byte, retErr error) {

	glog.V(5).Infof("     --> Start Quote")

	pcrList := []int{reqPCR}
	pcrval, err := tpm2.ReadPCR(rwc, *pcr, tpm2.AlgSHA256)
	if err != nil {
		glog.Fatalf("Unable to  ReadPCR : %v", err)
	}
	glog.V(5).Infof("     PCR %d Value %v ", *pcr, hex.EncodeToString(pcrval))

	pcrSelection23 := tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: pcrList}
	emptyPassword := ""

	glog.V(10).Infof("     ContextLoad (ek) ========")
	ekhBytes, err := ioutil.ReadFile(ekFile)
	if err != nil {
		return []byte(""), []byte(""), fmt.Errorf("ContextLoad failed for ekh: %v", err)
	}
	ekh, err := tpm2.ContextLoad(rwc, ekhBytes)
	if err != nil {
		return []byte(""), []byte(""), fmt.Errorf("ContextLoad failed for ekh: %v", err)
	}
	defer tpm2.FlushContext(rwc, ekh)
	glog.V(10).Infof("     LoadUsingAuth ========")

	loadCreateHandle, _, err := tpm2.StartAuthSession(
		rwc,
		tpm2.HandleNull,
		tpm2.HandleNull,
		make([]byte, 16),
		nil,
		tpm2.SessionPolicy,
		tpm2.AlgNull,
		tpm2.AlgSHA256)
	if err != nil {
		return []byte(""), []byte(""), fmt.Errorf("Unable to create StartAuthSession : %v", err)
	}
	defer tpm2.FlushContext(rwc, loadCreateHandle)

	if _, err := tpm2.PolicySecret(rwc, tpm2.HandleEndorsement, tpm2.AuthCommand{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession}, loadCreateHandle, nil, nil, nil, 0); err != nil {
		return []byte(""), []byte(""), fmt.Errorf("Unable to create PolicySecret: %v", err)
	}

	authCommandLoad := tpm2.AuthCommand{Session: loadCreateHandle, Attributes: tpm2.AttrContinueSession}

	glog.V(10).Infof("     Read (akPub) ========")
	akPub, err := ioutil.ReadFile(akPubFile)
	if err != nil {
		return []byte(""), []byte(""), fmt.Errorf("Read failed for akPub: %v", err)
	}
	glog.V(10).Infof("     Read (akPriv) ========")
	akPriv, err := ioutil.ReadFile(akPrivFile)
	if err != nil {
		return []byte(""), []byte(""), fmt.Errorf("Read failed for akPriv: %v", err)
	}

	keyHandle, keyName, err := tpm2.LoadUsingAuth(rwc, ekh, authCommandLoad, akPub, akPriv)
	if err != nil {
		return []byte(""), []byte(""), fmt.Errorf("Load failed: %s", err)
	}
	defer tpm2.FlushContext(rwc, keyHandle)
	kn := hex.EncodeToString(keyName)
	glog.V(10).Infof("     AK keyName %s", kn)

	attestation, sig, err := tpm2.Quote(rwc, keyHandle, emptyPassword, emptyPassword, []byte(secret), pcrSelection23, tpm2.AlgNull)
	if err != nil {
		return []byte(""), []byte(""), fmt.Errorf("Failed to quote: %s", err)
	}
	glog.V(10).Infof("     Quote Hex %v", hex.EncodeToString(attestation))
	glog.V(10).Infof("     Quote Sig %v", hex.EncodeToString(sig.RSA.Signature))
	glog.V(5).Infof("     <-- End Quote")
	return attestation, sig.RSA.Signature, nil
}

// Create Attestation keys
func createKeys() (n string, ekPub []byte, akPub []byte, retErr error) {

	glog.V(5).Infof("     --> CreateKeys()")

	pcrList := []int{*pcr}
	pcrval, err := tpm2.ReadPCR(rwc, *pcr, tpm2.AlgSHA256)
	if err != nil {
		return "", []byte(""), []byte(""), fmt.Errorf("Unable to  ReadPCR : %v", err)
	}
	glog.V(10).Infof("    Current PCR %v Value %d ", *pcr, hex.EncodeToString(pcrval))

	pcrSelection23 := tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: pcrList}
	emptyPassword := ""

	glog.V(10).Infof("     createPrimary")

	ekh, _, err := tpm2.CreatePrimary(rwc, tpm2.HandleEndorsement, pcrSelection23, emptyPassword, emptyPassword, defaultEKTemplate)
	if err != nil {
		return "", []byte(""), []byte(""), fmt.Errorf("Error creating EK: %v", err)
	}
	defer tpm2.FlushContext(rwc, ekh)

	// reread the pub eventhough tpm2.CreatePrimary* gives pub
	tpmEkPub, name, _, err := tpm2.ReadPublic(rwc, ekh)
	if err != nil {
		return "", []byte(""), []byte(""), fmt.Errorf("Error ReadPublic failed: %s", err)
	}

	p, err := tpmEkPub.Key()
	if err != nil {
		return "", []byte(""), []byte(""), fmt.Errorf("Error tpmEkPub.Key() failed: %s", err)
	}
	glog.V(10).Infof("     tpmEkPub: \n%v", p)

	b, err := x509.MarshalPKIXPublicKey(p)
	if err != nil {
		return "", []byte(""), []byte(""), fmt.Errorf("Unable to convert ekpub: %v", err)
	}

	ekPubPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: b,
		},
	)
	glog.V(5).Infof("     ekPub Name: %v", hex.EncodeToString(name))
	glog.V(10).Infof("     ekPubPEM: \n%v", string(ekPubPEM))

	ekPubBytes, err := tpmEkPub.Encode()
	if err != nil {
		return "", []byte(""), []byte(""), fmt.Errorf("Load failed for ekPubBytes: %v", err)
	}

	glog.V(10).Infof("     CreateKeyUsingAuth")

	sessCreateHandle, _, err := tpm2.StartAuthSession(
		rwc,
		tpm2.HandleNull,
		tpm2.HandleNull,
		make([]byte, 16),
		nil,
		tpm2.SessionPolicy,
		tpm2.AlgNull,
		tpm2.AlgSHA256)
	if err != nil {
		return "", []byte(""), []byte(""), fmt.Errorf("Unable to create StartAuthSession : %v", err)
	}
	defer tpm2.FlushContext(rwc, sessCreateHandle)

	if _, err := tpm2.PolicySecret(rwc, tpm2.HandleEndorsement, tpm2.AuthCommand{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession}, sessCreateHandle, nil, nil, nil, 0); err != nil {
		return "", []byte(""), []byte(""), fmt.Errorf("Unable to create PolicySecret: %v", err)
	}

	authCommandCreateAuth := tpm2.AuthCommand{Session: sessCreateHandle, Attributes: tpm2.AttrContinueSession}

	akPriv, akPub, creationData, creationHash, creationTicket, err := tpm2.CreateKeyUsingAuth(rwc, ekh, pcrSelection23, authCommandCreateAuth, emptyPassword, defaultKeyParams)
	if err != nil {
		return "", []byte(""), []byte(""), fmt.Errorf("CreateKey failed: %s", err)
	}
	glog.V(10).Infof("     akPub: %v,", hex.EncodeToString(akPub))
	glog.V(10).Infof("     akPriv: %v,", hex.EncodeToString(akPriv))

	cr, err := tpm2.DecodeCreationData(creationData)
	if err != nil {
		return "", []byte(""), []byte(""), fmt.Errorf("Unable to  DecodeCreationData : %v", err)
	}

	glog.V(10).Infof("     CredentialData.ParentName.Digest.Value %v", hex.EncodeToString(cr.ParentName.Digest.Value))
	glog.V(10).Infof("     CredentialTicket %v", hex.EncodeToString(creationTicket.Digest))
	glog.V(10).Infof("     CredentialHash %v", hex.EncodeToString(creationHash))

	glog.V(10).Infof("     ContextSave (ek)")
	ekhBytes, err := tpm2.ContextSave(rwc, ekh)
	if err != nil {
		return "", []byte(""), []byte(""), fmt.Errorf("ContextSave failed for ekh: %v", err)
	}
	err = ioutil.WriteFile(ekFile, ekhBytes, 0644)
	if err != nil {
		return "", []byte(""), []byte(""), fmt.Errorf("ContextSave failed for ekh: %v", err)
	}
	tpm2.FlushContext(rwc, ekh)

	glog.V(10).Infof("     ContextLoad (ek)")
	ekhBytes, err = ioutil.ReadFile(ekFile)
	if err != nil {
		return "", []byte(""), []byte(""), fmt.Errorf("ContextLoad failed for ekh: %v", err)
	}
	ekh, err = tpm2.ContextLoad(rwc, ekhBytes)
	if err != nil {
		return "", []byte(""), []byte(""), fmt.Errorf("ContextLoad failed for ekh: %v", err)
	}
	defer tpm2.FlushContext(rwc, ekh)
	glog.V(10).Infof("     LoadUsingAuth")

	loadSession, _, err := tpm2.StartAuthSession(
		rwc,
		tpm2.HandleNull,
		tpm2.HandleNull,
		make([]byte, 16),
		nil,
		tpm2.SessionPolicy,
		tpm2.AlgNull,
		tpm2.AlgSHA256)
	if err != nil {
		return "", []byte(""), []byte(""), fmt.Errorf("Unable to create StartAuthSession : %v", err)
	}
	defer tpm2.FlushContext(rwc, loadSession)

	if _, err := tpm2.PolicySecret(rwc, tpm2.HandleEndorsement, tpm2.AuthCommand{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession}, loadSession, nil, nil, nil, 0); err != nil {
		return "", []byte(""), []byte(""), fmt.Errorf("Unable to create PolicySecret: %v", err)
	}

	authCommandLoad := tpm2.AuthCommand{Session: loadSession, Attributes: tpm2.AttrContinueSession}

	keyHandle, keyName, err := tpm2.LoadUsingAuth(rwc, ekh, authCommandLoad, akPub, akPriv)
	if err != nil {
		return "", []byte(""), []byte(""), fmt.Errorf("Load failed: %s", err)
	}
	defer tpm2.FlushContext(rwc, keyHandle)
	kn := hex.EncodeToString(keyName)
	glog.V(5).Infof("     AK keyName %v", kn)

	akPublicKey, _, _, err := tpm2.ReadPublic(rwc, keyHandle)
	if err != nil {
		return "", []byte(""), []byte(""), fmt.Errorf("Error tpmEkPub.Key() failed: %s", err)
	}

	ap, err := akPublicKey.Key()
	if err != nil {
		return "", []byte(""), []byte(""), fmt.Errorf("tpmEkPub.Key() failed: %s", err)
	}
	akBytes, err := x509.MarshalPKIXPublicKey(ap)
	if err != nil {
		return "", []byte(""), []byte(""), fmt.Errorf("Unable to convert ekpub: %v", err)
	}

	akPubPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: akBytes,
		},
	)
	glog.V(10).Infof("     akPubPEM: \n%v", string(akPubPEM))

	glog.V(10).Infof("     Write (akPub) ========")
	err = ioutil.WriteFile(akPubFile, akPub, 0644)
	if err != nil {
		return "", []byte(""), []byte(""), fmt.Errorf("Save failed for akPub: %v", err)
	}
	glog.V(10).Infof("     Write (akPriv) ========")
	err = ioutil.WriteFile(akPrivFile, akPriv, 0644)
	if err != nil {
		return "", []byte(""), []byte(""), fmt.Errorf("Save failed for akPriv: %v", err)
	}

	glog.V(5).Infof("     <-- CreateKeys()")
	return kn, ekPubBytes, akPub, nil
}

func activateCredential(uid string, credBlob []byte, encryptedSecret []byte) (n string, retErr error) {

	glog.V(5).Infof("     --> activateCredential()")

	glog.V(10).Infof("     ContextLoad (ek)")
	ekhBytes, err := ioutil.ReadFile(ekFile)
	if err != nil {
		return "", fmt.Errorf("ContextLoad failed for ekh: %v", err)
	}
	ekh, err := tpm2.ContextLoad(rwc, ekhBytes)
	if err != nil {
		return "", fmt.Errorf("ContextLoad failed for ekh: %v", err)
	}
	defer tpm2.FlushContext(rwc, ekh)

	glog.V(10).Infof("     Read (akPub)")
	akPub, err := ioutil.ReadFile(akPubFile)
	if err != nil {
		return "", fmt.Errorf("Read failed for akPub: %v", err)
	}
	glog.V(10).Infof("     Read (akPriv)")
	akPriv, err := ioutil.ReadFile(akPrivFile)
	if err != nil {
		return "", fmt.Errorf("Read failed for akPriv: %v", err)
	}

	glog.V(5).Infof("     LoadUsingAuth")

	loadCreateHandle, _, err := tpm2.StartAuthSession(
		rwc,
		tpm2.HandleNull,
		tpm2.HandleNull,
		make([]byte, 16),
		nil,
		tpm2.SessionPolicy,
		tpm2.AlgNull,
		tpm2.AlgSHA256)
	if err != nil {
		return "", fmt.Errorf("Unable to create StartAuthSession : %v", err)
	}
	defer tpm2.FlushContext(rwc, loadCreateHandle)

	if _, err := tpm2.PolicySecret(rwc, tpm2.HandleEndorsement, tpm2.AuthCommand{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession}, loadCreateHandle, nil, nil, nil, 0); err != nil {
		return "", fmt.Errorf("Unable to create PolicySecret: %v", err)
	}

	authCommandLoad := tpm2.AuthCommand{Session: loadCreateHandle, Attributes: tpm2.AttrContinueSession}

	keyHandle, keyName, err := tpm2.LoadUsingAuth(rwc, ekh, authCommandLoad, akPub, akPriv)
	if err != nil {
		return "", fmt.Errorf("Load failed: %s", err)
	}
	defer tpm2.FlushContext(rwc, keyHandle)
	glog.V(5).Infof("     keyName %v", hex.EncodeToString(keyName))

	glog.V(5).Infof("     ActivateCredentialUsingAuth")

	sessActivateCredentialSessHandle1, _, err := tpm2.StartAuthSession(
		rwc,
		tpm2.HandleNull,
		tpm2.HandleNull,
		make([]byte, 16),
		nil,
		tpm2.SessionPolicy,
		tpm2.AlgNull,
		tpm2.AlgSHA256)
	if err != nil {
		return "", fmt.Errorf("Unable to create StartAuthSession : %v", err)
	}
	defer tpm2.FlushContext(rwc, sessActivateCredentialSessHandle1)

	if _, err := tpm2.PolicySecret(rwc, tpm2.HandleEndorsement, tpm2.AuthCommand{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession}, sessActivateCredentialSessHandle1, nil, nil, nil, 0); err != nil {
		return "", fmt.Errorf("Unable to create PolicySecret: %v", err)
	}

	authCommandActivate1 := tpm2.AuthCommand{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession}

	sessActivateCredentialSessHandle2, _, err := tpm2.StartAuthSession(
		rwc,
		tpm2.HandleNull,
		tpm2.HandleNull,
		make([]byte, 16),
		nil,
		tpm2.SessionPolicy,
		tpm2.AlgNull,
		tpm2.AlgSHA256)
	if err != nil {
		return "", fmt.Errorf("Unable to create StartAuthSession : %v", err)
	}
	defer tpm2.FlushContext(rwc, sessActivateCredentialSessHandle2)

	if _, err := tpm2.PolicySecret(rwc, tpm2.HandleEndorsement, tpm2.AuthCommand{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession}, sessActivateCredentialSessHandle2, nil, nil, nil, 0); err != nil {
		return "", fmt.Errorf("Unable to create PolicySecret: %v", err)
	}

	authCommandActivate2 := tpm2.AuthCommand{Session: sessActivateCredentialSessHandle2, Attributes: tpm2.AttrContinueSession}

	tl := []tpm2.AuthCommand{authCommandActivate1, authCommandActivate2}

	recoveredCredential1, err := tpm2.ActivateCredentialUsingAuth(rwc, tl, keyHandle, ekh, credBlob, encryptedSecret)
	if err != nil {
		return "", fmt.Errorf("ActivateCredential failed: %v", err)
	}
	glog.V(5).Infof("     <--  activateCredential()")
	return string(recoveredCredential1), nil
}

// Create unrestricted Signing keys.
// These are keys associated with the EK/AK that can be used to sign any arbitrary bit of data
// In contrast, the AK can only sign data that has been hash() by the TPM
// The snippet below just generates the AK bases signed data for reference but doesn't do anything
// with them.   the function below will just return the unrestricted key, its attestation (cerfiication)
// and signature back to the Server
func signingKey(reqPCR int) (key []byte, attestation []byte, signature []byte, retErr error) {

	glog.V(5).Infof("     --> Start signingKey")

	pcrList := []int{reqPCR}
	pcrval, err := tpm2.ReadPCR(rwc, *pcr, tpm2.AlgSHA256)
	if err != nil {
		glog.Fatalf("Unable to  ReadPCR : %v", err)
	}
	glog.V(5).Infof("     PCR %d Value %v ", *pcr, hex.EncodeToString(pcrval))

	pcrSelection23 := tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: pcrList}
	emptyPassword := ""

	glog.V(10).Infof("     ContextLoad (ek)")
	ekhBytes, err := ioutil.ReadFile(ekFile)
	if err != nil {
		return []byte(""), []byte(""), []byte(""), fmt.Errorf("ContextLoad failed for ekh: %v", err)
	}
	ekh, err := tpm2.ContextLoad(rwc, ekhBytes)
	if err != nil {
		return []byte(""), []byte(""), []byte(""), fmt.Errorf("ContextLoad failed for ekh: %v", err)
	}
	defer tpm2.FlushContext(rwc, ekh)

	// Load the attestation keys we generated in createKeys()

	glog.V(10).Infof("     Read (akPub)")
	akPub, err := ioutil.ReadFile(akPubFile)
	if err != nil {
		return []byte(""), []byte(""), []byte(""), fmt.Errorf("Read failed for akPub: %v", err)
	}
	glog.V(10).Infof("     Read (akPriv)")
	akPriv, err := ioutil.ReadFile(akPrivFile)
	if err != nil {
		return []byte(""), []byte(""), []byte(""), fmt.Errorf("Read failed for akPriv: %v", err)
	}

	glog.V(10).Infof("     LoadUsingAuth ========")

	sessLoadHandle, _, err := tpm2.StartAuthSession(
		rwc,
		tpm2.HandleNull,
		tpm2.HandleNull,
		make([]byte, 16),
		nil,
		tpm2.SessionPolicy,
		tpm2.AlgNull,
		tpm2.AlgSHA256)
	if err != nil {
		return []byte(""), []byte(""), []byte(""), fmt.Errorf("Unable to create StartAuthSession : %v", err)
	}
	defer tpm2.FlushContext(rwc, sessLoadHandle)

	if _, err := tpm2.PolicySecret(rwc, tpm2.HandleEndorsement, tpm2.AuthCommand{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession}, sessLoadHandle, nil, nil, nil, 0); err != nil {
		return []byte(""), []byte(""), []byte(""), fmt.Errorf("Unable to create PolicySecret: %v", err)
	}
	authCommandLoad := tpm2.AuthCommand{Session: sessLoadHandle, Attributes: tpm2.AttrContinueSession}

	aKkeyHandle, keyName, err := tpm2.LoadUsingAuth(rwc, ekh, authCommandLoad, akPub, akPriv)
	defer tpm2.FlushContext(rwc, aKkeyHandle)
	if err != nil {
		return []byte(""), []byte(""), []byte(""), fmt.Errorf("Load AK failed: %s", err)
	}
	glog.V(5).Infof("     AK keyName: %v", hex.EncodeToString(keyName))

	tpm2.FlushContext(rwc, sessLoadHandle)

	glog.V(5).Infof("======= SignwithRestrictedKey ========")

	tPub, err := tpm2.DecodePublic(akPub)
	if err != nil {
		return []byte(""), []byte(""), []byte(""), fmt.Errorf("Error DecodePublic AK %v", tPub)
	}

	ap, err := tPub.Key()
	if err != nil {
		return []byte(""), []byte(""), []byte(""), fmt.Errorf("akPub.Key() failed: %s", err)
	}
	akBytes, err := x509.MarshalPKIXPublicKey(ap)
	if err != nil {
		return []byte(""), []byte(""), []byte(""), fmt.Errorf("Unable to convert akPub: %v", err)
	}

	akPubPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: akBytes,
		},
	)

	sessCreateHandle, _, err := tpm2.StartAuthSession(
		rwc,
		tpm2.HandleNull,
		tpm2.HandleNull,
		make([]byte, 16),
		nil,
		tpm2.SessionPolicy,
		tpm2.AlgNull,
		tpm2.AlgSHA256)
	if err != nil {
		return []byte(""), []byte(""), []byte(""), fmt.Errorf("Unable to create StartAuthSession : %v", err)
	}
	defer tpm2.FlushContext(rwc, sessCreateHandle)

	if _, err := tpm2.PolicySecret(rwc, tpm2.HandleEndorsement, tpm2.AuthCommand{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession}, sessCreateHandle, nil, nil, nil, 0); err != nil {
		return []byte(""), []byte(""), []byte(""), fmt.Errorf("Unable to create PolicySecret: %v", err)
	}
	authCommandCreateAuth := tpm2.AuthCommand{Session: sessCreateHandle, Attributes: tpm2.AttrContinueSession}

	// Use the TPM to hash some data
	aKdataToSign := []byte("foobar")
	aKdigest, aKvalidation, err := tpm2.Hash(rwc, tpm2.AlgSHA256, aKdataToSign, tpm2.HandleOwner)
	if err != nil {
		return []byte(""), []byte(""), []byte(""), fmt.Errorf("Hash failed unexpectedly: %v", err)
	}

	glog.V(5).Infof("     AK Issued Hash %s", base64.StdEncoding.EncodeToString(aKdigest))
	aKsig, err := tpm2.Sign(rwc, aKkeyHandle, emptyPassword, aKdigest, aKvalidation, &tpm2.SigScheme{
		Alg:  tpm2.AlgRSASSA,
		Hash: tpm2.AlgSHA256,
	})
	if err != nil {
		return []byte(""), []byte(""), []byte(""), fmt.Errorf("Sign failed unexpectedly: %v", err)
	}

	glog.V(5).Infof("     AK Signed Data %s", base64.StdEncoding.EncodeToString(aKsig.RSA.Signature))

	// Ok, now we've signed the data using the AK.
	// Now cross check by verifying that against the public part of the AK:
	akblock, _ := pem.Decode(akPubPEM)
	if akblock == nil {
		return []byte(""), []byte(""), []byte(""), fmt.Errorf("Unable to decode akPubPEM %v", err)
	}

	akRsa, err := x509.ParsePKIXPublicKey(akblock.Bytes)
	if err != nil {
		return []byte(""), []byte(""), []byte(""), fmt.Errorf("Unable to create rsa Key from PEM %v", err)
	}
	akRsaPub := *akRsa.(*rsa.PublicKey)

	akhsh := crypto.SHA256.New()
	akhsh.Write(aKdataToSign)

	if err := rsa.VerifyPKCS1v15(&akRsaPub, crypto.SHA256, akhsh.Sum(nil), aKsig.RSA.Signature); err != nil {
		return []byte(""), []byte(""), []byte(""), fmt.Errorf("VerifyPKCS1v15 failed: %v", err)
	}
	glog.V(5).Infof("     AK Verified Signature\n")

	//  Not create an unsrestricted signing key
	glog.V(5).Infof("======= SignwithUnrestrictedKey ========")

	sessCreateHandle, _, err = tpm2.StartAuthSession(
		rwc,
		tpm2.HandleNull,
		tpm2.HandleNull,
		make([]byte, 16),
		nil,
		tpm2.SessionPolicy,
		tpm2.AlgNull,
		tpm2.AlgSHA256)
	if err != nil {
		return []byte(""), []byte(""), []byte(""), fmt.Errorf("ERROR Unable to create StartAuthSession : %v", err)
	}
	defer tpm2.FlushContext(rwc, sessCreateHandle)

	if _, err := tpm2.PolicySecret(rwc, tpm2.HandleEndorsement, tpm2.AuthCommand{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession}, sessCreateHandle, nil, nil, nil, 0); err != nil {
		return []byte(""), []byte(""), []byte(""), fmt.Errorf("ERROR Unable to create PolicySecret: %v", err)
	}
	authCommandCreateAuth = tpm2.AuthCommand{Session: sessCreateHandle, Attributes: tpm2.AttrContinueSession}

	ukPriv, ukPub, _, _, _, err := tpm2.CreateKeyUsingAuth(rwc, ekh, pcrSelection23, authCommandCreateAuth, emptyPassword, unrestrictedKeyParams)

	if err != nil {
		return []byte(""), []byte(""), []byte(""), fmt.Errorf("ERROR UnrestrictedCreateKey failed: %s", err)
	}
	glog.V(5).Infof("     Unrestricted ukPub: %v,", hex.EncodeToString(ukPub))
	glog.V(5).Infof("     Unrestricted ukPriv: %v,", hex.EncodeToString(ukPriv))

	glog.V(10).Infof("     Write (ukPub) ========")
	err = ioutil.WriteFile(signPubFile, ukPub, 0644)
	if err != nil {
		return []byte(""), []byte(""), []byte(""), fmt.Errorf("Save failed for ukPub: %v", err)
	}
	glog.V(10).Infof("     Write (ukPriv) ========")
	err = ioutil.WriteFile(signPrivFile, ukPriv, 0644)
	if err != nil {
		return []byte(""), []byte(""), []byte(""), fmt.Errorf("Save failed for ukPriv: %v", err)
	}

	tpm2.FlushContext(rwc, sessCreateHandle)

	// Load the unrestricted key
	sessLoadHandle, _, err = tpm2.StartAuthSession(
		rwc,
		tpm2.HandleNull,
		tpm2.HandleNull,
		make([]byte, 16),
		nil,
		tpm2.SessionPolicy,
		tpm2.AlgNull,
		tpm2.AlgSHA256)
	if err != nil {
		glog.V(5).Infof("     Unable to create StartAuthSession : %v", err)
	}
	defer tpm2.FlushContext(rwc, sessLoadHandle)

	if _, err := tpm2.PolicySecret(rwc, tpm2.HandleEndorsement, tpm2.AuthCommand{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession}, sessLoadHandle, nil, nil, nil, 0); err != nil {
		glog.V(5).Infof("     Unable to create PolicySecret: %v", err)
	}
	authCommandLoad = tpm2.AuthCommand{Session: sessLoadHandle, Attributes: tpm2.AttrContinueSession}

	ukeyHandle, ukeyName, err := tpm2.LoadUsingAuth(rwc, ekh, authCommandLoad, ukPub, ukPriv)

	if err != nil {
		return []byte(""), []byte(""), []byte(""), fmt.Errorf("ERROR Load failed: %s", err)
	}
	defer tpm2.FlushContext(rwc, ukeyHandle)
	glog.V(5).Infof("     ukeyName: %v,", hex.EncodeToString(ukeyName))

	// Certify the Unrestricted key using the AK
	// This step will generate a form of attestation that the client can send back to the Server
	// The server (Alice), can use this certification to verify that the AK it has already
	// through remote attestation is the one that signed the unrestricted key
	attestation, csig, err := tpm2.Certify(rwc, emptyPassword, emptyPassword, ukeyHandle, aKkeyHandle, nil)
	if err != nil {
		return []byte(""), []byte(""), []byte(""), fmt.Errorf("ERROR Load failed: %s", err)
	}
	glog.V(5).Infof("     Certify Attestation: %v,", hex.EncodeToString(attestation))
	glog.V(5).Infof("     Certify Signature: %v,", hex.EncodeToString(csig))
	tpm2.FlushContext(rwc, sessLoadHandle)

	uPublicKey, _, _, err := tpm2.ReadPublic(rwc, ukeyHandle)
	if err != nil {
		return []byte(""), []byte(""), []byte(""), fmt.Errorf("Error uPublicKey.Key() failed: %s", err)
	}

	up, err := uPublicKey.Key()
	if err != nil {
		return []byte(""), []byte(""), []byte(""), fmt.Errorf("uPublicKey.Key() failed: %s", err)
	}
	upBytes, err := x509.MarshalPKIXPublicKey(up)
	if err != nil {
		return []byte(""), []byte(""), []byte(""), fmt.Errorf("Unable to convert upBytes: %v", err)
	}

	ukPubPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: upBytes,
		},
	)
	glog.V(2).Infof("     ukPubPEM: \n%v", string(ukPubPEM))

	// Genereate a test signature using the unrestricted key
	dataToSign := []byte("foobar")
	ukhDigest, ukhValidation, err := tpm2.Hash(rwc, tpm2.AlgSHA256, dataToSign, tpm2.HandleOwner)
	if err != nil {
		return []byte(""), []byte(""), []byte(""), fmt.Errorf("Hash failed unexpectedly: %v", err)
	}

	glog.V(5).Infof("     TPM based Hash for Unrestricted Key %s", base64.StdEncoding.EncodeToString(ukhDigest))

	sig, err := tpm2.Sign(rwc, ukeyHandle, "", ukhDigest[:], ukhValidation, &tpm2.SigScheme{
		Alg:  tpm2.AlgRSASSA,
		Hash: tpm2.AlgSHA256,
	})
	if err != nil {
		return []byte(""), []byte(""), []byte(""), fmt.Errorf("Error Signing with unrestricted key: %v", err)
	}
	glog.V(10).Infof("Control Signature data with unrestriced Key:  %s", base64.RawStdEncoding.EncodeToString([]byte(sig.RSA.Signature)))

	// Verify the signature using openssl locally
	hsh := crypto.SHA256.New()
	hsh.Write(dataToSign)
	if err := rsa.VerifyPKCS1v15(up.(*rsa.PublicKey), crypto.SHA256, hsh.Sum(nil), sig.RSA.Signature); err != nil {
		return []byte(""), []byte(""), []byte(""), fmt.Errorf("VerifyPKCS1v15 failed: %v", err)
	}
	glog.V(5).Infof("     Unrestricted Key Signature Verified\n")

	// return the PEM format of the unrestricted key and attestation back.
	return ukPubPEM, attestation, csig, nil
}
