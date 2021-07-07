package main

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"

	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"

	"flag"
	"fmt"
	"log"
	"net/url"
	"os"

	"strconv"
	"strings"
	"time"

	certparser "github.com/salrashid123/gcp_tokendistributor/certparser"
	tspb "github.com/salrashid123/gcp_tokendistributor/tokenservice"

	"cloud.google.com/go/firestore"

	"github.com/golang/protobuf/jsonpb"
	"github.com/golang/protobuf/proto"
	tpmpb "github.com/google/go-tpm-tools/proto"
	"github.com/google/go-tpm-tools/server"
	"golang.org/x/net/context"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
	"google.golang.org/genproto/googleapis/cloud/audit"

	"cloud.google.com/go/logging"
	"cloud.google.com/go/logging/logadmin"
)

type ServiceEntry struct {
	Description        string         `firestore:"description,omitempty"`
	Done               bool           `firestore:"done"`
	InstanceID         string         `firestore:"instanceid"`
	ClientProject      string         `firestore:"client_project"`
	ClientZone         string         `firestore:"client_zone"`
	ServiceAccountName string         `firestore:"service_account_name"`
	EKEncryptionCert   string         `firestore:"ek_encryption_cert"`
	AKSigningCert      string         `firestore:"ak_signing_cert"`
	EKEncryptionKey    string         `firestore:"ek_encryption_key"`
	AKSigningKey       string         `firestore:"ak_signing_key"`
	InitScriptHash     string         `firestore:"init_script_hash"`
	ImageFingerprint   string         `firestore:"image_fingerprint"`
	GCSObjectReference string         `firestore:"gcs_object,omitempty"`
	Secrets            []*tspb.Secret `firestore:"secrets,omitempty"`
	ProvidedAt         time.Time      `firestore:"provided_at"`
	PeerAddress        string         `firestore:"peer_address"`
	PeerSerialNumber   string         `firestore:"peer_serial_number"`
	PCR                int64          `firestore:"pcr"`
	PCRValue           string         `firestore:"pcr_value,omitempty"`
}

const (
	tpmDevice = "/dev/tpm0"
)

var (
	fireStoreProjectId      = flag.String("fireStoreProjectId", "", "ProjectID for Firestore")
	firestoreCollectionName = flag.String("firestoreCollectionName", "", "firestoreCollectionName where the sealedData is Stored")

	pcrsValues          = flag.String("pcrValues", "", "SHA256 PCR Values to seal against 23:=foo,20=bar.")
	encryptToTPM        = flag.String("encryptToTPM", "", "Data to seal with EkPub of target VM")
	attestationPCR      = flag.Int64("attestationPCR", 0, "The PCR bank for Attestation (default:0)")
	attestationPCRValue = flag.String("attestationPCRValue", "24af52a4f429b71a3184a6d64cddad17e54ea030e2aa6576bf3a5a3d8bd3328f", "expectedPCRValue")

	clientProjectId = flag.String("clientProjectId", "", "clientProjectId for VM")
	clientVMZone    = flag.String("clientVMZone", "", "clientVMZone for VM")
	clientVMId      = flag.String("clientVMId", "", "clientVMId for VM")
	autoAccept      = flag.Bool("autoAccept", false, "autoAccept configuration")

	secretsFile = flag.String("secretsFile", "", "File with []Secrets JSON struct")

	peerAddress = flag.String("peerAddress", "", "Token Client IP address")
	// SerialNumber=5 happens to be the value inside `bob/certs/tokenclient.crt`
	peerSerialNumber = flag.String("peerSerialNumber", "5", "Client Certificate Serial Number Serial Number: 5 (0x5) ")
	pcrMap           = map[uint32][]byte{}
	useTPM           = flag.Bool("useTPM", false, "Enable TPM operations")
)

func main() {
	flag.Parse()
	ctx := context.Background()

	computeService, err := compute.NewService(ctx)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("%s  %s  %s", *clientProjectId, *clientVMZone, *clientVMId)

	cresp, err := computeService.Instances.Get(*clientProjectId, *clientVMZone, *clientVMId).Do()
	if err != nil {
		log.Fatalf("Unable to find  Instance %v", err)
	}

	// TODO check name, service account
	log.Printf("Found  VM instanceID %#v\n", strconv.FormatUint(cresp.Id, 10))
	var initScriptHash string
	for _, m := range cresp.Metadata.Items {
		if m.Key == "user-data" {
			hasher := sha256.New()
			hasher.Write([]byte(*m.Value))
			initScriptHash = base64.StdEncoding.EncodeToString(hasher.Sum(nil))
			log.Printf("Image Data: %s\n", *m.Value)
		}
	}
	// TODO: save any of these parameters to ServiceEntry Firestore
	//       as other values to check for when GetToken() is called by the TokenClient
	//       The idea is to make sure the TokenClient is the same isolated system that
	//       Was provisioned here that makes the call to get the token at runtime
	// If a NAT is used, you need to specify that as the --peerAddress= value instead

	log.Printf("     Found  VM initScriptHash: [%s]\n", initScriptHash)
	log.Printf("     Found  VM CreationTimestamp %#v\n", cresp.CreationTimestamp)
	log.Printf("     Found  VM Fingerprint %#v\n", cresp.Fingerprint)
	log.Printf("     Found  VM CpuPlatform %#v\n", cresp.CpuPlatform)

	for _, d := range cresp.Disks {
		if d.Boot {
			log.Printf("     Found  VM Boot Disk Source %#v\n", d.Source)
			u, err := url.Parse(d.Source)
			if err != nil {
				log.Fatal(err)
			}
			// yeah, i don't know of a better way to parse a GCP ResourceURL...
			// compute/v1/projects/mineral-minutia-820/zones/us-central1-a/disks/tpm-a
			vals := strings.Split(u.Path, "/")
			if len(vals) == 9 {
				dresp, err := computeService.Disks.Get(vals[4], vals[6], vals[8]).Do()
				if err != nil {
					log.Fatalf("ERROR:  Could not find Disk  %s", err)
				}
				log.Printf("     Found Disk Image %s", dresp.SourceImage)
			}

		}
	}
	for _, sa := range cresp.ServiceAccounts {
		log.Printf("     Found  VM ServiceAccount %#v\n", sa.Email)
	}
	for _, ni := range cresp.NetworkInterfaces {
		for _, ac := range ni.AccessConfigs {
			if ac.Type == "ONE_TO_ONE_NAT" {
				log.Printf("Found VM External IP %s\n", ac.NatIP)
				if *peerAddress == "" {
					*peerAddress = ac.NatIP
				}
			}
		}
		log.Printf("Found VM Internal IP %s\n", ni.NetworkIP)
	}

	if *encryptToTPM != "" {
		mresp, err := computeService.Instances.GetShieldedInstanceIdentity(*clientProjectId, *clientVMZone, *clientVMId).Do()
		if err != nil {
			log.Fatalf("Unable to find  Instance %v", err)
		}
		log.Println("Derived EKPub for Instance:")
		log.Printf(mresp.EncryptionKey.EkPub)

		te, err := createImportBlob(mresp.EncryptionKey.EkPub, *encryptToTPM)
		log.Printf("Encrypted Data %v", base64.StdEncoding.EncodeToString(te))
		//  --sealToPCR=0 --sealToPCRValue=24af52a4f429b71a3184a6d64cddad17e54ea030e2aa6576bf3a5a3d8bd3328f
		//  --sealToPCR=23 --sealToPCRValue=f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b
		return
	}

	ekKeys, err := computeService.Instances.GetShieldedInstanceIdentity(*clientProjectId, *clientVMZone, *clientVMId).Do()
	if err != nil {
		log.Fatalf("Unable to find  Instance %v", err)
	}

	pubEKey := ekKeys.EncryptionKey.EkPub
	pubECert := ekKeys.EncryptionKey.EkCert // is currently null
	pubSKey := ekKeys.SigningKey.EkPub
	pubSCert := ekKeys.SigningKey.EkCert // is currently null

	// the following pubECert/pubScert is currently not used/enabled since these certs are not returned
	//  if they did, they would include some addition x509 extension data
	if pubECert != "" {
		block, _ := pem.Decode([]byte(pubECert))
		if block == nil {
			panic("failed to parse certificate PEM")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			panic("failed to parse certificate: " + err.Error())
		}
		e, err := certparser.NewEKCertificate(cert)
		if err != nil {
			panic(err)
		}
		log.Println("VM InstanceID from EKCert Encryption: ", e.GCEInstanceID())

	}
	if pubSCert != "" {
		block, _ := pem.Decode([]byte(pubSCert))
		if block == nil {
			panic("failed to parse certificate PEM")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			panic("failed to parse certificate: " + err.Error())
		}
		e, err := certparser.NewEKCertificate(cert)
		if err != nil {
			panic(err)
		}
		log.Println("VM InstanceID from EKCert Signing: ", e.GCEInstanceID())
	}

	// Now Read logging

	log.Println("===========  Instance AuditLog Start =========== ")
	loggingClient, err := logadmin.NewClient(ctx, *clientProjectId, option.WithScopes("https://www.googleapis.com/auth/logging.read"))
	if err != nil {
		log.Fatal(err)
	}

	var entries []*logging.Entry
	fiveminsAgo := time.Now().Add(time.Minute * time.Duration(-30))
	t := fiveminsAgo.Format(time.RFC3339) // Logging API wants timestamps in RFC 3339 format.

	filter := fmt.Sprintf("resource.type=gce_instance AND (logName=projects/%s/logs/cloudaudit.googleapis.com%%2Factivity OR logName=projects/%s/logs/cloudaudit.googleapis.com%%2Fdata_access) AND protoPayload.\"@type\"=\"type.googleapis.com/google.cloud.audit.AuditLog\" AND resource.labels.instance_id=%s AND %s", *clientProjectId, *clientProjectId, *clientVMId, fmt.Sprintf(`timestamp > "%s"`, t))
	iter := loggingClient.Entries(ctx,
		logadmin.Filter(filter),
		logadmin.NewestFirst(),
	)

	for len(entries) < 200 {
		entry, err := iter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			log.Fatalf("Error getting input %v\n", err)
		}
		entries = append(entries, entry)
	}

	// https://pkg.go.dev/google.golang.org/genproto/googleapis/cloud/audit#AuditLog
	for _, entry := range entries {
		log.Println("LogEntry:")
		log.Printf("    Severity %s\n", entry.Severity)
		log.Printf("    TimeStamp @%s\n", entry.Timestamp.Format(time.RFC3339))
		log.Printf("    LogName [%s]\n", entry.LogName)
		b, ok := entry.Payload.(*audit.AuditLog)
		if !ok {
			log.Fatalf("Error unmarshalling AuditLog %v\n", err)
		}

		log.Printf("    Service Name  [%s]\n", b.ServiceName)
		log.Printf("    Method Name [%s]\n", b.MethodName)
		log.Printf("    AuthenticationInfo [%s]\n", b.AuthenticationInfo)
		log.Printf("    CallerIP [%s]\n", b.RequestMetadata.CallerIp)
		log.Printf("    Request %s\n", b.Request)
		log.Println("    ============")
		if b.MethodName == "v1.compute.instances.setMetadata" {
			log.Fatalf(">>>> SetMetadata called on instance, exiting\n")
		}

	}

	log.Println("===========  Instance AuditLog End =========== ")
	var s string

	if *autoAccept {
		log.Println("Automatically accepting VM Configuration (used for testing")
	} else {
		log.Printf("looks ok? (y/N): ")
		_, err = fmt.Scan(&s)
		if err != nil {
			log.Fatalf("Error getting input %v\n", err)
		}

		s = strings.TrimSpace(s)
		s = strings.ToLower(s)

		if !(s == "y" || s == "yes") {
			return
		}
	}

	jsonFile, err := os.Open(*secretsFile)
	if err != nil {
		log.Fatal(err)
	}
	jsonDecoder := json.NewDecoder(jsonFile)
	_, err = jsonDecoder.Token()
	if err != nil {
		log.Fatal(err)
	}
	var protoMessages []*tspb.Secret
	for jsonDecoder.More() {
		protoMessage := tspb.Secret{}
		err := jsonpb.UnmarshalNext(jsonDecoder, &protoMessage)
		if err != nil {
			log.Fatal(err)
		}
		protoMessages = append(protoMessages, &protoMessage)
	}

	client, err := firestore.NewClient(ctx, *fireStoreProjectId)
	if err != nil {
		log.Fatal(err)
	}

	e := &ServiceEntry{
		InstanceID:         *clientVMId,
		ClientProject:      *clientProjectId,
		ClientZone:         *clientVMZone,
		Done:               false,
		ServiceAccountName: cresp.ServiceAccounts[0].Email,
		InitScriptHash:     initScriptHash,
		ImageFingerprint:   cresp.Fingerprint,
		Secrets:            protoMessages,

		EKEncryptionCert: pubECert, // currently null
		EKEncryptionKey:  pubEKey,
		AKSigningCert:    pubSCert, // currently null
		AKSigningKey:     pubSKey,

		ProvidedAt:       time.Now(),
		PCR:              *attestationPCR,
		PCRValue:         *attestationPCRValue,
		PeerAddress:      *peerAddress,
		PeerSerialNumber: *peerSerialNumber,
	}

	resp, err := client.Collection(*firestoreCollectionName).Doc(*clientVMId).Set(ctx, e)
	if err != nil {
		log.Printf("An error has occurred: %s", err)
	}
	log.Printf(resp.UpdateTime.String())

	dsnap, err := client.Collection(*firestoreCollectionName).Doc(*clientVMId).Get(ctx)
	if err != nil {
		log.Fatal(err)
	}
	var c ServiceEntry
	dsnap.DataTo(&c)
	log.Printf("Document data: %#v\n", c.InstanceID)

}

func createSigningKeyImportBlob(ekPubPEM string, rsaKeyPEM string) (sealedOutput []byte, retErr error) {

	block, _ := pem.Decode([]byte(ekPubPEM))
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return []byte(""), err
	}

	ekPub := pub.(crypto.PublicKey)

	privBlock, _ := pem.Decode([]byte(rsaKeyPEM))
	signingKey, err := x509.ParsePKCS1PrivateKey(privBlock.Bytes)
	if err != nil {
		return []byte(""), err
	}

	// todo: seal to PCR value
	var pcrs *tpmpb.Pcrs
	if *pcrsValues != "" {
		entries := strings.Split(*pcrsValues, ",")
		pcrMap = make(map[uint32][]byte)
		for _, e := range entries {
			parts := strings.Split(e, "=")
			u, err := strconv.ParseUint(parts[0], 10, 64)
			if err != nil {
				return []byte(""), err
			}

			hv, err := hex.DecodeString(parts[1])
			if err != nil {
				return []byte(""), err
			}
			pcrMap[uint32(u)] = hv

			rr := hex.Dump(hv)
			log.Printf("PCR key: %v\n", uint32(u))
			log.Printf("PCR Values: %v\n", rr)

		}
		log.Printf("PCR Values: %v\n", pcrMap)
	}

	pcrs = &tpmpb.Pcrs{Hash: tpmpb.HashAlgo_SHA256, Pcrs: pcrMap}

	blob, err := server.CreateSigningKeyImportBlob(ekPub, signingKey, pcrs)
	if err != nil {
		return []byte(""), err
	}

	dd, err := proto.Marshal(blob)
	if err != nil {
		return []byte(""), err
	}

	//return base64.RawStdEncoding.EncodeToString(dd), nil
	return dd, nil
}

func createImportBlob(ekPubPEM string, aesKey string) (sealedOutput []byte, retErr error) {

	block, _ := pem.Decode([]byte(ekPubPEM))
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return []byte(""), err
	}

	ekPub := pub.(crypto.PublicKey)
	var pcrs *tpmpb.Pcrs

	if *pcrsValues != "" {
		entries := strings.Split(*pcrsValues, ",")
		pcrMap = make(map[uint32][]byte)
		for _, e := range entries {
			parts := strings.Split(e, "=")
			u, err := strconv.ParseUint(parts[0], 10, 64)
			if err != nil {
				return []byte(""), err
			}

			hv, err := hex.DecodeString(parts[1])
			if err != nil {
				return []byte(""), err
			}
			pcrMap[uint32(u)] = hv

			rr := hex.Dump(hv)
			log.Printf("PCR key: %v\n", uint32(u))
			log.Printf("PCR Values: %v\n", rr)

		}
		log.Printf("PCR Values: %v\n", pcrMap)
	}

	pcrs = &tpmpb.Pcrs{Hash: tpmpb.HashAlgo_SHA256, Pcrs: pcrMap}

	blob, err := server.CreateImportBlob(ekPub, []byte(aesKey), pcrs)
	if err != nil {
		return []byte(""), err
	}
	data, err := proto.Marshal(blob)
	if err != nil {
		return []byte(""), err
	}

	return data, nil
}
