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

	tspb "tokenservice"

	"cloud.google.com/go/firestore"

	"github.com/golang/protobuf/jsonpb"
	tpmpb "github.com/google/go-tpm-tools/proto"
	"github.com/google/go-tpm-tools/server"
	"google.golang.org/api/compute/v1"

	"github.com/golang/protobuf/proto"

	"golang.org/x/net/context"
)

type ServiceEntry struct {
	Description        string         `firestore:"description,omitempty"`
	Done               bool           `firestore:"done"`
	InstanceID         string         `firestore:"instanceid"`
	ClientProject      string         `firestore:"client_project"`
	ClientZone         string         `firestore:"client_zone"`
	ServiceAccountName string         `firestore:"service_account_name"`
	InitScriptHash     string         `firestore:"init_script_hash"`
	ImageFingerprint   string         `firestore:"image_fingerprint"`
	GCSObjectReference string         `firestore:"gcs_object,omitempty"`
	Secrets            []*tspb.Secret `firestore:"secrets,omitempty"`
	ProvidedAt         time.Time      `firestore:"provided_at"`
	PeerAddress        string         `firestore:"peer_address"`
	PeerSerialNumber   string         `firestore:"peer_serial_number"`
}

const (
	tpmDevice = "/dev/tpm0"
)

var (
	fireStoreProjectId      = flag.String("fireStoreProjectId", "", "ProjectID for Firestore")
	firestoreCollectionName = flag.String("firestoreCollectionName", "", "firestoreCollectionName where the sealedData is Stored")

	sealToPCR       = flag.Int64("sealToPCR", 0, "The PCR number to seal this data to where the sealedData is Stored")
	sealToPCRValue  = flag.String("sealToPCRValue", "fcecb56acc303862b30eb342c4990beb50b5e0ab89722449c2d9a73f37b019fe", "The PCR Vallue to seal this data to")
	encryptToTPM    = flag.String("encryptToTPM", "", "Data to seal with EkPub of target VM")
	clientProjectId = flag.String("clientProjectId", "", "clientProjectId for VM")
	clientVMZone    = flag.String("clientVMZone", "", "clientVMZone for VM")
	clientVMId      = flag.String("clientVMId", "", "clientVMId for VM")
	autoAccept      = flag.Bool("autoAccept", false, "autoAccept configuration")

	secretsFile = flag.String("secretsFile", "", "File with []Secrets JSON struct")

	peerAddress = flag.String("peerAddress", "", "Token Client IP address")
	// SerialNumber=5 happens to be the value inside `bob/certs/tokenclient.crt`
	peerSerialNumber = flag.String("peerSerialNumber", "5", "Client Certificate Serial Number Serial Number: 5 (0x5) ")
	pcrMap           = map[uint32][]byte{}
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
		//  --sealToPCR=0 --sealToPCRValue=fcecb56acc303862b30eb342c4990beb50b5e0ab89722449c2d9a73f37b019fe
		//  --sealToPCR=23 --sealToPCRValue=DB56114E00FDD4C1F85C892BF35AC9A89289AAECB1EBD0A96CDE606A748B5D71
		return
	}

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

		ProvidedAt: time.Now(),

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

func createImportBlob(ekPubPEM string, aesKey string) (sealedOutput []byte, retErr error) {

	block, _ := pem.Decode([]byte(ekPubPEM))
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return []byte(""), err
	}

	ekPub := pub.(crypto.PublicKey)
	var pcrs *tpmpb.Pcrs
	if *sealToPCR >= 0 && *sealToPCRValue != "" {
		hv, err := hex.DecodeString(*sealToPCRValue)
		if err != nil {
			return []byte(""), err
		}
		pcrMap = map[uint32][]byte{uint32(*sealToPCR): hv}
	} else {
		pcrMap = map[uint32][]byte{}
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
