package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"cloud.google.com/go/firestore"
	"google.golang.org/api/compute/v1"

	"golang.org/x/net/context"
)

type Secret struct {
	Name string `firestore:"name"`
	Type string `firestore:"type"`
	Data string `firestore:"data"`
}
type ServiceEntry struct {
	Description        string    `firestore:"description,omitempty"`
	Done               bool      `firestore:"done"`
	InstanceID         string    `firestore:"instanceid"`
	ClientProject      string    `firestore:"client_project"`
	ClientZone         string    `firestore:"client_zone"`
	ServiceAccountName string    `firestore:"service_account_name"`
	InitScriptHash     string    `firestore:"init_script_hash"`
	ImageFingerprint   string    `firestore:"image_fingerprint"`
	GCSObjectReference string    `firestore:"gcs_object,omitempty"`
	Secrets            []Secret  `firestore:"secrets,omitempty"`
	ProvidedAt         time.Time `firestore:"provided_at"`
	PeerAddress        string    `firestore:"peer_address"`
	PeerSerialNumber   string    `firestore:"peer_serial_number"`
}

const ()

var (
	fireStoreProjectId      = flag.String("fireStoreProjectId", "", "ProjectID for Firestore")
	firestoreCollectionName = flag.String("firestoreCollectionName", "", "firestoreCollectionName where the sealedData is Stored")

	sealToPCR       = flag.Int64("sealToPCR", -1, "The PCR number to seal this data to where the sealedData is Stored")
	sealToPCRValue  = flag.String("sealToPCRValue", "", "The PCR Vallue to seal this data to")
	clientProjectId = flag.String("clientProjectId", "", "clientProjectId for VM")
	clientVMZone    = flag.String("clientVMZone", "", "clientVMZone for VM")
	clientVMId      = flag.String("clientVMId", "", "clientVMId for VM")
	autoAccept      = flag.Bool("autoAccept", false, "autoAccept configuration")

	secretsFile = flag.String("secretsFile", "", "File with []Secrets JSON struct")

	peerAddress = flag.String("peerAddress", "", "Token Client IP address")
	// SerialNumber=5 happens to be the value inside `bob/certs/tokenclient.crt`
	peerSerialNumber = flag.String("peerSerialNumber", "5", "Client Certificate Serial Number Serial Number: 5 (0x5) ")
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
	log.Printf("Found s VM ServiceAccount %#v\n", cresp.ServiceAccounts[0].Email)
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
	log.Printf("     Found  VM instanceID %#v\n", strconv.FormatUint(cresp.Id, 10))
	log.Printf("     Found  VM CreationTimestamp %#v\n", cresp.CreationTimestamp)
	log.Printf("     Found  VM Fingerprint %#v\n", cresp.Fingerprint)
	log.Printf("     Found  VM CpuPlatform %#v\n", cresp.CpuPlatform)

	for _, d := range cresp.Disks {
		log.Printf("     Found  VM Disk %#v\n", d)
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

	defer jsonFile.Close()
	byteValue, err := ioutil.ReadAll(jsonFile)
	if err != nil {
		log.Fatal(err)
	}

	var sec []Secret

	err = json.Unmarshal(byteValue, &sec)
	if err != nil {
		log.Fatal(err)
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
		Secrets:            sec,

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
