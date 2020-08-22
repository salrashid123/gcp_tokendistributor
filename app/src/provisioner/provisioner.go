package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"strconv"
	"strings"
	"time"

	"cloud.google.com/go/firestore"
	pb "github.com/google/go-tpm-tools/proto"
	"github.com/google/go-tpm-tools/server"
	"google.golang.org/api/compute/v1"

	"github.com/golang/protobuf/proto"

	"golang.org/x/net/context"
)

type ServiceEntry struct {
	Description        string    `firestore:"description,omitempty"`
	Done               bool      `firestore:"done"`
	InstanceID         string    `firestore:"instanceid"`
	ClientProject      string    `firestore:"client_project"`
	ClientZone         string    `firestore:"client_zone"`
	ServiceAccountName string    `firestore:"service_account_name"`
	InitScriptHash     string    `firestore:"init_script_hash"`
	ImageFingerprint   string    `firestore:"image_fingerprint"`
	SealedRSAKey       []byte    `firestore:"rsa_key,omitempty"`
	SealedAESKey       []byte    `firestore:"aes_key,omitempty"`
	RawKey             []byte    `firestore:"raw_key,omitempty"`
	PCR                int64     `firestore:"pcr"`
	PCRValue           string    `firestore:"pcr_value,omitempty"`
	GCSObjectReference string    `firestore:"gcs_object,omitempty"`
	ProvidedAt         time.Time `firestore:"provided_at"`
	PeerAddress        string    `firestore:"peer_address"`
	PeerSerialNumber   string    `firestore:"peer_serial_number"`
}

const (
	tpmDevice = "/dev/tpm0"
)

var (
	fireStoreProjectId      = flag.String("fireStoreProjectId", "", "ProjectID for Firestore")
	firestoreCollectionName = flag.String("firestoreCollectionName", "", "firestoreCollectionName where the sealedData is Stored")

	sealToPCR       = flag.Int64("sealToPCR", -1, "The PCR number to seal this data to where the sealedData is Stored")
	sealToPCRValue  = flag.String("sealToPCRValue", "", "The PCR Vallue to seal this data to")
	clientProjectId = flag.String("clientProjectId", "", "clientProjectId for VM")
	clientVMZone    = flag.String("clientVMZone", "", "clientVMZone for VM")
	clientVMId      = flag.String("clientVMId", "", "clientVMId for VM")
	autoAccept      = flag.Bool("autoAccept", false, "autoAccept configuration")
	useTPM          = flag.Bool("useTPM", false, "Use TPM to seal data")
	rsaKeyFile      = flag.String("rsaKeyFile", "", "RSAKey Filename")
	aesKeyFile      = flag.String("aesKeyFile", "", "AESKey FIlename")
	rawKeyFile      = flag.String("rawKeyFile", "", "RawKey FIlename")
	peerAddress     = flag.String("peerAddress", "", "Token Client IP address")
	// SerialNumber=5 happens to be the value inside `bob/certs/tokenclient.crt`
	peerSerialNumber = flag.String("peerSerialNumber", "5", "Client Certificate Serial Number Serial Number: 5 (0x5) ")
	pcrMap           = map[uint32][]byte{}
)

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
	var pcrs *pb.Pcrs
	if *sealToPCR >= 0 && *sealToPCRValue != "" {
		hv, err := hex.DecodeString(*sealToPCRValue)
		if err != nil {
			return []byte(""), err
		}
		pcrMap = map[uint32][]byte{uint32(*sealToPCR): hv}
	} else {
		pcrMap = map[uint32][]byte{}
	}
	pcrs = &pb.Pcrs{Hash: pb.HashAlgo_SHA256, Pcrs: pcrMap}

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
	var pcrs *pb.Pcrs
	if *sealToPCR >= 0 && *sealToPCRValue != "" {
		hv, err := hex.DecodeString(*sealToPCRValue)
		if err != nil {
			return []byte(""), err
		}
		pcrMap = map[uint32][]byte{uint32(*sealToPCR): hv}
	} else {
		pcrMap = map[uint32][]byte{}
	}
	pcrs = &pb.Pcrs{Hash: pb.HashAlgo_SHA256, Pcrs: pcrMap}

	blob, err := server.CreateImportBlob(ekPub, []byte(aesKey), pcrs)
	if err != nil {
		return []byte(""), err
	}
	data, err := proto.Marshal(blob)
	if err != nil {
		return []byte(""), err
	}

	//return base64.RawStdEncoding.EncodeToString(dd), nil
	return data, nil
}

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
	log.Printf("ImageStartup Hash: [%s]\n", initScriptHash)
	log.Printf("Image Fingerprint: [%s]\n", cresp.Fingerprint)

	// This is an optional check which binds the ServiceEntry to an IP address for a given VM
	// If a NAT is used, you need to specify that as teh --peerAddress= value instead
	nis := cresp.NetworkInterfaces
	for _, ni := range nis {
		for _, ac := range ni.AccessConfigs {
			if ac.Type == "ONE_TO_ONE_NAT" {
				log.Printf("Found VM External IP %s\n", ac.NatIP)
				if *peerAddress == "" {
					*peerAddress = ac.NatIP
				}
			}
		}
	}
	mresp, err := computeService.Instances.GetShieldedInstanceIdentity(*clientProjectId, *clientVMZone, *clientVMId).Do()
	if err != nil {
		log.Fatalf("Unable to find  Instance %v", err)
	}
	log.Println("Derived EKPub for Instance:")
	log.Printf(mresp.EncryptionKey.EkPub)

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

	// For testing, just generate an RSA key
	// In production, use API to generate a key:
	// https://cloud.google.com/iam/docs/creating-managing-service-account-keys#iam-service-account-keys-create-go

	var privPEM, key []byte
	var priv *rsa.PrivateKey
	if *rsaKeyFile == "" {
		log.Printf("Generating RSA Key")
		priv, _ = rsa.GenerateKey(rand.Reader, 2048)

		privPEM = pem.EncodeToMemory(
			&pem.Block{
				Type:  "RSA PRIVATE KEY",
				Bytes: x509.MarshalPKCS1PrivateKey(priv),
			},
		)
	} else {
		log.Printf("Using Existing RSA Key")
		privPEM, err = ioutil.ReadFile(*rsaKeyFile)
		if err != nil {
			log.Fatalf("Unable to Read RSAKeyFile %v\n", err)
		}

		block, _ := pem.Decode(privPEM)
		priv, _ = x509.ParsePKCS1PrivateKey(block.Bytes)

	}
	//log.Printf("RSAKey %s", privPEM)

	data := []byte("foobar")
	h := sha256.New()
	h.Write(data)
	d := h.Sum(nil)

	signed, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, d)
	if err != nil {
		log.Fatalf("Unable to sign RSA %v\n", err)
	}
	log.Printf("Sample control Signed data: %s", base64.RawStdEncoding.EncodeToString(signed))

	var sealedAES, sealedRSA []byte

	if *useTPM {
		sealedRSA, err = createSigningKeyImportBlob(mresp.EncryptionKey.EkPub, string(privPEM))
		if err != nil {
			log.Fatalf("Unable to createSigningKeyImportBlob %v", err)
		}
	} else {
		sealedRSA = privPEM
	}

	if *aesKeyFile == "" {
		log.Printf("Generating AES Key")
		key = make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, key); err != nil {
			log.Fatalf("RNG failure")
		}
	} else {
		log.Printf("Using Existing AES Key")
		key, err = ioutil.ReadFile(*aesKeyFile)
		if err != nil {
			log.Fatalf("Unable to Read AESKeyFile %v\n", err)
		}
	}

	hasher := sha256.New()
	hasher.Write(key)
	encsha := base64.StdEncoding.EncodeToString(hasher.Sum(nil))

	log.Printf("Sealed AES Key with hash: %v\n", encsha)

	var rawKey []byte
	if *rawKeyFile != "" {
		log.Printf("Adding Raw Key")
		rawKey, err = ioutil.ReadFile(*rawKeyFile)
		if err != nil {
			log.Fatalf("Unable to Read RawKeyFile %v\n", err)
		}
	}

	//log.Printf("AES KEY %s", base64.RawStdEncoding.EncodeToString(key))

	if *useTPM {
		sealedAES, err = createImportBlob(mresp.EncryptionKey.EkPub, string(key))
		if err != nil {
			log.Fatalf("Unable to find createImportBlob %v", err)
		}
		//log.Printf("Sealed RSABlob: %s", base64.RawStdEncoding.EncodeToString(sealedRSA))
	} else {
		sealedAES = key
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
		SealedRSAKey:       sealedRSA,
		SealedAESKey:       sealedAES,
		RawKey:             rawKey,
		ProvidedAt:         time.Now(),
		PCR:                0,
		PCRValue:           *sealToPCRValue,
		PeerAddress:        *peerAddress,
		PeerSerialNumber:   *peerSerialNumber,
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
