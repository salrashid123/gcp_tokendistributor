package main

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"oid"
	tspb "tokenservice"

	"cloud.google.com/go/firestore"

	"github.com/golang/protobuf/jsonpb"
	tpmpb "github.com/google/go-tpm-tools/proto"
	"github.com/google/go-tpm-tools/server"
	"google.golang.org/api/compute/v1"

	"github.com/golang/protobuf/proto"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/net/context"
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
	pubECert := ekKeys.EncryptionKey.EkCert
	pubSKey := ekKeys.SigningKey.EkPub
	pubSCert := ekKeys.SigningKey.EkCert

	if pubECert != "" {
		block, _ := pem.Decode([]byte(pubECert))
		if block == nil {
			panic("failed to parse certificate PEM")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			panic("failed to parse certificate: " + err.Error())
		}
		e, err := NewEKCertificate(cert)
		if err != nil {
			panic(err)
		}
		log.Println("VM InstanceID from EKCert Encryption: ", e.gceInstanceID)

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
		e, err := NewEKCertificate(cert)
		if err != nil {
			panic(err)
		}
		log.Println("VM InstanceID from EKCert Signing: ", e.gceInstanceID)
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

		EKEncryptionCert: pubECert, // currently null
		EKEncryptionKey:  pubEKey,  // currently null
		AKSigningCert:    pubSCert,
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

var (
	versionRE         = regexp.MustCompile("^id:[0-9a-fA-F]{8}$")
	infineonVersionRE = regexp.MustCompile("^id:[0-9a-fA-F]{4}$")
	nuvotonVersionRE  = regexp.MustCompile("^id:[0-9a-fA-F]{2}$")
)

type attributeTypeAndValue struct {
	Type  asn1.ObjectIdentifier
	Value asn1.RawValue
}

type tpmSpecification struct {
	Family   string
	Level    int
	Revision int
}

type GCEInstanceID struct {
	Zone          string
	ProjectNumber int
	ProjectID     string
	InstanceID    int
	InstanceName  string
}

type EKCertificate struct {
	*x509.Certificate
	tpmManufacturer, tpmModel, tpmVersion string
	tpmSpecification                      tpmSpecification
	gceInstanceID                         GCEInstanceID
}

// Fingerprint returns a unique representation of an EK certificate.
func (e EKCertificate) Fingerprint() string {
	b := sha256.Sum256(e.Raw)
	return hex.EncodeToString(b[:])
}

// Manufacturer returns the TPM manufacturer.
func (e EKCertificate) Manufacturer() string {
	return e.tpmManufacturer
}

// Model returns the TPM model.
func (e EKCertificate) Model() string {
	return e.tpmModel
}

// Version returns the TPM firmware version.
func (e EKCertificate) Version() string {
	return e.tpmVersion
}

// SpecificationFamily returns the TPM specification family.
func (e EKCertificate) SpecificationFamily() string {
	return e.tpmSpecification.Family
}

// SpecificationLevel returns the TPM specification level.
func (e EKCertificate) SpecificationLevel() int {
	return e.tpmSpecification.Level
}

// SpecificationRevision returns the TPM specification revision.
func (e EKCertificate) SpecificationRevision() int {
	return e.tpmSpecification.Revision
}

// GCEInstanceID ...
func (e EKCertificate) GCEInstanceID() GCEInstanceID {
	return e.gceInstanceID
}

// ToPEM returns the EK certificate PEM encoded.
func (e EKCertificate) ToPEM() string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "X509 CERTIFICATE", Bytes: e.Raw}))
}

func parseSubjectAltName(ext pkix.Extension) (dirName pkix.RDNSequence, otherName cryptobyte.String, err error) {
	err = forEachSAN(ext.Value, func(tag int, data []byte) error {
		switch tag {
		case 0:
			otherName = cryptobyte.String(data)
		case 4:
			if _, err := asn1.Unmarshal(data, &dirName); err != nil {
				return err
			}
		default:
			return fmt.Errorf("expected tag %d", tag)
		}
		return nil
	})
	return
}

// Borrowed from the x509 package.
func forEachSAN(extension []byte, callback func(tag int, data []byte) error) error {
	var seq asn1.RawValue
	rest, err := asn1.Unmarshal(extension, &seq)
	if err != nil {
		return err
	} else if len(rest) != 0 {
		return errors.New("x509: trailing data after X.509 extension")
	}
	if !seq.IsCompound || seq.Tag != 16 || seq.Class != 0 {
		return asn1.StructuralError{Msg: "bad SAN sequence"}
	}

	rest = seq.Bytes
	for len(rest) > 0 {
		var v asn1.RawValue
		rest, err = asn1.Unmarshal(rest, &v)
		if err != nil {
			return err
		}

		if err := callback(v.Tag, v.Bytes); err != nil {
			return err
		}
	}

	return nil
}

func parseName(name pkix.RDNSequence) (string, string, string, error) {
	var tpmManufacturer, tpmModel, tpmVersion string
	var err error
	for _, rdn := range name {
		for _, attr := range rdn {
			if attr.Type.Equal(oid.TPMManufacturer) {
				tpmManufacturer = fmt.Sprintf("%v", attr.Value)
				continue
			}
			if attr.Type.Equal(oid.TPMModel) {
				tpmModel = fmt.Sprintf("%v", attr.Value)
				continue
			}
			if attr.Type.Equal(oid.TPMVersion) {
				if tpmVersion, err = versionFix(fmt.Sprintf("%v", attr.Value)); err != nil {
					return tpmManufacturer, tpmModel, tpmVersion, err
				}
				continue
			}
			return tpmManufacturer, tpmModel, tpmVersion, fmt.Errorf("unknown attribute type: %v", attr.Type)
		}
	}
	return tpmManufacturer, tpmModel, tpmVersion, nil
}

func versionFix(tpmVersion string) (string, error) {
	if infineonVersionRE.MatchString(tpmVersion) {
		major, err := hex.DecodeString(tpmVersion[3:5])
		if err != nil {
			return "", err
		}
		minor, err := hex.DecodeString(tpmVersion[5:7])
		if err != nil {
			return "", err
		}
		tpmVersion = fmt.Sprintf("id:%04X%04X", major, minor)
	}
	if nuvotonVersionRE.MatchString(tpmVersion) {
		major, err := hex.DecodeString(tpmVersion[3:5])
		if err != nil {
			return "", err
		}
		tpmVersion = fmt.Sprintf("id:%04X0000", major)
	}
	return tpmVersion, nil
}

func parseGCEInstanceID(ext pkix.Extension) (out GCEInstanceID, err error) {
	_, err = asn1.Unmarshal(ext.Value, &out)
	return
}

func parseTPMSpecification(SubjectDirectoryAttributes []attributeTypeAndValue) (tpmSpecification, error) {
	for _, attr := range SubjectDirectoryAttributes {
		if attr.Type.Equal(oid.TPMSpecification) {
			var spec tpmSpecification
			rest, err := asn1.Unmarshal(attr.Value.Bytes, &spec)
			if err != nil {
				return tpmSpecification{}, err
			}
			if len(rest) != 0 {
				return tpmSpecification{}, errors.New("trailing data after TPMSpecification")
			}
			return spec, nil
		}
	}
	return tpmSpecification{}, errors.New("TPMSpecification not present")
}

func parseSubjectDirectoryAttributes(ext pkix.Extension) ([]attributeTypeAndValue, error) {
	var attrs []attributeTypeAndValue
	rest, err := asn1.Unmarshal(ext.Value, &attrs)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, errors.New("trailing data after X.509 extension")
	}
	return attrs, nil
}
func ParseEKCertificate(asn1Data []byte) (*EKCertificate, error) {
	cert, err := x509.ParseCertificate(asn1Data)
	if err != nil {
		return nil, err
	}
	return NewEKCertificate(cert)
}

func NewEKCertificate(cert *x509.Certificate) (*EKCertificate, error) {
	var spec tpmSpecification
	var tpmManufacturer, tpmModel, tpmVersion string
	var gceInstanceID GCEInstanceID
	var err error
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oid.SubjectAltName) {
			directoryName, _, err := parseSubjectAltName(ext)
			if err != nil {
				return nil, err
			}
			tpmManufacturer, tpmModel, tpmVersion, err = parseName(directoryName)
			if err != nil {
				return nil, err
			}
		}
		if ext.Id.Equal(oid.SubjectDirectoryAttributes) {
			subjectDirectoryAttributes, err := parseSubjectDirectoryAttributes(ext)
			if err != nil {
				return nil, err
			}
			if spec, err = parseTPMSpecification(subjectDirectoryAttributes); err != nil {
				return nil, err
			}
		}
		if ext.Id.Equal(oid.CloudComputeInstanceIdentifier) {
			if gceInstanceID, err = parseGCEInstanceID(ext); err != nil {
				return nil, err
			}
		}
	}
	if !versionRE.MatchString(tpmVersion) {
		return nil, fmt.Errorf("invalid TPM version %q", tpmVersion)
	}
	return &EKCertificate{cert, tpmManufacturer, tpmModel, tpmVersion, spec, gceInstanceID}, nil
}
