package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/lestrrat/go-jwx/jwk"
	"golang.org/x/net/http2"

	"os"

	"github.com/gorilla/mux"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	secretmanagerpb "google.golang.org/genproto/googleapis/cloud/secretmanager/v1"
)

type AlicesMessage struct {
	AESKey string `json:"aes_key"`
	RSAKey string `json:"rsa_key"`
}

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

type contextKey string

const (
	jwksURL = "https://www.googleapis.com/oauth2/v3/certs"
)

var (
	sad   = ":("
	happy = ":)"

	myAudience         = os.Getenv("VERIFIER_AUDIENCE")
	bobsServiceAccount = os.Getenv("BOBS_VM_SERVICE_ACCOUNT")
	aliceProjectID     = os.Getenv("ALICE_PROJECT_ID")

	jwtSet *jwk.Set
)

func getKey(token *jwt.Token) (interface{}, error) {
	keyID, ok := token.Header["kid"].(string)
	if !ok {
		return nil, errors.New("expecting JWT header to have string kid")
	}
	if key := jwtSet.LookupKeyID(keyID); len(key) == 1 {
		return key[0].Materialize()
	}
	return nil, errors.New("unable to find key")
}

func verifyGoogleIDToken(ctx context.Context, aud string, rawToken string) (gcpIdentityDoc, error) {
	token, err := jwt.ParseWithClaims(rawToken, &gcpIdentityDoc{}, getKey)
	if err != nil {
		log.Printf("Error parsing JWT %v", err)
		return gcpIdentityDoc{}, err
	}
	if claims, ok := token.Claims.(*gcpIdentityDoc); ok && token.Valid {
		log.Printf("OIDC doc has Audience [%s]   Issuer [%v]", claims.Audience, claims.StandardClaims.Issuer)
		return *claims, nil
	}
	return gcpIdentityDoc{}, errors.New("Error parsing JWT Claims")
}

func verifyhandler(w http.ResponseWriter, r *http.Request) {
	log.Println("/verify called")

	authHeader := r.Header.Get("Authorization")

	if authHeader == "" {
		http.Error(w, sad, http.StatusUnauthorized)
		return
	}
	splitToken := strings.Split(authHeader, "Bearer")
	if len(splitToken) > 0 {
		tok := strings.TrimSpace(splitToken[1])
		idDoc, err := verifyGoogleIDToken(r.Context(), myAudience, tok)
		if err != nil {
			http.Error(w, sad, http.StatusUnauthorized)
			return
		}
		log.Printf("Authenticated email: %v", idDoc.Email)

		if idDoc.Email != bobsServiceAccount {
			log.Printf("Authorized origin email does not match email in Identity Document")
			http.Error(w, sad, http.StatusInternalServerError)
			return
		}

		ctx := context.Background()

		client, err := secretmanager.NewClient(ctx)
		if err != nil {
			log.Printf("failed to create secretmanager client: %v", err)
			http.Error(w, sad, http.StatusInternalServerError)
			return
		}

		aes_name := fmt.Sprintf("projects/%s/secrets/%s/versions/latest", aliceProjectID, "aes-"+idDoc.Google.ComputeEngine.InstanceID)
		aes_req := &secretmanagerpb.AccessSecretVersionRequest{
			Name: aes_name,
		}

		aes_result, err := client.AccessSecretVersion(ctx, aes_req)
		if err != nil {
			log.Printf("failed to access aes secret version: %v", err)
			http.Error(w, sad, http.StatusInternalServerError)
			return
		}

		rsa_name := fmt.Sprintf("projects/%s/secrets/%s/versions/latest", aliceProjectID, "rsa-"+idDoc.Google.ComputeEngine.InstanceID)
		rsa_req := &secretmanagerpb.AccessSecretVersionRequest{
			Name: rsa_name,
		}

		rsa_result, err := client.AccessSecretVersion(ctx, rsa_req)
		if err != nil {
			log.Printf("failed to access rsa secret version: %v", err)
			http.Error(w, sad, http.StatusInternalServerError)
			return
		}
		myHardCodedSecrets := map[string]AlicesMessage{
			idDoc.Google.ComputeEngine.InstanceID: AlicesMessage{
				AESKey: string(aes_result.Payload.Data),
				RSAKey: string(rsa_result.Payload.Data),
			},
		}
		m, err := json.Marshal(myHardCodedSecrets[idDoc.Google.ComputeEngine.InstanceID])
		if err != nil {
			http.Error(w, sad, http.StatusInternalServerError)
			return
		}
		fmt.Fprint(w, string(m))
		return
	}
	http.Error(w, sad, http.StatusUnauthorized)
}

func defaulthandler(w http.ResponseWriter, r *http.Request) {
	log.Println("heathcheck...")
	fmt.Fprint(w, "ok")
}

func main() {

	var err error
	jwtSet, err = jwk.FetchHTTP(jwksURL)
	if err != nil {
		log.Fatal("Unable to load JWK Set: ", err)
	}

	r := mux.NewRouter()

	r.HandleFunc("/verify", verifyhandler)
	r.HandleFunc("/", defaulthandler)
	http.Handle("/", r)

	srv := &http.Server{
		Addr: ":8080",
	}
	http2.ConfigureServer(srv, &http2.Server{})
	err = srv.ListenAndServe()
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}
