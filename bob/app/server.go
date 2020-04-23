package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"cloud.google.com/go/storage"
	sal "github.com/salrashid123/oauth2/google"
	"golang.org/x/net/context"
	"golang.org/x/net/http2"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/option"
)

const (
	targetAudience = "https://verifier-nvm6vsykba-uc.a.run.app"
	url            = "https://verifier-nvm6vsykba-uc.a.run.app/verify"
	bucketName     = "alice-275112-shared-bucket"
	objectName     = "secret.txt"
)

var (
	sad   = ":("
	happy = ":)"
)

type AlicesMessage struct {
	AESKey string `json:"aes_key"`
	RSAKey string `json:"rsa_key"`
}

func fronthandler(w http.ResponseWriter, r *http.Request) {
	log.Println("/ called")
	var message string

	scopes := "https://www.googleapis.com/auth/userinfo.email"
	ctx := context.Background()
	creds, err := google.FindDefaultCredentials(ctx, scopes)
	idTokenSource, err := sal.IdTokenSource(
		&sal.IdTokenConfig{
			Credentials: creds,
			Audiences:   []string{targetAudience},
			GCEExtension: sal.GCEExtension{
				Format: "full",
			},
		},
	)
	client := &http.Client{
		Transport: &oauth2.Transport{
			Source: idTokenSource,
		},
	}

	resp, err := client.Get(url)
	if err != nil {
		http.Error(w, sad, http.StatusInternalServerError)
	}
	log.Printf("Response: %v", resp.Status)
	if err != nil {
		http.Error(w, sad, http.StatusInternalServerError)
	}
	if resp.StatusCode == http.StatusOK {

		secrets := AlicesMessage{}

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Printf("%s unable to read struct from verifier... %v")
			http.Error(w, fmt.Sprintf("%s unable to read struct from verifier... %v", sad, err), http.StatusInternalServerError)
			return
		}

		err = json.Unmarshal(body, &secrets)
		if err != nil {
			log.Printf("%s unable to read struct... %v", sad, err)
			http.Error(w, fmt.Sprintf("%s unable to read struct... %v", sad, err), http.StatusInternalServerError)
			return
		}

		data, err := base64.StdEncoding.DecodeString(secrets.RSAKey)
		if err != nil {
			log.Printf("%s unable to decode RSAKey... %v", sad, err)
			http.Error(w, fmt.Sprintf("%s unable to decode RSAKey... %v", sad, err), http.StatusInternalServerError)
			return
		}

		ctx := context.Background()

		creds, err := google.CredentialsFromJSON(ctx, data, "https://www.googleapis.com/auth/devstorage.read_only")
		if err != nil {
			http.Error(w, sad+" unable to parse RSA Secret ", http.StatusInternalServerError)
			return
		}

		storageClient, err := storage.NewClient(ctx, option.WithTokenSource(creds.TokenSource))
		bkt := storageClient.Bucket(bucketName)
		obj := bkt.Object(objectName)
		var rr *storage.Reader

		rr, err = obj.NewReader(ctx)
		if err != nil {
			http.Error(w, sad+" unable to create gcs reader", http.StatusInternalServerError)
			return
		}
		defer rr.Close()
		gdata, err := ioutil.ReadAll(rr)
		if err != nil {
			http.Error(w, sad+" unable to read gcs file ", http.StatusInternalServerError)
			return
		}
		message = happy + " AES Key [" + secrets.AESKey + "]" + "       GCS Data [" + string(gdata) + "]"

	} else {
		http.Error(w, fmt.Sprintf("%s  unable to connect to verifier...got Status %v", sad, resp.StatusCode), http.StatusInternalServerError)
		return
	}
	fmt.Fprint(w, message)
}

func healthhandler(w http.ResponseWriter, r *http.Request) {
	log.Println("heathcheck...")
	fmt.Fprint(w, "ok")
}

func main() {

	http.HandleFunc("/", fronthandler)
	http.HandleFunc("/_ah/health", healthhandler)

	srv := &http.Server{
		Addr: ":8080",
	}
	http2.ConfigureServer(srv, &http2.Server{})
	err := srv.ListenAndServe()
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}
