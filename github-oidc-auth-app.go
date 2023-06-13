package main

import (
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/joho/godotenv"
)

func main() {
	godotenv.Load()
	port := os.Getenv("PORT")
	private_key_base64 := os.Getenv("PRIVATE_KEY")

	private_key, err := base64.StdEncoding.DecodeString(private_key_base64)
	if err != nil {
		log.Fatal("error decoding private key", err)
	}
	app_id, err := strconv.ParseInt(os.Getenv("APP_ID"), 10, 36)
	if err != nil {
		log.Fatal("Wrong format for APP_ID")
	}

	var webhook_secret, configRepo, configFile string

	if webhook_secret = os.Getenv("WEBHOOK_SECRET"); webhook_secret == "" {
		log.Fatal("WEBHOOK_SECRET is not set")
	}

	if configRepo = os.Getenv("CONFIG_REPO"); configRepo == "" {
		configRepo = "oidc_entitlements"
	}

	configFile = os.Getenv("CONFIG_FILE")

	appTransport, err := ghinstallation.NewAppsTransport(http.DefaultTransport, app_id, private_key)
	if err != nil {
		log.Fatal("Failed to initialize GitHub App transport:", err)
	}

	wellKnownURL := "https://token.actions.githubusercontent.com/.well-known/jwks"
	gitUrl := "https://github.com"

	if ghesUrl := os.Getenv("GHES_URL"); ghesUrl != "" {
		appTransport.BaseURL = fmt.Sprintf("%s/api/v3", ghesUrl)
		wellKnownURL = fmt.Sprintf("%s/_services/token/.well-known/jwks", ghesUrl)
		gitUrl = ghesUrl
	}

	appContext := NewAppContext(time.Now(), appTransport, webhook_secret, configRepo, configFile, wellKnownURL, gitUrl)

	fmt.Println("loading config cache")
	err = appContext.loadConfigs()
	if err != nil {
		log.Println("error while loading config cache", err)
	}

	fmt.Printf("starting up on port %s\n", port)

	server := http.Server{
		Addr:         fmt.Sprintf(":%s", port),
		Handler:      appContext,
		ReadTimeout:  60 * time.Second,
		WriteTimeout: 60 * time.Second,
	}

	server.ListenAndServe()

}
