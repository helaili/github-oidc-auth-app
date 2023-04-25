package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"time"

	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/golang-jwt/jwt"
	"github.com/google/go-github/v52/github"
	"github.com/joho/godotenv"
	"gopkg.in/yaml.v2"
)

type GatewayContext struct {
	jwksCache      []byte
	jwksLastUpdate time.Time
	appTransport   *ghinstallation.AppsTransport
}

type ScopedTokenRequest struct {
	OIDCToken      string `json:"oidcToken"`
	InstallationId int64  `json:"installationId"`
}

type ScopedTokenResponse struct {
	GitHubToken    string `json:"githubToken"`
	InstallationId int64  `json:"installationId"`
}

func getInstallationLogin(appTransport *ghinstallation.AppsTransport, installationId int64) (string, error) {
	client := github.NewClient(&http.Client{Transport: appTransport})

	// Retrieve installation
	installation, _, err := client.Apps.GetInstallation(context.Background(), installationId)
	if err != nil {
		log.Println("failed to get installation:", err)
		return "", err
	}
	return installation.Account.GetLogin(), nil
}

func getEntitlementConfig(installationId int64, appTransport *ghinstallation.AppsTransport) ([]Entitlement, error) {
	login, err := getInstallationLogin(appTransport, installationId)
	if err != nil {
		return nil, err
	}

	itr := ghinstallation.NewFromAppsTransport(appTransport, installationId)
	// Use installation transport with github.com/google/go-github
	client := github.NewClient(&http.Client{Transport: itr})

	// Retrieve the oidc_entitlements.yml file from the .github-private repository in the organization that owns the installation
	fileContent, _, _, err := client.Repositories.GetContents(context.Background(), login, ".github-private", "oidc_entitlements.yml", &github.RepositoryContentGetOptions{})
	if err != nil {
		log.Println("failed to get file oidc_entitlements.yml in repository .github-private:", err)
		return nil, err
	}

	// Get the content of the oidc_entitlements.yml file as a string
	content, err := fileContent.GetContent()
	if err != nil {
		log.Println("failed to get content of file oidc_entitlements.yml in repository .github-private:", err)
		return nil, err
	}

	// Parse the oidc_entitlements.yml file as YAML
	var entitlements []Entitlement
	err = yaml.Unmarshal([]byte(content), &entitlements)
	if err != nil {
		log.Println("failed to unmarshal content of file oidc_entitlements.yml in repository .github-private:", err)
		return nil, err
	}
	return entitlements, nil
}

func computeScopes(claims jwt.MapClaims, entitlementConfig []Entitlement) *Scope {
	scope := NewScope()

	strMapClaims := stringifyMapClaims(claims)

	for _, entitlement := range entitlementConfig {
		match, _ := regexp.MatchString(entitlement.regexString(), strMapClaims)
		if match {
			scope.merge(entitlement.Scopes)
		}
	}

	return scope
}

func generateScopedToken(scope *Scope, installationId int64, appTransport *ghinstallation.AppsTransport) (ScopedTokenResponse, error) {
	opts := &github.InstallationTokenOptions{Repositories: scope.Repositories, Permissions: &scope.Permissions}
	// opts := &github.InstallationTokenOptions{}

	client := github.NewClient(&http.Client{Transport: appTransport})
	token, _, err := client.Apps.CreateInstallationToken(context.Background(), installationId, opts)
	if err != nil {
		log.Println("failed to get scoped token:", err)
		return ScopedTokenResponse{}, err
	}

	return ScopedTokenResponse{InstallationId: installationId, GitHubToken: token.GetToken()}, nil
}

func (gatewayContext *GatewayContext) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	// Ping method to check we are up
	if req.Method == http.MethodGet && req.RequestURI == "/ping" {
		defer req.Body.Close()

		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("Ok\n"))
		return
	}

	if req.Method != http.MethodPost && req.RequestURI != "/token" {
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		return
	}

	defer req.Body.Close()

	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		log.Println("Error retrieving request body.", err)
		http.Error(w, http.StatusText(http.StatusNoContent), http.StatusNoContent)
		return
	}

	var scopedTokenRequest ScopedTokenRequest
	err = json.Unmarshal([]byte(body), &scopedTokenRequest)
	if err != nil {
		log.Println("Error unmarshaling data from request.", err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	log.Println(scopedTokenRequest.OIDCToken)

	// Check that the OIDC token verifies as a valid token from GitHub
	claims, err := validateTokenCameFromGitHub(scopedTokenRequest.OIDCToken, gatewayContext)
	if err != nil {
		log.Println(err)
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}

	// Token is valid. We now need to generate a new token that is specific to our use case
	// Retrieve the entitlement config for the installation
	entitlementConfig, err := getEntitlementConfig(scopedTokenRequest.InstallationId, gatewayContext.appTransport)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	// Compute the entitlement for the claim
	scope := computeScopes(claims, entitlementConfig)

	scopedTokenResponse, err := generateScopedToken(scope, scopedTokenRequest.InstallationId, gatewayContext.appTransport)
	if err != nil {
		log.Println(err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	log.Println(scopedTokenResponse)

	// Return the new token to the client
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(scopedTokenResponse)
}

func main() {
	godotenv.Load()
	port := os.Getenv("PORT")
	private_key := os.Getenv("PRIVATE_KEY")
	app_id, err := strconv.ParseInt(os.Getenv("APP_ID"), 10, 36)
	if err != nil {
		log.Fatal("Wrong format for APP_ID")
	}

	fmt.Printf("starting up on port %s\n", port)

	appTransport, err := ghinstallation.NewAppsTransport(http.DefaultTransport, app_id, []byte(private_key))
	if err != nil {
		log.Fatal("Failed to initialize GitHub App transport:", err)
	}

	gatewayContext := &GatewayContext{jwksLastUpdate: time.Now(), appTransport: appTransport}

	server := http.Server{
		Addr:         fmt.Sprintf(":%s", port),
		Handler:      gatewayContext,
		ReadTimeout:  60 * time.Second,
		WriteTimeout: 60 * time.Second,
	}

	server.ListenAndServe()

}
