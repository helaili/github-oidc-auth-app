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
	configRepo     string
	configFile     string
}

type ScopedTokenRequest struct {
	OIDCToken      string `json:"oidcToken"`
	InstallationId int64  `json:"installationId"`
}

type ScopedTokenResponse struct {
	GitHubToken    string `json:"githubToken"`
	InstallationId int64  `json:"installationId"`
	Message        string `json:"message"`
}

/*
 * Retrieves the login (aka organization name) of the installation with the given id
 */
func getInstallationLogin(appTransport *ghinstallation.AppsTransport, installationId int64) (string, error) {
	// TODO: cache this
	client := github.NewClient(&http.Client{Transport: appTransport})

	// Retrieve installation
	installation, _, err := client.Apps.GetInstallation(context.Background(), installationId)
	if err != nil {
		return "", err
	}
	return installation.Account.GetLogin(), nil
}

/*
 * Retrieve the entitlement config for the installation with the organisation that owns the installation.
 * Default to the .github-private repository and oidc_entitlements.yml file
 */
func getEntitlementConfig(configRepo string, configFile string, installationId int64, appTransport *ghinstallation.AppsTransport) ([]Entitlement, error) {
	login, err := getInstallationLogin(appTransport, installationId)
	if err != nil {
		return nil, err
	}

	itr := ghinstallation.NewFromAppsTransport(appTransport, installationId)
	// Use installation transport with github.com/google/go-github
	client := github.NewClient(&http.Client{Transport: itr})

	// Retrieve the oidc_entitlements.yml file from the .github-private repository in the organization that owns the installation
	fileContent, _, _, err := client.Repositories.GetContents(context.Background(), login, configRepo, configFile, &github.RepositoryContentGetOptions{})
	if err != nil {
		return nil, err
	}

	// Get the content of the oidc_entitlements.yml file as a string
	content, err := fileContent.GetContent()
	if err != nil {
		return nil, err
	}

	// Parse the oidc_entitlements.yml file as YAML
	var entitlements []Entitlement
	err = yaml.Unmarshal([]byte(content), &entitlements)
	if err != nil {
		return nil, err
	}
	return entitlements, nil
}

/*
 * Several configs could match the claims. We need to merge the scopes of all matching configs into a single scope.
 * This is done by merging the repositories and permissions of all matching configs. In case of conflict, the highest permission is kept (admin > write > read)
 */
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

/*
 * Once the scope has been computed, we can connect to GitHub as an installation and retrieve a scoped token
 */
func generateScopedToken(scope *Scope, installationId int64, appTransport *ghinstallation.AppsTransport) (ScopedTokenResponse, error) {
	if scope == nil || scope.isEmpty() {
		return ScopedTokenResponse{InstallationId: installationId, Message: "no scope matching these claims"}, nil
	}

	opts := &github.InstallationTokenOptions{Repositories: scope.Repositories, Permissions: &scope.Permissions}

	client := github.NewClient(&http.Client{Transport: appTransport})
	token, _, err := client.Apps.CreateInstallationToken(context.Background(), installationId, opts)
	if err != nil {
		return ScopedTokenResponse{}, err
	}

	return ScopedTokenResponse{InstallationId: installationId, GitHubToken: token.GetToken()}, nil
}

/*
 * Handle http requests
 */
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
		http.Error(w, http.StatusText(http.StatusNoContent), http.StatusNoContent)
		return
	}

	var scopedTokenRequest ScopedTokenRequest
	err = json.Unmarshal([]byte(body), &scopedTokenRequest)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	// Check that the OIDC token verifies as a valid token from GitHub
	claims, err := validateTokenCameFromGitHub(scopedTokenRequest.OIDCToken, gatewayContext)
	if err != nil {
		log.Println("couldn't validate OIDC token provenance", err)
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}

	// Token is valid. We now need to generate a new token that is specific to our use case
	// Retrieve the entitlement config for the installation
	entitlementConfig, err := getEntitlementConfig(gatewayContext.configRepo, gatewayContext.configFile, scopedTokenRequest.InstallationId, gatewayContext.appTransport)
	if err != nil {
		log.Println("couldn't get entitlement config", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	// Compute the entitlement for the claim
	scope := computeScopes(claims, entitlementConfig)

	scopedTokenResponse, err := generateScopedToken(scope, scopedTokenRequest.InstallationId, gatewayContext.appTransport)
	if err != nil {
		log.Printf("failed to generate scoped tokens for claims: %v, %s\n", claims, err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	if scopedTokenResponse.GitHubToken != "" {
		log.Printf("no token generated for claims: %v\n", claims)
	} else {
		log.Printf("succesfully generated token for claims: %v, with scopes %s\n", claims, scope.String())
	}

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
	var configRepo, configFile string
	if configRepo = os.Getenv("CONFIG_REPO"); configRepo == "" {
		configRepo = ".github-private"
	}
	if configFile = os.Getenv("CONFIG_FILE"); configFile == "" {
		configFile = "oidc_entitlements.yml"
	}

	log.Println(private_key)

	appTransport, err := ghinstallation.NewAppsTransport(http.DefaultTransport, app_id, []byte(private_key))
	if err != nil {
		log.Fatal("Failed to initialize GitHub App transport:", err)
	}

	fmt.Printf("starting up on port %s\n", port)

	gatewayContext := &GatewayContext{
		jwksLastUpdate: time.Now(),
		appTransport:   appTransport,
		configRepo:     configRepo,
		configFile:     configFile,
	}

	server := http.Server{
		Addr:         fmt.Sprintf(":%s", port),
		Handler:      gatewayContext,
		ReadTimeout:  60 * time.Second,
		WriteTimeout: 60 * time.Second,
	}

	server.ListenAndServe()

}
