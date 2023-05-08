package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
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
	OIDCToken string `json:"oidcToken"`
	Login     string `json:"login"`
}

type ScopedTokenResponse struct {
	ScopedToken    string `json:"scopedToken"`
	InstallationId int64  `json:"installationId"`
	Message        string `json:"message"`
}

// Global array of installations used as a cache
var installationCache = make(map[string]int64)

func loadInstallationIdCache(appTransport *ghinstallation.AppsTransport) error {
	client := github.NewClient(&http.Client{Transport: appTransport})
	options := &github.ListOptions{
		PerPage: 100,
		Page:    1,
	}

	// Keep retrieving all intstallaions until we reach the last page within the response
	for {
		installations, response, err := client.Apps.ListInstallations(context.Background(), options)
		if err != nil {
			return err
		}

		for _, installation := range installations {
			installationCache[strings.ToUpper(installation.Account.GetLogin())] = installation.GetID()
			log.Printf("updating cache for login %s\n", installation.Account.GetLogin())
		}
		if response.NextPage == 0 {
			break
		}
		options.Page = response.NextPage
	}
	return nil
}

/*
 * Retrieves the installation id from the login (organization or user)
 */
func getInstallationID(appTransport *ghinstallation.AppsTransport, login string) (int64, error) {
	upperLogin := strings.ToUpper(login)

	if installationCache[upperLogin] != 0 {
		return installationCache[upperLogin], nil
	} else {
		// Cache miss, retrieve all installations
		log.Printf("missed cache looking for installation for login %s\n", login)

		err := loadInstallationIdCache(appTransport)
		if err != nil {
			return 0, err
		}
	}
	installationId := installationCache[upperLogin]
	if installationId == 0 {
		return 0, fmt.Errorf("no installation found for login %s", login)
	} else {
		return installationId, nil
	}
}

/*
 * Retrieve the entitlement config for the installation with the organisation that owns the installation.
 * Default to the .github-private repository and oidc_entitlements.yml file
 */
func getEntitlementConfig(configRepo string, configFile string, login string, appTransport *ghinstallation.AppsTransport) ([]Entitlement, error) {
	installationId, err := getInstallationID(appTransport, login)
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
func generateScopedToken(scope *Scope, login string, appTransport *ghinstallation.AppsTransport) (ScopedTokenResponse, error) {
	installationId, err := getInstallationID(appTransport, login)
	if err != nil {
		return ScopedTokenResponse{Message: "no installation found"}, nil
	}

	if scope == nil || scope.isEmpty() {
		return ScopedTokenResponse{InstallationId: installationId, Message: "no scope matching these claims"}, nil
	}

	opts := &github.InstallationTokenOptions{Repositories: scope.Repositories, Permissions: &scope.Permissions}

	client := github.NewClient(&http.Client{Transport: appTransport})
	token, _, err := client.Apps.CreateInstallationToken(context.Background(), installationId, opts)
	if err != nil {
		return ScopedTokenResponse{}, err
	}

	return ScopedTokenResponse{InstallationId: installationId, ScopedToken: token.GetToken()}, nil
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
	entitlementConfig, err := getEntitlementConfig(gatewayContext.configRepo, gatewayContext.configFile, scopedTokenRequest.Login, gatewayContext.appTransport)
	if err != nil {
		log.Println("couldn't get entitlement config", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	// Compute the entitlement for the claim
	scope := computeScopes(claims, entitlementConfig)

	scopedTokenResponse, err := generateScopedToken(scope, scopedTokenRequest.Login, gatewayContext.appTransport)
	if err != nil {
		log.Printf("failed to generate scoped tokens for claims: %v, %s\n", claims, err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	if scopedTokenResponse.ScopedToken == "" {
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
	private_key_base64 := os.Getenv("PRIVATE_KEY")

	private_key, err := base64.StdEncoding.DecodeString(private_key_base64)
	if err != nil {
		log.Fatal("error decoding private key", err)
	}
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

	appTransport, err := ghinstallation.NewAppsTransport(http.DefaultTransport, app_id, private_key)
	if err != nil {
		log.Fatal("Failed to initialize GitHub App transport:", err)
	}

	fmt.Println("loading installation id cache")
	loadInstallationIdCache(appTransport)

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
