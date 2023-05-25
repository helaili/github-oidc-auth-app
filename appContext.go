package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/google/go-github/v52/github"
)

type AppContext struct {
	jwksLastUpdate    time.Time
	appTransport      *ghinstallation.AppsTransport
	configRepo        string
	configFile        string
	wellKnownURL      string
	jwksCache         []byte
	installationCache map[string]int64
	configCache       map[string]*EntitlementConfig
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

func NewAppContext(jwksLastUpdate time.Time, appTransport *ghinstallation.AppsTransport,
	configRepo string, configFile string, wellKnownURL string) *AppContext {
	installationCache := make(map[string]int64)
	configCache := make(map[string]*EntitlementConfig)

	return &AppContext{
		jwksLastUpdate, appTransport,
		configRepo, configFile, wellKnownURL,
		nil, installationCache, configCache}
}

func (appContext *AppContext) loadConfigs() error {
	client := github.NewClient(&http.Client{Transport: appContext.appTransport})
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
			config := NewEntitlementConfig(
				installation.Account.GetLogin(),
				installation.GetID(),
				appContext.configRepo,
				appContext.configFile,
			)

			err := config.load(appContext.appTransport)
			if err != nil {
				// Shall we do something with this error besides logging it? As it is, the entry is in the cache so
				// we don't try to reload a faulty configuration for each call. Users will not get a token
				log.Printf("failed to load config for installation %d on org %s with error %s\n",
					installation.GetID(), installation.Account.GetLogin(), err)
			}

			appContext.configCache[strings.ToUpper(installation.Account.GetLogin())] = config
			log.Printf("updating config cache for login %s\n", installation.Account.GetLogin())
		}
		if response.NextPage == 0 {
			break
		}
		options.Page = response.NextPage
	}
	return nil
}

func (appContext *AppContext) loadInstallationIdCache() error {
	client := github.NewClient(&http.Client{Transport: appContext.appTransport})
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
			appContext.installationCache[strings.ToUpper(installation.Account.GetLogin())] = installation.GetID()
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
func (appContext *AppContext) getInstallationID(login string) (int64, error) {
	upperLogin := strings.ToUpper(login)

	if appContext.installationCache[upperLogin] != 0 {
		return appContext.installationCache[upperLogin], nil
	} else {
		// Cache miss, retrieve all installations
		log.Printf("missed cache looking for installation for login %s\n", login)

		err := appContext.loadInstallationIdCache()
		if err != nil {
			return 0, err
		}
	}
	installationId := appContext.installationCache[upperLogin]
	if installationId == 0 {
		return 0, fmt.Errorf("no installation found for login %s", login)
	} else {
		return installationId, nil
	}
}

/*
 * Once the scope has been computed, we can connect to GitHub as an installation and retrieve a scoped token
 */
func (appContext *AppContext) generateScopedToken(scope *Scope, login string) (ScopedTokenResponse, error) {
	installationId, err := appContext.getInstallationID(login)
	if err != nil {
		return ScopedTokenResponse{Message: "no installation found"}, nil
	}

	if scope == nil || scope.isEmpty() {
		return ScopedTokenResponse{InstallationId: installationId, Message: "no scope matching these claims"}, nil
	}

	opts := &github.InstallationTokenOptions{Repositories: scope.Repositories, Permissions: &scope.Permissions}

	client := github.NewClient(&http.Client{Transport: appContext.appTransport})
	token, _, err := client.Apps.CreateInstallationToken(context.Background(), installationId, opts)
	if err != nil {
		return ScopedTokenResponse{}, err
	}

	return ScopedTokenResponse{InstallationId: installationId, ScopedToken: token.GetToken()}, nil
}

func (appContext *AppContext) handleTokenRequest(w http.ResponseWriter, req *http.Request) {
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
	claims, err := validateTokenCameFromGitHub(scopedTokenRequest.OIDCToken, appContext)
	if err != nil {
		log.Println("couldn't validate OIDC token provenance:", err)
		http.Error(w, "couldn't validate OIDC token provenance", http.StatusUnauthorized)
		return
	}

	// Token is valid. We now need to generate a new token that is specific to our use case
	config := appContext.configCache[strings.ToUpper(scopedTokenRequest.Login)]
	if config == nil {
		msg := fmt.Sprintf("no configuration found in cache for %s", scopedTokenRequest.Login)
		log.Println(msg)
		http.Error(w, msg, http.StatusNotFound)
		return
	}
	scope := config.computeScopes(claims)

	scopedTokenResponse, err := appContext.generateScopedToken(scope, scopedTokenRequest.Login)
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

/*
 * Handle http requests
 */
func (appContext *AppContext) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	// Ping method to check we are up
	if req.Method == http.MethodGet && req.RequestURI == "/ping" {
		defer req.Body.Close()

		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("Ok\n"))
		return
	}

	if req.Method == http.MethodPost && req.RequestURI == "/webhook" {
		defer req.Body.Close()
		fmt.Println("webhook received")
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("webhook\n"))
		return
	}

	if req.Method != http.MethodPost && req.RequestURI != "/token" {
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		return
	}

	appContext.handleTokenRequest(w, req)
}
