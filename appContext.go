package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
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
	installationCache *InstallationCache
	configCache       *ConfigCache
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
	installationCache := NewInstallationCache()
	configCache := NewConfigCache()

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
			if installation.GetSuspendedBy() == nil {
				appContext.loadConfig(installation.Account.GetLogin(), installation.GetID())
				appContext.installationCache.SetInstallationId(installation.Account.GetLogin(), installation.GetID())
			}
		}
		if response.NextPage == 0 {
			break
		}
		options.Page = response.NextPage
	}
	return nil
}

func (appContext *AppContext) loadConfig(login string, installationId int64) error {
	config := NewEntitlementConfig(login, installationId, appContext.configRepo, appContext.configFile)

	err := config.load(appContext.appTransport)
	if err != nil {
		// Shall we do something with this error besides logging it? As it is, the entry is in the cache so
		// we don't try to reload a faulty configuration for each call. Users will not get a token
		log.Printf("failed to load config for installation %d on org %s with error %s\n", installationId, login, err)
	}

	appContext.configCache.SetConfig(login, config)
	log.Printf("updating config cache for login %s\n", login)

	return nil
}

/*
 * Once the scope has been computed, we can connect to GitHub as an installation and retrieve a scoped token
 */
func (appContext *AppContext) generateScopedToken(scope *Scope, login string) (ScopedTokenResponse, error) {
	installationId := appContext.installationCache.GetInstallationId(login)
	if installationId == 0 {
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

/*
 * Received a request to deliver a scoped token for a given OIDC token
 */
func (appContext *AppContext) handleTokenRequest(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()

	body, err := io.ReadAll(req.Body)
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
	config := appContext.configCache.GetConfig(scopedTokenRequest.Login)
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
 * This function is called when a push event is received from GitHub.
 * It might mean the configuration has changed and need to be reloaded.
 */
func (appContext *AppContext) processPushEvent(event github.PushEvent) {
	if appContext.checkConfigChange(event) {
		log.Printf("reloading config for organization %s\n", event.GetRepo().GetOwner().GetLogin())
		appContext.loadConfig(event.GetRepo().GetOwner().GetLogin(), event.Installation.GetID())
	}
}

/*
 * Checking if the configuration has changed
 */
func (appContext *AppContext) checkConfigChange(event github.PushEvent) bool {
	// Check if the push event is for the main or master branch.
	// We are not at this time trying to figure out what the default branch is
	branch := event.GetRef()
	if branch != "refs/heads/main" && branch != "refs/heads/master" {
		return false
	}

	// Check if the push event is for the config repo
	if appContext.configRepo == event.GetRepo().GetName() {
		if appContext.configFile != "" {
			// Config is single file based.
			// Check if the config file is part of one of the commits within this push event
			for _, commit := range event.Commits {
				var fileArrays = [][]string{commit.Added, commit.Removed, commit.Modified}
				for _, files := range fileArrays {
					for _, file := range files {
						if file == appContext.configFile {
							return true
						}
					}
				}
			}
		} else {
			// Config is repo based, so we need to reload the config regardless of the files that were pushed
			return true
		}
	}
	return false
}

func (appContext *AppContext) processInstallationEvent(event github.InstallationEvent) {
	login := event.GetInstallation().GetAccount().GetLogin()
	id := event.GetInstallation().GetID()
	log.Printf("%s event for installation %d on org %s\n", event.GetAction(), id, login)

	if event.GetAction() == "deleted" || event.GetAction() == "suspend" {
		appContext.configCache.DeleteConfig(login)
	} else if event.GetAction() == "created" || event.GetAction() == "unsuspend" {
		appContext.loadConfig(login, id)
		appContext.installationCache.SetInstallationId(login, id)
	}

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
		payload, err := github.ValidatePayload(req, nil)
		if err != nil {
			log.Println("failed to validate webhook payload:", err)
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		event, err := github.ParseWebHook(github.WebHookType(req), payload)
		if err != nil {
			log.Println("failed to parse webhook payload:", err)
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		switch event := event.(type) {
		case *github.PushEvent:
			appContext.processPushEvent(*event)
			return
		case *github.InstallationEvent:
			appContext.processInstallationEvent(*event)
			return
		}

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
