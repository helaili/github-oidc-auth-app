package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"regexp"

	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/go-github/v52/github"
)

type EntitlementConfig struct {
	Login          string
	InstallationId int64
	Repo           string
	File           string
	Entitlements   []Entitlement
}

func NewEntitlementConfig(Login string, InstallationId int64, Repo, File string) *EntitlementConfig {
	entitlements := make([]Entitlement, 0)
	return &EntitlementConfig{Login, InstallationId, Repo, File, entitlements}
}

func (config *EntitlementConfig) load(appTransport *ghinstallation.AppsTransport) error {
	log.Printf("loading config for org %s\n", config.Login)
	itr := ghinstallation.NewFromAppsTransport(appTransport, config.InstallationId)
	// Use installation transport with github.com/google/go-github
	client := github.NewClient(&http.Client{Transport: itr})

	// Retrieve the oidc_entitlements.json file from the .github-private repository in the organization that owns the installation
	fileContent, _, _, err := client.Repositories.GetContents(context.Background(), config.Login, config.Repo, config.File, &github.RepositoryContentGetOptions{})
	if err != nil {
		log.Println("couldn't download file")
		return err
	}

	// Get the content of the oidc_entitlements.json file as a string
	content, err := fileContent.GetContent()
	if err != nil {
		log.Println("couldn't get file content as string")
		return err
	}

	// Parse the oidc_entitlements.json file as JSON
	err = json.Unmarshal([]byte(content), &(config.Entitlements))
	if err != nil {
		log.Printf("failed to parse JSON file %s", config.File)
		return err
	}
	log.Printf("Loaded %d entitlements for org %s", len(config.Entitlements), config.Login)
	return nil
}

/*
 * Several configs could match the claims. We need to merge the scopes of all matching configs into a single scope.
 * This is done by merging the repositories and permissions of all matching configs. In case of conflict, the highest permission is kept (admin > write > read)
 */
func (config *EntitlementConfig) computeScopes(claims jwt.MapClaims) *Scope {
	scope := NewScope()

	strMapClaims := stringifyMapClaims(claims)

	for _, entitlement := range config.Entitlements {
		match, _ := regexp.MatchString(entitlement.regexString(), strMapClaims)
		if match {
			scope.merge(entitlement.Scopes)
		}
	}
	return scope
}
