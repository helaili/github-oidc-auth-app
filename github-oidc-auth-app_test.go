package main

import (
	"os"
	"reflect"
	"testing"

	"github.com/golang-jwt/jwt"
	"github.com/google/go-github/v52/github"
	"gopkg.in/yaml.v2"
)

func TestExactRegexEntitlement(t *testing.T) {
	entitlement := Entitlement{
		Actor:       "helaili",
		Environment: "production",
		EventName:   "workflow_dispatch",
		Ref:         "refs/heads/main",
		Repository:  "helaili/github-oidc-auth-app",
		Owner:       "helaili",
		Visibility:  "public",
		Workflow:    "Manual Test Workflow",
	}
	entitlementRegex := entitlement.regexString()
	if entitlementRegex != "^actor:helaili,environment:production,event_name:workflow_dispatch,ref:refs/heads/main,repository:helaili/github-oidc-auth-app,repository_owner:helaili,repository_visibility:public,workflow:Manual Test Workflow$" {
		t.Error("Expected entitlementRegex to be ^actor:helaili,environment:production,event_name:workflow_dispatch,ref:refs/heads/main,repository:helaili/github-oidc-auth-app,repository_owner:helaili,repository_visibility:public,workflow:Manual Test Workflow$, but got", entitlementRegex)
	}
}

func TestFuzzyRegexEntitlement(t *testing.T) {
	entitlement := Entitlement{
		Environment: "production",
		EventName:   "workflow_dispatch",
		Ref:         "refs/heads/main",
		Owner:       "helaili",
		Visibility:  "public",
	}
	entitlementRegex := entitlement.regexString()
	if entitlementRegex != "^actor:.*,environment:production,event_name:workflow_dispatch,ref:refs/heads/main,repository:.*,repository_owner:helaili,repository_visibility:public,workflow:.*$" {
		t.Error("Expected entitlementRegex to be ^actor:.*,environment:production,event_name:workflow_dispatch,ref:refs/heads/main,repository:.*,repository_owner:helaili,repository_visibility:public,workflow:.*$, but got", entitlementRegex)
	}
}

func TestComputeSimpleEntitlements(t *testing.T) {
	//Load the sample config file as a string
	b, err := os.ReadFile("test/precise-match.yml") // just pass the file name
	if err != nil {
		t.Fatal(err)
	}

	content := string(b) // convert content to a 'string'
	var entitlementConfig []Entitlement
	err = yaml.Unmarshal([]byte(content), &entitlementConfig)
	if err != nil {
		t.Fatal(err)
	}

	claims := jwt.MapClaims{
		"actor":                 "helaili",
		"environment":           "production",
		"event_name":            "workflow_dispatch",
		"ref":                   "refs/heads/main",
		"repository":            "helaili/github-oidc-auth-app",
		"repository_owner":      "helaili",
		"repository_visibility": "public",
		"workflow":              "Manual Test Workflow",
	}

	// Compute the scope for the claims
	scope := computeScopes(claims, entitlementConfig)
	expectedRepoList := []string{"codespace-oddity"}
	read := "read"
	expectedPermissions := github.InstallationPermissions{
		Contents: &read,
	}

	if !reflect.DeepEqual(scope.Repositories, expectedRepoList) {
		t.Error("Expected scope.Repositories to be [codespace-oddity], but got", scope.Repositories)
	}
	if !reflect.DeepEqual(scope.Permissions, expectedPermissions) {
		t.Error("Expected scope.Permissions to be", expectedPermissions, ", but got", scope.Permissions)
	}
}

func TestComputeMultipleEntitlements(t *testing.T) {
	//Load the sample config file as a string
	b, err := os.ReadFile("test/multiple-match.yml") // just pass the file name
	if err != nil {
		t.Fatal(err)
	}

	content := string(b) // convert content to a 'string'
	var entitlementConfig []Entitlement
	err = yaml.Unmarshal([]byte(content), &entitlementConfig)
	if err != nil {
		t.Fatal(err)
	}

	claims := jwt.MapClaims{
		"actor":                 "helaili",
		"environment":           "production",
		"event_name":            "workflow_dispatch",
		"ref":                   "refs/heads/main",
		"repository":            "helaili/github-oidc-auth-app",
		"repository_owner":      "helaili",
		"repository_visibility": "public",
		"workflow":              "Manual Test Workflow",
	}

	expectedRepoList := []string{"codespace-oddity", "bootstrap"}
	read := "read"
	write := "write"
	expectedPermissions := github.InstallationPermissions{
		Contents: &write,
		Checks:   &read,
	}

	// Compute the scope for the claims
	scope := computeScopes(claims, entitlementConfig)
	if !reflect.DeepEqual(scope.Repositories, expectedRepoList) {
		t.Error("Expected scope.Repositories to be [codespace-oddity, bootstrap], but got", scope.Repositories)
	}
	if !reflect.DeepEqual(scope.Permissions, expectedPermissions) {
		t.Error("Expected scope.Permissions to be", expectedPermissions, ", but got", scope.Permissions)
	}
}
