package main

import (
	"os"
	"reflect"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/go-github/v52/github"
	"gopkg.in/yaml.v2"
)

var claims jwt.MapClaims = jwt.MapClaims{
	"actor":                 "helaili",
	"actor_id":              2787414,
	"aud":                   "api://ActionsOIDCGateway",
	"base_ref":              "",
	"environment":           "production",
	"event_name":            "workflow_dispatch",
	"head_ref":              "",
	"iss":                   "https://token.actions.githubusercontent.com",
	"job_workflow_ref":      "helaili/github-oidc-auth-app/.github/workflows/manual-test.yml@refs/heads/main",
	"job_workflow_sha":      "44216e5ae99f3653290b60b7f995bfe1c0f3aba0",
	"ref":                   "refs/heads/main",
	"ref_type":              "branch",
	"repository":            "helaili/github-oidc-auth-app",
	"repository_id":         630836305,
	"repository_owner":      "helaili",
	"repository_owner_id":   2787414,
	"repository_visibility": "public",
	"run_attempt":           1,
	"run_id":                4779904167,
	"run_number":            12,
	"runner_environment":    "github-hosted",
	"sub":                   "repo:helaili/github-oidc-auth-app:ref:refs/heads/main",
	"workflow":              "Manual Test Workflow",
	"workflow_ref":          "helaili/github-oidc-auth-app/.github/workflows/manual-test.yml@refs/heads/main",
	"workflow_sha":          "44216e5ae99f3653290b60b7f995bfe1c0f3aba0",
}

func TestExactRegexEntitlement(t *testing.T) {
	entitlement := Entitlement{
		Actor:             "helaili",
		ActorId:           2787414,
		Audience:          "api://ActionsOIDCGateway",
		BaseRef:           "",
		Environment:       "production",
		EventName:         "workflow_dispatch",
		HeadRef:           "",
		Issuer:            "https://token.actions.githubusercontent.com",
		JobWokflowRef:     "helaili/github-oidc-auth-app/.github/workflows/manual-test.yml@refs/heads/main",
		JobWokflowSha:     "44216e5ae99f3653290b60b7f995bfe1c0f3aba0",
		Ref:               "refs/heads/main",
		RefType:           "branch",
		Repository:        "helaili/github-oidc-auth-app",
		RepositoryId:      630836305,
		RepositoryOwner:   "helaili",
		RepositoryOwnerId: 2787414,
		RunAttempt:        1,
		RunId:             4779904167,
		RunNumber:         12,
		RunnerEnvironment: "github-hosted",
		Subject:           "repo:helaili/github-oidc-auth-app:ref:refs/heads/main",
		Visibility:        "public",
		Workflow:          "Manual Test Workflow",
		WorkflowRef:       "helaili/github-oidc-auth-app/.github/workflows/manual-test.yml@refs/heads/main",
		WorkflowSha:       "44216e5ae99f3653290b60b7f995bfe1c0f3aba0",
	}
	entitlementRegex := entitlement.regexString()
	if entitlementRegex != "^actor:helaili,actor_id:2787414,aud:api://ActionsOIDCGateway,base_ref:.*,environment:production,event_name:workflow_dispatch,head_ref:.*,iss:https://token.actions.githubusercontent.com,job_workflow_ref:helaili/github-oidc-auth-app/.github/workflows/manual-test.yml@refs/heads/main,job_workflow_sha:44216e5ae99f3653290b60b7f995bfe1c0f3aba0,ref:refs/heads/main,ref_type:branch,repository:helaili/github-oidc-auth-app,repository_id:630836305,repository_owner:helaili,repository_owner_id:2787414,repository_visibility:public,run_attempt:1,run_id:4779904167,run_number:12,runner_environment:github-hosted,sub:repo:helaili/github-oidc-auth-app:ref:refs/heads/main,workflow:Manual Test Workflow,workflow_ref:helaili/github-oidc-auth-app/.github/workflows/manual-test.yml@refs/heads/main,workflow_sha:44216e5ae99f3653290b60b7f995bfe1c0f3aba0$" {
		t.Error("Expected entitlementRegex to be ^actor:helaili,actor_id:2787414,aud:api://ActionsOIDCGateway,base_ref:.*,environment:production,event_name:workflow_dispatch,head_ref:.*,iss:https://token.actions.githubusercontent.com,job_workflow_ref:helaili/github-oidc-auth-app/.github/workflows/manual-test.yml@refs/heads/main,job_workflow_sha:44216e5ae99f3653290b60b7f995bfe1c0f3aba0,ref:refs/heads/main,ref_type:branch,repository:helaili/github-oidc-auth-app,repository_id:630836305,repository_owner:helaili,repository_owner_id:2787414,repository_visibility:public,run_attempt:1,run_id:4779904167,run_number:12,runner_environment:github-hosted,sub:repo:helaili/github-oidc-auth-app:ref:refs/heads/main,workflow:Manual Test Workflow,workflow_ref:helaili/github-oidc-auth-app/.github/workflows/manual-test.yml@refs/heads/main,workflow_sha:44216e5ae99f3653290b60b7f995bfe1c0f3aba0$, but got", entitlementRegex)
	}
}

func TestFuzzyRegexEntitlement(t *testing.T) {
	entitlement := Entitlement{
		Environment:     "production",
		EventName:       "workflow_dispatch",
		Ref:             "refs/heads/main",
		RepositoryOwner: "helaili",
		Visibility:      "public",
	}
	entitlementRegex := entitlement.regexString()
	if entitlementRegex != "^actor:.*,actor_id:.*,aud:.*,base_ref:.*,environment:production,event_name:workflow_dispatch,head_ref:.*,iss:.*,job_workflow_ref:.*,job_workflow_sha:.*,ref:refs/heads/main,ref_type:.*,repository:.*,repository_id:.*,repository_owner:helaili,repository_owner_id:.*,repository_visibility:public,run_attempt:.*,run_id:.*,run_number:.*,runner_environment:.*,sub:.*,workflow:.*,workflow_ref:.*,workflow_sha:.*$" {
		t.Error("Expected entitlementRegex to be ^actor:.*,actor_id:.*,aud:.*,base_ref:.*,environment:production,event_name:workflow_dispatch,head_ref:.*,iss:.*,job_workflow_ref:.*,job_workflow_sha:.*,ref:refs/heads/main,ref_type:.*,repository:.*,repository_id:.*,repository_owner:helaili,repository_owner_id:.*,repository_visibility:public,run_attempt:.*,run_id:.*,run_number:.*,runner_environment:.*,sub:.*,workflow:.*,workflow_ref:.*,workflow_sha:.*$, but got", entitlementRegex)
	}
}

func TestComputeSimpleEntitlements(t *testing.T) {
	//Load the sample config file as a string
	b, err := os.ReadFile("test/precise-match.yml")
	if err != nil {
		t.Fatal(err)
	}

	content := string(b)
	var entitlementConfig []Entitlement
	err = yaml.Unmarshal([]byte(content), &entitlementConfig)
	if err != nil {
		t.Fatal(err)
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

func TestNoEntitlements(t *testing.T) {
	//Load the sample config file as a string
	b, err := os.ReadFile("test/no-match.yml")
	if err != nil {
		t.Fatal(err)
	}

	content := string(b)
	var entitlementConfig []Entitlement
	err = yaml.Unmarshal([]byte(content), &entitlementConfig)
	if err != nil {
		t.Fatal(err)
	}

	// Compute the scope for the claims
	scope := computeScopes(claims, entitlementConfig)
	expectedRepoList := []string{}
	expectedPermissions := github.InstallationPermissions{}

	if !reflect.DeepEqual(scope.Repositories, expectedRepoList) {
		t.Error("Expected scope.Repositories to be empty, but got", scope.Repositories)
	}
	if !reflect.DeepEqual(scope.Permissions, expectedPermissions) {
		t.Error("Expected scope.Permissions to be empty, but got", scope.Permissions)
	}
}
