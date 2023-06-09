package main

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/go-github/v53/github"
)

var claims jwt.MapClaims = jwt.MapClaims{
	"actor":                 "major-tom",
	"actor_id":              2787414,
	"aud":                   "api://ActionsOIDCGateway",
	"base_ref":              "",
	"environment":           "production",
	"event_name":            "workflow_dispatch",
	"head_ref":              "",
	"iss":                   "https://token.actions.githubusercontent.com",
	"job_workflow_ref":      "major-tom/starman/.github/workflows/manual-test.yml@refs/heads/main",
	"job_workflow_sha":      "44216e5ae99f3653290b60b7f995bfe1c0f3aba0",
	"ref":                   "refs/heads/main",
	"ref_type":              "branch",
	"repository":            "major-tom/starman",
	"repository_id":         630836305,
	"repository_owner":      "major-tom",
	"repository_owner_id":   2787414,
	"repository_visibility": "public",
	"run_attempt":           1,
	"run_id":                4779904167,
	"run_number":            12,
	"runner_environment":    "github-hosted",
	"sub":                   "repo:major-tom/starman:ref:refs/heads/main",
	"workflow":              "Manual Test Workflow",
	"workflow_ref":          "major-tom/starman/.github/workflows/manual-test.yml@refs/heads/main",
	"workflow_sha":          "44216e5ae99f3653290b60b7f995bfe1c0f3aba0",
}

func TestExactRegexEntitlement(t *testing.T) {
	entitlement := Entitlement{
		Environment:       "production",
		Repository:        "major-tom/starman",
		RepositoryId:      630836305,
		RepositoryOwner:   "major-tom",
		RepositoryOwnerId: 2787414,
		Actor:             "major-tom",
		ActorId:           2787414,
		Audience:          "api://ActionsOIDCGateway",
		BaseRef:           "",
		EventName:         "workflow_dispatch",
		HeadRef:           "",
		Issuer:            "https://token.actions.githubusercontent.com",
		JobWokflowRef:     "major-tom/starman/.github/workflows/manual-test.yml@refs/heads/main",
		JobWokflowSha:     "44216e5ae99f3653290b60b7f995bfe1c0f3aba0",
		Ref:               "refs/heads/main",
		RefType:           "branch",
		RunAttempt:        1,
		RunId:             4779904167,
		RunNumber:         12,
		RunnerEnvironment: "github-hosted",
		Subject:           "repo:major-tom/starman:ref:refs/heads/main",
		Visibility:        "public",
		Workflow:          "Manual Test Workflow",
		WorkflowRef:       "major-tom/starman/.github/workflows/manual-test.yml@refs/heads/main",
		WorkflowSha:       "44216e5ae99f3653290b60b7f995bfe1c0f3aba0",
	}
	entitlementRegex := entitlement.regexString()
	if entitlementRegex != "^actor:major-tom,actor_id:2787414,aud:api://ActionsOIDCGateway,base_ref:.*,environment:production,event_name:workflow_dispatch,head_ref:.*,iss:https://token.actions.githubusercontent.com,job_workflow_ref:major-tom/starman/.github/workflows/manual-test.yml@refs/heads/main,job_workflow_sha:44216e5ae99f3653290b60b7f995bfe1c0f3aba0,ref:refs/heads/main,ref_type:branch,repository:major-tom/starman,repository_id:630836305,repository_owner:major-tom,repository_owner_id:2787414,repository_visibility:public,run_attempt:1,run_id:4779904167,run_number:12,runner_environment:github-hosted,sub:repo:major-tom/starman:ref:refs/heads/main,workflow:Manual Test Workflow,workflow_ref:major-tom/starman/.github/workflows/manual-test.yml@refs/heads/main,workflow_sha:44216e5ae99f3653290b60b7f995bfe1c0f3aba0$" {
		t.Error("Expected entitlementRegex to be ^actor:major-tom,actor_id:2787414,aud:api://ActionsOIDCGateway,base_ref:.*,environment:production,event_name:workflow_dispatch,head_ref:.*,iss:https://token.actions.githubusercontent.com,job_workflow_ref:major-tom/starman/.github/workflows/manual-test.yml@refs/heads/main,job_workflow_sha:44216e5ae99f3653290b60b7f995bfe1c0f3aba0,ref:refs/heads/main,ref_type:branch,repository:major-tom/starman,repository_id:630836305,repository_owner:major-tom,repository_owner_id:2787414,repository_visibility:public,run_attempt:1,run_id:4779904167,run_number:12,runner_environment:github-hosted,sub:repo:major-tom/starman:ref:refs/heads/main,workflow:Manual Test Workflow,workflow_ref:major-tom/starman/.github/workflows/manual-test.yml@refs/heads/main,workflow_sha:44216e5ae99f3653290b60b7f995bfe1c0f3aba0$, but got", entitlementRegex)
	}
}

func TestFuzzyRegexEntitlement(t *testing.T) {
	entitlement := Entitlement{
		Environment:     "production",
		RepositoryOwner: "major-tom",
		EventName:       "workflow_dispatch",
		Ref:             "refs/heads/main",
		Visibility:      "public",
	}
	entitlementRegex := entitlement.regexString()
	if entitlementRegex != "^actor:.*,actor_id:.*,aud:.*,base_ref:.*,environment:production,event_name:workflow_dispatch,head_ref:.*,iss:.*,job_workflow_ref:.*,job_workflow_sha:.*,ref:refs/heads/main,ref_type:.*,repository:.*,repository_id:.*,repository_owner:major-tom,repository_owner_id:.*,repository_visibility:public,run_attempt:.*,run_id:.*,run_number:.*,runner_environment:.*,sub:.*,workflow:.*,workflow_ref:.*,workflow_sha:.*$" {
		t.Error("Expected entitlementRegex to be ^actor:.*,actor_id:.*,aud:.*,base_ref:.*,environment:production,event_name:workflow_dispatch,head_ref:.*,iss:.*,job_workflow_ref:.*,job_workflow_sha:.*,ref:refs/heads/main,ref_type:.*,repository:.*,repository_id:.*,repository_owner:major-tom,repository_owner_id:.*,repository_visibility:public,run_attempt:.*,run_id:.*,run_number:.*,runner_environment:.*,sub:.*,workflow:.*,workflow_ref:.*,workflow_sha:.*$, but got", entitlementRegex)
	}
}

func TestComputeSimpleEntitlements(t *testing.T) {
	//Load the sample config file as a string
	b, err := os.ReadFile("test/precise-match.json")
	if err != nil {
		t.Fatal(err)
	}

	content := string(b)
	var entitlements []Entitlement
	err = json.Unmarshal([]byte(content), &entitlements)
	if err != nil {
		t.Fatal(err)
	}

	entitlementConfig := &EntitlementConfig{
		Entitlements: entitlements,
	}

	// Compute the scope for the claims
	scope := entitlementConfig.computeScopes(claims)
	expectedRepoList := []string{"codespace-oddity"}
	read := "read"
	expectedPermissions := github.InstallationPermissions{
		Contents: &read,
	}

	if !reflect.DeepEqual(scope.Repositories, expectedRepoList) {
		t.Errorf("Expected scope.Repositories to be [codespace-oddity], but got %s", scope.Repositories)
	}
	if !reflect.DeepEqual(scope.Permissions, expectedPermissions) {
		expPerms, _ := json.MarshalIndent(expectedPermissions, "", "  ")
		gotPerms, _ := json.MarshalIndent(scope.Permissions, "", "  ")
		t.Errorf("Expected scope.Permissions to be %s, but got %v", string(expPerms), string(gotPerms))
	}
}

func TestComputeMultipleEntitlements(t *testing.T) {
	//Load the sample config file as a string
	b, err := os.ReadFile("test/multiple-match.json") // just pass the file name
	if err != nil {
		t.Fatal(err)
	}

	content := string(b) // convert content to a 'string'
	var entitlements []Entitlement
	err = json.Unmarshal([]byte(content), &entitlements)
	if err != nil {
		t.Fatal(err)
	}

	entitlementConfig := &EntitlementConfig{
		Entitlements: entitlements,
	}

	expectedRepoList := []string{"codespace-oddity", "bootstrap"}
	read := "read"
	write := "write"
	expectedPermissions := github.InstallationPermissions{
		Contents:             &write,
		Checks:               &read,
		OrganizationProjects: &read,
	}

	// Compute the scope for the claims
	scope := entitlementConfig.computeScopes(claims)
	if !reflect.DeepEqual(scope.Repositories, expectedRepoList) {
		t.Errorf("Expected scope.Repositories to be [codespace-oddity, bootstrap], but got %s", scope.Repositories)
	}
	if !reflect.DeepEqual(scope.Permissions, expectedPermissions) {
		expPerms, _ := json.MarshalIndent(expectedPermissions, "", "  ")
		gotPerms, _ := json.MarshalIndent(scope.Permissions, "", "  ")
		t.Errorf("Expected scope.Permissions to be %s, but got %v", string(expPerms), string(gotPerms))
	}
}

func TestNoEntitlements(t *testing.T) {
	//Load the sample config file as a string
	b, err := os.ReadFile("test/no-match.json")
	if err != nil {
		t.Fatal(err)
	}

	content := string(b)
	var entitlements []Entitlement
	err = json.Unmarshal([]byte(content), &entitlements)
	if err != nil {
		t.Fatal(err)
	}

	entitlementConfig := &EntitlementConfig{
		Entitlements: entitlements,
	}

	// Compute the scope for the claims
	scope := entitlementConfig.computeScopes(claims)
	expectedRepoList := []string{}
	expectedPermissions := github.InstallationPermissions{}

	if !reflect.DeepEqual(scope.Repositories, expectedRepoList) {
		t.Errorf("Expected scope.Repositories to be empty, but got %s", scope.Repositories)
	}
	if !reflect.DeepEqual(scope.Permissions, expectedPermissions) {
		expPerms, _ := json.MarshalIndent(expectedPermissions, "", "  ")
		gotPerms, _ := json.MarshalIndent(scope.Permissions, "", "  ")
		t.Errorf("Expected scope.Permissions to be %s, but got %v", string(expPerms), string(gotPerms))
	}
}
