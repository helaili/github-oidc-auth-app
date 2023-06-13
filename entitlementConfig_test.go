package main

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"

	"github.com/google/go-github/v53/github"
)

func TestStripAllPermissionsBut(t *testing.T) {
	read := "read"
	write := "write"

	config := NewEntitlementConfig("test", 1, "https://github.com", "test", "")

	srcEntitlement := Entitlement{
		Repository:      "helaili/github-oidc-auth-app",
		RepositoryOwner: "helaili",
		Environment:     "development",
		BasicEntitlement: BasicEntitlement{
			Scopes: Scope{
				Permissions: github.InstallationPermissions{
					Contents:                   &write,
					OrganizationAdministration: &read,
					OrganizationCustomRoles:    &read,
				},
				Repositories: []string{"codespace-oddity"},
			},
		},
	}

	expectedEntitlement := Entitlement{
		Repository:      "helaili/github-oidc-auth-app",
		RepositoryOwner: "helaili",
		Environment:     "development",
		BasicEntitlement: BasicEntitlement{
			Scopes: Scope{
				Permissions: github.InstallationPermissions{
					OrganizationAdministration: &read,
				},
				Repositories: []string{"codespace-oddity"},
			},
		},
	}

	config.stripAllPermissionsBut("organization_administration", &srcEntitlement)

	if !reflect.DeepEqual(expectedEntitlement, srcEntitlement) {
		expectedEntitlementJson, _ := json.MarshalIndent(expectedEntitlement, "", "  ")
		gotEntitlementJson, _ := json.MarshalIndent(srcEntitlement, "", "  ")
		t.Errorf("Expected entitlements to be %s, but got %v", string(expectedEntitlementJson), string(gotEntitlementJson))
	}
}

func TestStripAllOrgPermissions(t *testing.T) {
	read := "read"
	write := "write"

	config := NewEntitlementConfig("test", 1, "https://github.com", "test", "")

	srcEntitlement := Entitlement{
		Repository:      "helaili/github-oidc-auth-app",
		RepositoryOwner: "helaili",
		Environment:     "development",
		BasicEntitlement: BasicEntitlement{
			Scopes: Scope{
				Permissions: github.InstallationPermissions{
					Contents:                   &write,
					OrganizationAdministration: &read,
					OrganizationCustomRoles:    &write,
				},
				Repositories: []string{"codespace-oddity"},
			},
		},
	}

	expectedEntitlement := Entitlement{
		Repository:      "helaili/github-oidc-auth-app",
		RepositoryOwner: "helaili",
		Environment:     "development",
		BasicEntitlement: BasicEntitlement{
			Scopes: Scope{
				Permissions: github.InstallationPermissions{
					Contents: &write,
				},
				Repositories: []string{"codespace-oddity"},
			},
		},
	}

	config.stripAllOrgPermissions(&srcEntitlement)

	if !reflect.DeepEqual(expectedEntitlement, srcEntitlement) {
		expectedEntitlementJson, _ := json.MarshalIndent(expectedEntitlement, "", "  ")
		gotEntitlementJson, _ := json.MarshalIndent(srcEntitlement, "", "  ")
		t.Errorf("Expected entitlements to be %s, but got %v", string(expectedEntitlementJson), string(gotEntitlementJson))
	}
}

func TestSimpleRepoConfig(t *testing.T) {
	path := "test/simple-repo"

	config := NewEntitlementConfig("test", 1, "https://github.com", "test", "")

	files, err := os.ReadDir(path)
	if err != nil {
		t.Error(err)
	}
	err = config.loadFolder(path, files, true)
	if err != nil {
		t.Error(err)
	}

	read := "read"
	write := "write"

	expectedEntitlements := []Entitlement{
		{
			Repository:      "helaili/github-oidc-auth-app",
			RepositoryOwner: "helaili",
			Environment:     "development",
			BasicEntitlement: BasicEntitlement{
				Scopes: Scope{
					Permissions: github.InstallationPermissions{
						Contents:                   &write,
						OrganizationAdministration: &read,
					},
					Repositories: []string{"codespace-oddity"},
				},
			},
		},
	}

	if !reflect.DeepEqual(expectedEntitlements, config.Entitlements) {
		expectedEntitlementsJson, _ := json.MarshalIndent(expectedEntitlements, "", "  ")
		gotEntitlementsJson, _ := json.MarshalIndent(config.Entitlements, "", "  ")
		t.Errorf("Expected entitlements to be %s, but got %v", string(expectedEntitlementsJson), string(gotEntitlementsJson))
	}
}

func TestGoodRepoConfig(t *testing.T) {
	path := "test/good-repo"

	config := NewEntitlementConfig("test", 1, "https://github.com", "test", "")

	files, err := os.ReadDir(path)
	if err != nil {
		t.Error(err)
	}
	err = config.loadFolder(path, files, true)
	if err != nil {
		t.Error(err)
	}

	read := "read"
	write := "write"

	expectedEntitlements := []Entitlement{
		// from test/good-repo/generic.json
		{
			Repository:      "helaili/test-three-repo",
			RepositoryOwner: "helaili",
			Environment:     "development",
			BasicEntitlement: BasicEntitlement{
				Scopes: Scope{
					Repositories: []string{
						"codespace-oddity",
					},
					Permissions: github.InstallationPermissions{
						OrganizationAdministration: &read,
						Contents:                   &write,
					},
				},
			},
		},
		// from test/good-repo/organization/administration/owners/helaili/environments/development/admin_read.json
		{
			RepositoryOwner: "helaili",
			Environment:     "development",
			BasicEntitlement: BasicEntitlement{
				Scopes: Scope{
					Permissions: github.InstallationPermissions{
						OrganizationAdministration: &read,
					},
				},
			},
		},
		// from test/good-repo/repositories/codespace-oddity/owners/helaili/test-repo-dev.json
		{
			Repository:      "helaili/test-two-repo",
			RepositoryOwner: "helaili",
			Environment:     "development",
			BasicEntitlement: BasicEntitlement{
				Scopes: Scope{
					Permissions: github.InstallationPermissions{
						Contents: &write,
					},
					Repositories: []string{"codespace-oddity"},
				},
			},
		},
		// from test/good-repo/repositories/codespace-oddity/owners/helaili/environments/development/test-workflow.json
		{
			RepositoryOwner: "helaili",
			Environment:     "development",
			BasicEntitlement: BasicEntitlement{
				Workflow: "Workflow 1",
				Scopes: Scope{
					Permissions: github.InstallationPermissions{
						Contents: &write,
					},
					Repositories: []string{"codespace-oddity"},
				},
			},
		},
		// from test/good-repo/repositories/codespace-oddity/owners/helaili/repositories/github-oidc-auth-app/entitlements.json
		{
			Repository:      "helaili/github-oidc-auth-app",
			RepositoryOwner: "helaili",
			Environment:     "development",
			BasicEntitlement: BasicEntitlement{
				Scopes: Scope{
					Permissions: github.InstallationPermissions{
						Contents: &write,
					},
					Repositories: []string{"codespace-oddity"},
				},
			},
		},
		// test/good-repo/repositories/codespace-oddity/codespace-oddity-generic.json
		{
			Repository:      "helaili/test-repo",
			RepositoryOwner: "helaili",
			Environment:     "development",
			BasicEntitlement: BasicEntitlement{
				Scopes: Scope{
					Permissions: github.InstallationPermissions{
						Contents: &write,
					},
					Repositories: []string{
						"codespace-oddity",
					},
				},
			},
		},
	}

	if !reflect.DeepEqual(expectedEntitlements, config.Entitlements) {
		expectedEntitlementsJson, _ := json.MarshalIndent(expectedEntitlements, "", "  ")
		gotEntitlementsJson, _ := json.MarshalIndent(config.Entitlements, "", "  ")
		t.Errorf("Expected entitlements to be %s, but got %v", string(expectedEntitlementsJson), string(gotEntitlementsJson))
	}
}

func TestDeepEnvRepoConfig(t *testing.T) {
	path := "test/deep-env-repo"

	config := NewEntitlementConfig("test", 1, "https://github.com", "test", "")

	files, err := os.ReadDir(path)
	if err != nil {
		t.Error(err)
	}
	err = config.loadFolder(path, files, true)
	if err != nil {
		t.Error(err)
	}

	write := "write"

	expectedEntitlements := []Entitlement{
		// from test/deep-env-repo/repositories/codespace-oddity/owners/helaili/repositories/github-oidc-auth-app/environments/production/test-workflow.json
		{
			Repository:      "helaili/github-oidc-auth-app",
			RepositoryOwner: "helaili",
			Environment:     "production",
			BasicEntitlement: BasicEntitlement{
				Workflow: "Workflow 1",
				Scopes: Scope{
					Repositories: []string{
						"codespace-oddity",
					},
					Permissions: github.InstallationPermissions{
						Contents: &write,
					},
				},
			},
		},
	}

	if !reflect.DeepEqual(expectedEntitlements, config.Entitlements) {
		expectedEntitlementsJson, _ := json.MarshalIndent(expectedEntitlements, "", "  ")
		gotEntitlementsJson, _ := json.MarshalIndent(config.Entitlements, "", "  ")
		t.Errorf("Expected entitlements to be %s, but got %v", string(expectedEntitlementsJson), string(gotEntitlementsJson))
	}
}

func TestDeepRepoRepoConfig(t *testing.T) {
	path := "test/deep-repo-repo"

	config := NewEntitlementConfig("test", 1, "https://github.com", "test", "")

	files, err := os.ReadDir(path)
	if err != nil {
		t.Error(err)
	}
	err = config.loadFolder(path, files, true)
	if err != nil {
		t.Error(err)
	}

	write := "write"

	expectedEntitlements := []Entitlement{
		// from test/deep-repo-repo/repositories/codespace-oddity/environments/production/owners/helaili/repositories/github-oidc-auth-app/test-workflow.json
		{
			Repository:      "helaili/github-oidc-auth-app",
			RepositoryOwner: "helaili",
			Environment:     "production",
			BasicEntitlement: BasicEntitlement{
				Workflow: "Workflow 1",
				Scopes: Scope{
					Repositories: []string{
						"codespace-oddity",
					},
					Permissions: github.InstallationPermissions{
						Contents: &write,
					},
				},
			},
		},
	}

	if !reflect.DeepEqual(expectedEntitlements, config.Entitlements) {
		expectedEntitlementsJson, _ := json.MarshalIndent(expectedEntitlements, "", "  ")
		gotEntitlementsJson, _ := json.MarshalIndent(config.Entitlements, "", "  ")
		t.Errorf("Expected entitlements to be %s, but got %v", string(expectedEntitlementsJson), string(gotEntitlementsJson))
	}
}

func TestOwnerEnvRepoConfig(t *testing.T) {
	path := "test/owner-env-repo"

	config := NewEntitlementConfig("test", 1, "https://github.com", "test", "")

	files, err := os.ReadDir(path)
	if err != nil {
		t.Error(err)
	}
	err = config.loadFolder(path, files, true)
	if err != nil {
		t.Error(err)
	}

	write := "write"

	expectedEntitlements := []Entitlement{
		// from test/owner-env-repo/owners/helaili/environments/production/test-workflow.json
		{
			RepositoryOwner: "helaili",
			Environment:     "production",
			BasicEntitlement: BasicEntitlement{
				Workflow: "Workflow 1",
				Scopes: Scope{
					Permissions: github.InstallationPermissions{
						Contents: &write,
					},
				},
			},
		},
	}

	if !reflect.DeepEqual(expectedEntitlements, config.Entitlements) {
		expectedEntitlementsJson, _ := json.MarshalIndent(expectedEntitlements, "", "  ")
		gotEntitlementsJson, _ := json.MarshalIndent(config.Entitlements, "", "  ")
		t.Errorf("Expected entitlements to be %s, but got %v", string(expectedEntitlementsJson), string(gotEntitlementsJson))
	}
}

/*
 * The second repo is ignored because it's not in after an owner definition
 */
func TestRepoRepoRepoConfig(t *testing.T) {
	path := "test/repo-repo-repo"

	config := NewEntitlementConfig("test", 1, "https://github.com", "test", "")

	files, err := os.ReadDir(path)
	if err != nil {
		t.Error(err)
	}
	err = config.loadFolder(path, files, true)
	if err != nil {
		t.Error(err)
	}

	write := "write"

	expectedEntitlements := []Entitlement{
		// from test/repo-repo-repo/repositories/codespace-oddity/repositories/github-oidc-auth-app/test-workflow.json
		{
			BasicEntitlement: BasicEntitlement{
				Workflow: "Workflow 1",
				Scopes: Scope{
					Repositories: []string{
						"codespace-oddity",
					},
					Permissions: github.InstallationPermissions{
						Contents: &write,
					},
				},
			},
		},
	}

	if !reflect.DeepEqual(expectedEntitlements, config.Entitlements) {
		expectedEntitlementsJson, _ := json.MarshalIndent(expectedEntitlements, "", "  ")
		gotEntitlementsJson, _ := json.MarshalIndent(config.Entitlements, "", "  ")
		t.Errorf("Expected entitlements to be %s, but got %v", string(expectedEntitlementsJson), string(gotEntitlementsJson))
	}
}

func TestEnvRepoConfig(t *testing.T) {
	path := "test/env-repo"

	config := NewEntitlementConfig("test", 1, "https://github.com", "test", "")

	files, err := os.ReadDir(path)
	if err != nil {
		t.Error(err)
	}
	err = config.loadFolder(path, files, true)
	if err != nil {
		t.Error(err)
	}

	write := "write"

	expectedEntitlements := []Entitlement{
		// from test/env-repo/environments/production/test-workflow.json
		{
			Environment: "production",
			BasicEntitlement: BasicEntitlement{
				Workflow: "Workflow 1",
				Scopes: Scope{
					Permissions: github.InstallationPermissions{
						Contents: &write,
					},
				},
			},
		},
	}

	if !reflect.DeepEqual(expectedEntitlements, config.Entitlements) {
		expectedEntitlementsJson, _ := json.MarshalIndent(expectedEntitlements, "", "  ")
		gotEntitlementsJson, _ := json.MarshalIndent(config.Entitlements, "", "  ")
		t.Errorf("Expected entitlements to be %s, but got %v", string(expectedEntitlementsJson), string(gotEntitlementsJson))
	}
}

func TestEnvRepoRepoConfig(t *testing.T) {
	path := "test/env-repo-repo"

	config := NewEntitlementConfig("test", 1, "https://github.com", "test", "")

	files, err := os.ReadDir(path)
	if err != nil {
		t.Error(err)
	}
	err = config.loadFolder(path, files, true)
	if err != nil {
		t.Error(err)
	}

	write := "write"

	expectedEntitlements := []Entitlement{
		// from test/env-repo-repo/environments/production/repositories/codespace-oddity/test-workflow.json
		{
			Environment: "production",
			BasicEntitlement: BasicEntitlement{
				Workflow: "Workflow 1",
				Scopes: Scope{
					Repositories: []string{
						"codespace-oddity",
					},
					Permissions: github.InstallationPermissions{
						Contents: &write,
					},
				},
			},
		},
	}

	if !reflect.DeepEqual(expectedEntitlements, config.Entitlements) {
		expectedEntitlementsJson, _ := json.MarshalIndent(expectedEntitlements, "", "  ")
		gotEntitlementsJson, _ := json.MarshalIndent(config.Entitlements, "", "  ")
		t.Errorf("Expected entitlements to be %s, but got %v", string(expectedEntitlementsJson), string(gotEntitlementsJson))
	}
}

func TestEnvOwnersRepoConfig(t *testing.T) {
	path := "test/env-owners-repo-repo"

	config := NewEntitlementConfig("test", 1, "https://github.com", "test", "")

	files, err := os.ReadDir(path)
	if err != nil {
		t.Error(err)
	}
	err = config.loadFolder(path, files, true)
	if err != nil {
		t.Error(err)
	}

	write := "write"

	expectedEntitlements := []Entitlement{
		// from test/env-owners-repo-repo/environments/production/owners/helaili/repositories/github-oidc-auth-app/test-workflow.json
		{
			Repository:      "helaili/github-oidc-auth-app",
			RepositoryOwner: "helaili",
			Environment:     "production",
			BasicEntitlement: BasicEntitlement{
				Workflow: "Workflow 1",
				Scopes: Scope{
					Permissions: github.InstallationPermissions{
						Contents: &write,
					},
				},
			},
		},
	}

	if !reflect.DeepEqual(expectedEntitlements, config.Entitlements) {
		expectedEntitlementsJson, _ := json.MarshalIndent(expectedEntitlements, "", "  ")
		gotEntitlementsJson, _ := json.MarshalIndent(config.Entitlements, "", "  ")
		t.Errorf("Expected entitlements to be %s, but got %v", string(expectedEntitlementsJson), string(gotEntitlementsJson))
	}
}

func TestEnvOrganizationRepoConfig(t *testing.T) {
	path := "test/env-organization-repo"

	config := NewEntitlementConfig("test", 1, "https://github.com", "test", "")

	files, err := os.ReadDir(path)
	if err != nil {
		t.Error(err)
	}
	err = config.loadFolder(path, files, true)
	if err != nil {
		t.Error(err)
	}

	write := "write"

	expectedEntitlements := []Entitlement{
		// from test/env-organization-repo/environments/production/organization/custom_roles/test-workflow.json
		{
			Environment: "production",
			BasicEntitlement: BasicEntitlement{
				Workflow: "Workflow 1",
				Scopes: Scope{
					Permissions: github.InstallationPermissions{
						OrganizationCustomRoles: &write,
					},
				},
			},
		},
	}

	if !reflect.DeepEqual(expectedEntitlements, config.Entitlements) {
		expectedEntitlementsJson, _ := json.MarshalIndent(expectedEntitlements, "", "  ")
		gotEntitlementsJson, _ := json.MarshalIndent(config.Entitlements, "", "  ")
		t.Errorf("Expected entitlements to be %s, but got %v", string(expectedEntitlementsJson), string(gotEntitlementsJson))
	}
}
