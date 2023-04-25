package main

import (
	"reflect"
	"testing"

	"github.com/google/go-github/v52/github"
)

func TestIsCompletelyEmpty(t *testing.T) {
	scope := NewScope()
	if !scope.isEmpty() {
		t.Error("Expected scope to be empty")
	}
}

func TestHasAtLeastARepo(t *testing.T) {
	scope := NewScope()
	scope.Repositories = append(scope.Repositories, "test")
	if scope.isEmpty() {
		t.Error("Expected scope to not be empty")
	}
}

func TestHasAtLeastAPermission(t *testing.T) {
	scope := NewScope()
	read := "read"
	scope.Permissions.Contents = &read

	if scope.isEmpty() {
		t.Error("Expected scope to not be empty")
	}
}

func TestHasRepoAndPermission(t *testing.T) {
	read := "read"
	scope := Scope{
		Repositories: []string{"test"},
		Permissions: github.InstallationPermissions{
			Contents: &read,
		},
	}

	if scope.isEmpty() {
		t.Error("Expected scope to not be empty")
	}
}

func TestMergeWithEmptyScope(t *testing.T) {
	read := "read"
	write := "write"
	baseScope := NewScope()
	additionalScope := Scope{
		Repositories: []string{"test1", "test2"},
		Permissions: github.InstallationPermissions{
			Contents: &read,
			Actions:  &write,
		},
	}
	baseScope.merge(additionalScope)

	expectedPermissions := github.InstallationPermissions{
		Contents: &read,
		Actions:  &write,
	}
	if !reflect.DeepEqual(baseScope.Repositories, []string{"test1", "test2"}) {
		t.Error("Expected baseScope.Repositories to be [test1, test2], but got", baseScope.Repositories)
	}
	if !reflect.DeepEqual(baseScope.Permissions, expectedPermissions) {
		t.Error("Expected scope.Permissions to be", expectedPermissions, ", but got", baseScope.Permissions)
	}
}

func TestMergeWithExisingScope(t *testing.T) {
	read := "read"
	write := "write"
	admin := "admin"

	baseScope := Scope{
		Repositories: []string{"test1", "test2"},
		Permissions: github.InstallationPermissions{
			Contents:             &read,
			Actions:              &read,
			Checks:               &write,
			OrganizationProjects: &admin,
			OrganizationPackages: &read,
		},
	}

	additionalScope := Scope{
		Repositories: []string{"test3", "test4"},
		Permissions: github.InstallationPermissions{
			Contents:             &read,
			Actions:              &write,
			Checks:               &write,
			OrganizationProjects: &write,
			Secrets:              &write,
		},
	}
	baseScope.merge(additionalScope)

	expectedPermissions := github.InstallationPermissions{
		Contents:             &read,
		Actions:              &write,
		Checks:               &write,
		OrganizationProjects: &admin,
		OrganizationPackages: &read,
		Secrets:              &write,
	}
	if !reflect.DeepEqual(baseScope.Repositories, []string{"test1", "test2", "test3", "test4"}) {
		t.Error("Expected baseScope.Repositories to be [test1, test2, test3, test4], but got", baseScope.Repositories)
	}
	if !reflect.DeepEqual(baseScope.Permissions, expectedPermissions) {
		t.Error("Expected scope.Permissions to be", expectedPermissions, ", but got", baseScope.Permissions)
	}
}

func TestString(t *testing.T) {
	read := "read"
	write := "write"
	admin := "admin"

	baseScope := Scope{
		Repositories: []string{"test1", "test2"},
		Permissions: github.InstallationPermissions{
			Contents:             &read,
			Checks:               &write,
			OrganizationProjects: &admin,
		},
	}
	baseScopeStr := baseScope.String()

	if baseScopeStr != "{repositories: [test1, test2], permissions: {Checks: write, Contents: read, OrganizationProjects: admin}}" {
		t.Error("Expected baseScope.String to be {repositories: [test1, test2], permissions: {Checks: write, Contents: read, OrganizationProjects: admin}}, but got", baseScopeStr)
	}
}
