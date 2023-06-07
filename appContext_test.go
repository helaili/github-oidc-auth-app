package main

import (
	"testing"

	"github.com/google/go-github/v52/github"
)

func TestFileBasedConfigFileAdded(t *testing.T) {
	event := github.PushEvent{
		Ref: github.String("refs/heads/master"),
		Repo: &github.PushEventRepository{
			Name: github.String(".github-private"),
			Owner: &github.User{
				Login: github.String("octodemo"),
			},
		},
		Commits: []*github.HeadCommit{
			{
				Added: []string{
					"oidc_entitlements.json",
				},
			},
		},
	}

	context := AppContext{
		configRepo: ".github-private",
		configFile: "oidc_entitlements.json",
	}

	if context.checkConfigChange(event) != true {
		t.Error("Excpected config change")
	}
}

func TestFileBasedConfigFileRemoved(t *testing.T) {
	event := github.PushEvent{
		Ref: github.String("refs/heads/master"),
		Repo: &github.PushEventRepository{
			Name: github.String(".github-private"),
			Owner: &github.User{
				Login: github.String("octodemo"),
			},
		},
		Commits: []*github.HeadCommit{
			{
				Removed: []string{
					"oidc_entitlements.json",
				},
			},
		},
	}

	context := AppContext{
		configRepo: ".github-private",
		configFile: "oidc_entitlements.json",
	}

	if context.checkConfigChange(event) != true {
		t.Error("Excpected config change")
	}
}

func TestFileBasedConfigFileModified(t *testing.T) {
	event := github.PushEvent{
		Ref: github.String("refs/heads/master"),
		Repo: &github.PushEventRepository{
			Name: github.String(".github-private"),
			Owner: &github.User{
				Login: github.String("octodemo"),
			},
		},
		Commits: []*github.HeadCommit{
			{
				Modified: []string{
					"oidc_entitlements.json",
				},
			},
		},
	}

	context := AppContext{
		configRepo: ".github-private",
		configFile: "oidc_entitlements.json",
	}

	if context.checkConfigChange(event) != true {
		t.Error("Excpected config change")
	}
}

func TestFileBasedConfigFileAddedInSecondCommit(t *testing.T) {
	event := github.PushEvent{
		Ref: github.String("refs/heads/master"),
		Repo: &github.PushEventRepository{
			Name: github.String(".github-private"),
			Owner: &github.User{
				Login: github.String("octodemo"),
			},
		},
		Commits: []*github.HeadCommit{
			{
				Added: []string{
					"dummy.yml",
				},
			},
			{
				Added: []string{
					"oidc_entitlements.json",
				},
			},
		},
	}

	context := AppContext{
		configRepo: ".github-private",
		configFile: "oidc_entitlements.json",
	}

	if context.checkConfigChange(event) != true {
		t.Error("Excpected config change")
	}
}

func TestFileBasedConfigOtherFileAdded(t *testing.T) {
	event := github.PushEvent{
		Ref: github.String("refs/heads/master"),
		Repo: &github.PushEventRepository{
			Name: github.String(".github-private"),
			Owner: &github.User{
				Login: github.String("octodemo"),
			},
		},
		Commits: []*github.HeadCommit{
			{
				Added: []string{
					"dummy.yml",
				},
			},
		},
	}

	context := AppContext{
		configRepo: ".github-private",
		configFile: "oidc_entitlements.json",
	}

	if context.checkConfigChange(event) != false {
		t.Error("Expected config didn't change")
	}
}

func TestFileBasedConfigFileAddedToOtherRepo(t *testing.T) {
	event := github.PushEvent{
		Ref: github.String("refs/heads/master"),
		Repo: &github.PushEventRepository{
			Name: github.String("dummy"),
			Owner: &github.User{
				Login: github.String("octodemo"),
			},
		},
		Commits: []*github.HeadCommit{
			{
				Added: []string{
					"oidc_entitlements.json",
				},
			},
		},
	}

	context := AppContext{
		configRepo: ".github-private",
		configFile: "oidc_entitlements.json",
	}

	if context.checkConfigChange(event) != false {
		t.Error("Expected config didn't change")
	}
}

func TestRepoBasedConfig(t *testing.T) {
	event := github.PushEvent{
		Ref: github.String("refs/heads/master"),
		Repo: &github.PushEventRepository{
			Name: github.String(".github-private"),
			Owner: &github.User{
				Login: github.String("octodemo"),
			},
		},
	}

	context := AppContext{
		configRepo: ".github-private",
	}

	if context.checkConfigChange(event) != true {
		t.Error("Expected config change")
	}
}

func TestRepoBasedConfigWrongRepo(t *testing.T) {
	event := github.PushEvent{
		Ref: github.String("refs/heads/master"),
		Repo: &github.PushEventRepository{
			Name: github.String(".dummy"),
			Owner: &github.User{
				Login: github.String("octodemo"),
			},
		},
	}

	context := AppContext{
		configRepo: ".github-private",
	}

	if context.checkConfigChange(event) != false {
		t.Error("Expected config didn't change")
	}
}
