package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"reflect"
	"regexp"
	"strings"

	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/go-git/go-git/v5"
	githttp "github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/go-github/v53/github"
)

type EntitlementConfig struct {
	Login          string
	InstallationId int64
	GitUrl         string
	Repo           string
	File           string
	Entitlements   []Entitlement
}

func NewEntitlementConfig(Login string, InstallationId int64, GitUrl, Repo, File string) *EntitlementConfig {
	entitlements := make([]Entitlement, 0)
	return &EntitlementConfig{Login, InstallationId, GitUrl, Repo, File, entitlements}
}

func (config *EntitlementConfig) load(appTransport *ghinstallation.AppsTransport) error {
	itr := ghinstallation.NewFromAppsTransport(appTransport, config.InstallationId)
	// Use installation transport with github.com/google/go-github
	client := github.NewClient(&http.Client{Transport: itr})

	if config.File != "" {
		log.Printf("loading config for org %s from file %s in repo %s\n", config.Login, config.File, config.Repo)

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
	} else {
		log.Printf("loading config for org %s from repo %s/%s/%s\n", config.Login, config.GitUrl, config.Login, config.Repo)

		// Need to clean up the download directory before cloning the repo
		os.RemoveAll(fmt.Sprintf("/tmp/%s/%s", config.Login, config.Repo))

		token, err := itr.Token(context.Background())
		if err != nil {
			log.Printf("couldn't get token for installation %d on org %s", config.InstallationId, config.Login)
			return err
		}

		_, err = git.PlainClone(fmt.Sprintf("/tmp/%s/%s", config.Login, config.Repo), false, &git.CloneOptions{
			URL:      fmt.Sprintf("%s/%s/%s", config.GitUrl, config.Login, config.Repo),
			Auth:     &githttp.BasicAuth{Username: "username", Password: token},
			Progress: os.Stdout,
		})
		if err != nil {
			log.Printf("couldn't clone repo %s/%s/%s", config.GitUrl, config.Login, config.Repo)
			return err
		}

		// iterate over all files in the directory
		files, err := os.ReadDir(fmt.Sprintf("/tmp/%s/%s", config.Login, config.Repo))
		if err != nil {
			log.Printf("couldn't read directory /tmp/%s/%s", config.Login, config.Repo)
			return err
		}
		config.loadFolder(fmt.Sprintf("/tmp/%s/%s", config.Login, config.Repo), files, true)

	}
	log.Printf("Loaded %d entitlements for org %s", len(config.Entitlements), config.Login)
	return nil
}

/*
 * Strip all the permissions but the one matching the one defined by the folder name .e.g. organization/<permissionName>
 */
func (config *EntitlementConfig) stripAllPermissionsBut(permissionName string, permission string, entitlement *Entitlement) {
	jsonString := fmt.Sprintf(`{"%s": "%s"}`, permissionName, permission)
	permissionObj := github.InstallationPermissions{}

	err := json.Unmarshal([]byte(jsonString), &permissionObj)
	if err != nil {
		log.Printf("failed to create permission %s", jsonString)
	}
	entitlement.Scopes.Permissions = permissionObj
}

/*
 * Strip all the org level permissions when the entitlement is defined uner the repositories folder
 */
func (config *EntitlementConfig) stripAllOrgPermissions(entitlement *Entitlement) {
	// Get all the fields of the Permissions struct
	fields := reflect.VisibleFields(reflect.TypeOf(struct{ github.InstallationPermissions }{}))
	// Get all the permissions set in the entitlement
	reflectScope := reflect.ValueOf(&entitlement.Scopes.Permissions).Elem()

	for _, field := range fields {
		value := reflectScope.FieldByName(field.Name)

		// Has this filed been set? If its name starts with 'Organization' set it to zero
		if value.IsValid() && !value.IsZero() && strings.HasPrefix(field.Name, "Organization") {
			value.Set(reflect.Zero(value.Type()))
		}
	}
}

func (config *EntitlementConfig) loadFolder(path string, files []fs.DirEntry, isRoot bool) error {
	// Regex to find the section right after /repositories/ in the path
	targetRepoRegex := regexp.MustCompile(`\/repositories\/([^\/]+)\/`)
	// Regex to find the section right after /owner/ in the path
	ownerRegex := regexp.MustCompile(`.*\/owner\/([^\/]+)\/`)
	// Regex to find the section right after /owner/xxxx/repository in the path
	sourceRepoRegex := regexp.MustCompile(`\/owner\/[^\/]+\/repository\/([^\/]+)\/`)
	// Regex to find the section right after /owner/ in the path
	envRegex := regexp.MustCompile(`.*\/environment\/([^\/]+)\/`)
	// Regex to find the section right after /organization/ in the path
	orgRegex := regexp.MustCompile(`.*\/organization\/([^\/]+)\/(read|admin|write)\/`)

	skipFiles := false
	// the directories below are not supposed to contain entitlement files
	if strings.HasSuffix(path, "/repositories") || strings.HasSuffix(path, "/environment") || strings.HasSuffix(path, "/owner") || strings.HasSuffix(path, "/organization") || strings.HasSuffix(path, "/repository/") {
		skipFiles = true
	}

	for _, file := range files {
		fullPath := fmt.Sprintf("%s/%s", path, file.Name())

		if strings.HasSuffix(file.Name(), ".json") && !skipFiles {
			// This is a JSON configuration file

			jsonFile, err := os.Open(fullPath)
			if err != nil {
				log.Printf("couldn't open file %s: %s", fullPath, err)
				return err
			}
			defer jsonFile.Close()

			// Parse the oidc_entitlements.json file as JSON
			var entitlement Entitlement
			err = json.NewDecoder(jsonFile).Decode(&entitlement)
			if err != nil {
				log.Printf("failed to parse JSON file %s: %s", fullPath, err)
				return err
			}

			// an owner (of a client repository) is present in the path, so we can use it as the owner of the repository in the claims
			ownerName := ownerRegex.FindStringSubmatch(fullPath)
			if ownerName != nil {
				entitlement.RepositoryOwner = ownerName[1]
			}

			sourceRepoName := sourceRepoRegex.FindStringSubmatch(fullPath)
			if sourceRepoName != nil && entitlement.RepositoryOwner != "" {
				// a client repository name is present in the path, so we can use it as the repository full name (owner/name) in the claims
				entitlement.Repository = fmt.Sprintf("%s/%s", entitlement.RepositoryOwner, sourceRepoName[1])
			}

			repoName := targetRepoRegex.FindStringSubmatch(fullPath)
			if repoName != nil {
				// A target repository name is present in the path, so we can use it as the repository name in the scope
				// Any previously set list of repositories is discarded
				entitlement.Scopes.Repositories = repoName[1:]
			}

			// an environment is present in the path, so we can use it in the claims
			envName := envRegex.FindStringSubmatch(fullPath)
			if envName != nil {
				entitlement.Environment = envName[1]
			}

			orgPermissionName := orgRegex.FindStringSubmatch(fullPath)
			if orgPermissionName != nil {
				// we are under the orgnization/<permission> folder, so we can use the folder name as the unique permission name
				config.stripAllPermissionsBut(fmt.Sprintf("organization_%s", orgPermissionName[1]), orgPermissionName[2], &entitlement)
				// Whatever repo access needs to be removed
				entitlement.Scopes.Repositories = nil

			} else if !isRoot {
				// We are not under the orgnization/<permission> folder and not at the root, so we need to strip all organization permissions
				config.stripAllOrgPermissions(&entitlement)
			}

			config.Entitlements = append(config.Entitlements, entitlement)

		} else if file.IsDir() && file.Name() != ".git" {
			// This is a subfolder, we need to load it recursively

			subFolderPath := fmt.Sprintf("%s/%s", path, file.Name())
			subFolderFiles, err := os.ReadDir(subFolderPath)
			if err != nil {
				log.Printf("couldn't read directory %s: %s", subFolderPath, err)
				return err
			}
			err = config.loadFolder(subFolderPath, subFolderFiles, false)
			if err != nil {
				log.Printf("couldn't load folder %s: %s", subFolderPath, err)
				return err
			}
		}
	}
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
			if config.File == "" {
				// This is a repo based config
				entitlementStr, _ := json.Marshal(config.Entitlements)
				log.Printf("Found match with %s\n", entitlementStr)
			}
		}
	}
	return scope
}
