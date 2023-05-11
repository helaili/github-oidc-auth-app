package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestGetKeyForTokenMaker(t *testing.T) {
	// Create a JWKS for verifying tokens
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	pubKey := privateKey.Public().(*rsa.PublicKey)

	jwk := JWK{Kty: "RSA", Kid: "testKey", Alg: "RS256", Use: "sig"}
	jwk.N = base64.RawURLEncoding.EncodeToString(pubKey.N.Bytes())
	jwk.E = "AQAB"

	jwks := JWKS{Keys: []JWK{jwk}}

	jwksBytes, _ := json.Marshal(jwks)
	getKeyFunc := getKeyFromJwks(jwksBytes)

	// Test token referencing known key
	tokenClaims := jwt.MapClaims{"for": "testing"}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, tokenClaims)

	token.Header["kid"] = "testKey"

	key, err := getKeyFunc(token)
	if err != nil {
		t.Error(err)
	}
	if key.(*rsa.PublicKey).N.Cmp(pubKey.N) != 0 {
		t.Error("public key does not match")
	}

	// Test token referencing unknown key
	token.Header["kid"] = "unknownKey"
	key, err = getKeyFunc(token)
	if err == nil {
		t.Error("Should fail when passed unknown key")
	}

	// Test token fails with any other signing key than RSA
	tokenHmac := jwt.NewWithClaims(jwt.SigningMethodHS256, tokenClaims)

	key, err = getKeyFunc(tokenHmac)
	if err == nil {
		t.Error("Should fail any signing algorithm other than RSA")
	}
}

func TestValidateTokenCameFromGitHub(t *testing.T) {
	// Create a JWKS for verifying tokens
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	pubKey := privateKey.Public().(*rsa.PublicKey)

	jwk := JWK{Kty: "RSA", Kid: "testKey", Alg: "RS256", Use: "sig"}
	jwk.N = base64.RawURLEncoding.EncodeToString(pubKey.N.Bytes())
	jwk.E = "AQAB"

	jwks := JWKS{Keys: []JWK{jwk}}
	jwksBytes, _ := json.Marshal(jwks)

	gatewayContext := &GatewayContext{jwksCache: jwksBytes, jwksLastUpdate: time.Now()}

	// Test token signed in the expected way
	tokenClaims := jwt.MapClaims{"for": "testing"}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, tokenClaims)
	token.Header["kid"] = "testKey"

	signedToken, err := token.SignedString(privateKey)
	if err != nil {
		panic(err)
	}

	claims, err := validateTokenCameFromGitHub(signedToken, gatewayContext)

	if err != nil {
		t.Error(err)
	}
	if claims["for"] != "testing" {
		t.Error("Unable to find claims")
	}

	// Test signing with a unknown key is not allowed
	otherPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	signedToken, err = token.SignedString(otherPrivateKey)
	if err != nil {
		panic(err)
	}

	claims, err = validateTokenCameFromGitHub(signedToken, gatewayContext)
	if err == nil {
		t.Error("Should not validate token signed with other key")
	}

	// Test unsigned token is not allowed
	unsigendToken := jwt.NewWithClaims(jwt.SigningMethodNone, tokenClaims)
	unsigendToken.Header["kid"] = "testKey"

	noneToken, err := token.SignedString("none signing method allowed")

	claims, err = validateTokenCameFromGitHub(noneToken, gatewayContext)
	if err == nil {
		t.Error("Should not validate unsigned token")
	}
}

func TestStringifyCompleteMapClaims(t *testing.T) {
	claims := jwt.MapClaims{
		"actor":                 "helaili",
		"actor_id":              2787414,
		"aud":                   "api://ActionsOIDCGateway",
		"base_ref":              "refs/heads/main",
		"environment":           "production",
		"event_name":            "workflow_dispatch",
		"head_ref":              "refs/heads/main",
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

	strMapClaims := stringifyMapClaims(claims)
	if strMapClaims != "actor:helaili,actor_id:2787414,aud:api://ActionsOIDCGateway,base_ref:refs/heads/main,environment:production,event_name:workflow_dispatch,head_ref:refs/heads/main,iss:https://token.actions.githubusercontent.com,job_workflow_ref:helaili/github-oidc-auth-app/.github/workflows/manual-test.yml@refs/heads/main,job_workflow_sha:44216e5ae99f3653290b60b7f995bfe1c0f3aba0,ref:refs/heads/main,ref_type:branch,repository:helaili/github-oidc-auth-app,repository_id:630836305,repository_owner:helaili,repository_owner_id:2787414,repository_visibility:public,run_attempt:1,run_id:4779904167,run_number:12,runner_environment:github-hosted,sub:repo:helaili/github-oidc-auth-app:ref:refs/heads/main,workflow:Manual Test Workflow,workflow_ref:helaili/github-oidc-auth-app/.github/workflows/manual-test.yml@refs/heads/main,workflow_sha:44216e5ae99f3653290b60b7f995bfe1c0f3aba0" {
		t.Error("Expected stringified map claims to be actor:helaili,actor_id:2787414,aud:api://ActionsOIDCGateway,base_ref:refs/heads/main,environment:production,event_name:workflow_dispatch,head_ref:refs/heads/main,iss:https://token.actions.githubusercontent.com,job_workflow_ref:helaili/github-oidc-auth-app/.github/workflows/manual-test.yml@refs/heads/main,job_workflow_sha:44216e5ae99f3653290b60b7f995bfe1c0f3aba0,ref:refs/heads/main,ref_type:branch,repository:helaili/github-oidc-auth-app,repository_id:630836305,repository_owner:helaili,repository_owner_id:2787414,repository_visibility:public,run_attempt:1,run_id:4779904167,run_number:12,runner_environment:github-hosted,sub:repo:helaili/github-oidc-auth-app:ref:refs/heads/main,workflow:Manual Test Workflow,workflow_ref:helaili/github-oidc-auth-app/.github/workflows/manual-test.yml@refs/heads/main,workflow_sha:44216e5ae99f3653290b60b7f995bfe1c0f3aba0, but got", strMapClaims)
	}
}

func TestStringifyPartialMapClaims(t *testing.T) {
	claims := jwt.MapClaims{
		"actor":                 "helaili",
		"event_name":            "workflow_dispatch",
		"ref":                   "refs/heads/main",
		"repository":            "helaili/github-oidc-auth-app",
		"repository_owner":      "helaili",
		"repository_visibility": "public",
		"workflow":              "Manual Test Workflow",
	}

	strMapClaims := stringifyMapClaims(claims)
	if strMapClaims != "actor:helaili,actor_id:XXXNOTSETXXX,aud:XXXNOTSETXXX,base_ref:XXXNOTSETXXX,environment:XXXNOTSETXXX,event_name:workflow_dispatch,head_ref:XXXNOTSETXXX,iss:XXXNOTSETXXX,job_workflow_ref:XXXNOTSETXXX,job_workflow_sha:XXXNOTSETXXX,ref:refs/heads/main,ref_type:XXXNOTSETXXX,repository:helaili/github-oidc-auth-app,repository_id:XXXNOTSETXXX,repository_owner:helaili,repository_owner_id:XXXNOTSETXXX,repository_visibility:public,run_attempt:XXXNOTSETXXX,run_id:XXXNOTSETXXX,run_number:XXXNOTSETXXX,runner_environment:XXXNOTSETXXX,sub:XXXNOTSETXXX,workflow:Manual Test Workflow,workflow_ref:XXXNOTSETXXX,workflow_sha:XXXNOTSETXXX" {
		t.Error("Expected stringified map claims to be actor:helaili,actor_id:XXXNOTSETXXX,aud:XXXNOTSETXXX,base_ref:XXXNOTSETXXX,environment:XXXNOTSETXXX,event_name:workflow_dispatch,head_ref:XXXNOTSETXXX,iss:XXXNOTSETXXX,job_workflow_ref:XXXNOTSETXXX,job_workflow_sha:XXXNOTSETXXX,ref:refs/heads/main,ref_type:XXXNOTSETXXX,repository:helaili/github-oidc-auth-app,repository_id:XXXNOTSETXXX,repository_owner:helaili,repository_owner_id:XXXNOTSETXXX,repository_visibility:public,run_attempt:XXXNOTSETXXX,run_id:XXXNOTSETXXX,run_number:XXXNOTSETXXX,runner_environment:XXXNOTSETXXX,sub:XXXNOTSETXXX,workflow:Manual Test Workflow,workflow_ref:XXXNOTSETXXX,workflow_sha:XXXNOTSETXXX, but got", strMapClaims)
	}
}
