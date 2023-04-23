package main

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/golang-jwt/jwt"
	"github.com/google/go-github/v52/github"
	"github.com/joho/godotenv"
)

type JWK struct {
	N   string
	Kty string
	Kid string
	Alg string
	E   string
	Use string
	X5c []string
	X5t string
}

type JWKS struct {
	Keys []JWK
}

type GatewayContext struct {
	jwksCache      []byte
	jwksLastUpdate time.Time
	client         *github.Client
}

type ScopedTokenRequest struct {
	OIDCToken      string `json:"oidcToken"`
	InstallationId int64  `json:"installationId"`
}

type ScopedTokenResponse struct {
	GitHubToken    string `json:"githubToken"`
	InstallationId int64  `json:"installationId"`
}

func getKeyFromJwks(jwksBytes []byte) func(*jwt.Token) (interface{}, error) {
	return func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		var jwks JWKS
		if err := json.Unmarshal(jwksBytes, &jwks); err != nil {
			return nil, fmt.Errorf("unable to parse JWKS")
		}

		for _, jwk := range jwks.Keys {
			if jwk.Kid == token.Header["kid"] {
				nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
				if err != nil {
					return nil, fmt.Errorf("unable to parse key")
				}
				var n big.Int

				eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
				if err != nil {
					return nil, fmt.Errorf("unable to parse key")
				}
				var e big.Int

				key := rsa.PublicKey{
					N: n.SetBytes(nBytes),
					E: int(e.SetBytes(eBytes).Uint64()),
				}

				return &key, nil
			}
		}

		return nil, fmt.Errorf("unknown kid: %v", token.Header["kid"])
	}
}

func validateTokenCameFromGitHub(oidcTokenString string, gc *GatewayContext) (jwt.MapClaims, error) {
	// Check if we have a recently cached JWKS
	now := time.Now()

	if now.Sub(gc.jwksLastUpdate) > time.Minute || len(gc.jwksCache) == 0 {
		resp, err := http.Get("https://token.actions.githubusercontent.com/.well-known/jwks")
		if err != nil {
			fmt.Println(err)
			return nil, fmt.Errorf("unable to get JWKS configuration")
		}

		jwksBytes, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			fmt.Println(err)
			return nil, fmt.Errorf("unable to get JWKS configuration")
		}

		gc.jwksCache = jwksBytes
		gc.jwksLastUpdate = now
	}

	// Attempt to validate JWT with JWKS
	oidcToken, err := jwt.Parse(string(oidcTokenString), getKeyFromJwks(gc.jwksCache))
	if err != nil || !oidcToken.Valid {
		return nil, fmt.Errorf("unable to validate JWT")
	}

	claims, ok := oidcToken.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("unable to map JWT claims")
	}

	return claims, nil
}

func generateScopedToken(client *github.Client, installationId int64) (ScopedTokenResponse, error) {
	repoName := [1]string{"website"}
	opts := &github.InstallationTokenOptions{Repositories: repoName[:]}
	// opts := &github.InstallationTokenOptions{}

	token, _, err := client.Apps.CreateInstallationToken(context.Background(), installationId, opts)
	if err != nil {
		log.Println("failed to get scoped token:", err)
		return ScopedTokenResponse{}, err
	}

	return ScopedTokenResponse{InstallationId: installationId, GitHubToken: token.GetToken()}, nil
}

func (gatewayContext *GatewayContext) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	// Ping method to check we are up
	if req.Method == http.MethodGet && req.RequestURI == "/ping" {
		defer req.Body.Close()

		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("Ok\n"))
		return
	}

	if req.Method != http.MethodPost && req.RequestURI != "/token" {
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		return
	}

	defer req.Body.Close()

	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		log.Println("Error retrieving request body.", err)
		http.Error(w, http.StatusText(http.StatusNoContent), http.StatusNoContent)
		return
	}

	var scopedTokenRequest ScopedTokenRequest
	err = json.Unmarshal([]byte(body), &scopedTokenRequest)
	if err != nil {
		log.Println("Error unmarshaling data from request.", err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	// Check that the OIDC token verifies as a valid token from GitHub
	claims, err := validateTokenCameFromGitHub(scopedTokenRequest.OIDCToken, gatewayContext)
	if err != nil {
		log.Println(err)
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}

	fmt.Println(claims)

	// Token is valid. We now need to generate a new token that is specific to our use case
	scopedTokenResponse, err := generateScopedToken(gatewayContext.client, scopedTokenRequest.InstallationId)
	if err != nil {
		log.Println(err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	// Return the new token to the client
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(scopedTokenResponse)
}

func main() {
	godotenv.Load()
	port := os.Getenv("PORT")
	private_key := os.Getenv("PRIVATE_KEY")
	app_id, err := strconv.ParseInt(os.Getenv("APP_ID"), 10, 36)
	if err != nil {
		log.Fatal("Wrong format for APP_ID")
	}

	fmt.Printf("starting up on port %s\n", port)

	appTransport, err := ghinstallation.NewAppsTransport(http.DefaultTransport, app_id, []byte(private_key))
	if err != nil {
		log.Fatal("Failed to initialize GitHub App transport:", err)
	}

	// Use installation transport with github.com/google/go-github
	client := github.NewClient(&http.Client{Transport: appTransport})

	gatewayContext := &GatewayContext{jwksLastUpdate: time.Now(), client: client}

	server := http.Server{
		Addr:         fmt.Sprintf(":%s", port),
		Handler:      gatewayContext,
		ReadTimeout:  60 * time.Second,
		WriteTimeout: 60 * time.Second,
	}

	server.ListenAndServe()

}
