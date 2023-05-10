package main

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
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
		return nil, err
	}

	claims, ok := oidcToken.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("unable to map JWT claims")
	}

	return claims, nil
}

func stringifyMapClaims(claims jwt.MapClaims) string {
	return "actor:" + claimFieldValue(claims["actor"]) +
		",environment:" + claimFieldValue(claims["environment"]) +
		",event_name:" + claimFieldValue(claims["event_name"]) +
		",ref:" + claimFieldValue(claims["ref"]) +
		",repository:" + claimFieldValue(claims["repository"]) +
		",repository_owner:" + claimFieldValue(claims["repository_owner"]) +
		",repository_visibility:" + claimFieldValue(claims["repository_visibility"]) +
		",workflow:" + claimFieldValue(claims["workflow"])
}

func claimFieldValue(value interface{}) string {
	if value == nil {
		// This is to make sure we have a consistent representation of the claim for the regex matching
		return "XXXNOTSETXXX"
	} else {
		return fmt.Sprint(value)
	}
}
