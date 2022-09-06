//go:build integration
// +build integration

package tokendings_test

import (
	"io/ioutil"
	"net/url"
	"os"
	"testing"

	"github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/assert"
	"gopkg.in/square/go-jose.v2"

	"github.com/nais/jwker/pkg/tokendings"
)

var (
	clientid = os.Getenv("CLIENT_ID")
	scope    = os.Getenv("SCOPE")
	endpoint = os.Getenv("AUTH_PROVIDER_URL")
)

// Retrieve a valid token from Azure, and verify that it can be used with the correct audience.
// Needs a Azure Application private JWK in the file testdata/jwk.json, and the environment variables above.
func TestGetToken(t *testing.T) {
	jwk := &jose.JSONWebKey{}
	file, err := os.Open("testdata/jwk.json")
	if err != nil {
		panic("missing test fixture: please insert your azure application JWK into testdata/jwk.json")
	}
	serialized, err := ioutil.ReadAll(file)
	if err != nil {
		panic(err)
	}
	err = jwk.UnmarshalJSON(serialized)
	if err != nil {
		panic(err)
	}

	token, err := tokendings.GetToken(jwk, clientid, scope, endpoint)

	assert.NoError(t, err)

	parser := new(jwt.Parser)
	tok, _, err := parser.ParseUnverified(token.AccessToken, jwt.MapClaims{})

	assert.NoError(t, err)

	claims, ok := tok.Claims.(jwt.MapClaims)
	if !ok {
		panic("unable to retrieve claims from token")
	}

	aud, err := url.Parse(scope)
	assert.NoError(t, err)
	assert.Equal(t, aud.Host, claims["aud"])
}
