package tokendings_test

import (
	"fmt"
	"io/ioutil"
	"os"
	"testing"

	"github.com/nais/jwker/pkg/tokendings"
	"github.com/stretchr/testify/assert"
	"gopkg.in/square/go-jose.v2"
)

func TestGetToken(t *testing.T) {
	jwk := &jose.JSONWebKey{}
	file, err := os.Open("testdata/jwks.json")
	if err != nil {
		panic(err)
	}
	// bdec := base64.NewDecoder(base64.StdEncoding, file)
	serialized, err := ioutil.ReadAll(file)
	if err != nil {
		panic(err)
	}
	err = jwk.UnmarshalJSON(serialized)
	if err != nil {
		panic(err)
	}

	clientid := "2224a68c-b412-4040-8d9c-ca0f0b8acc20"
	scope := "api://13689a4a-187a-42ac-8a95-d87015742b45/.default"
	tenantID := "62366534-1ec3-4962-8869-9b5535279d0b"

	token, err := tokendings.GetToken(jwk, clientid, scope, tenantID)

	assert.NoError(t, err)
	fmt.Println("Access token:", token.AccessToken)
}
