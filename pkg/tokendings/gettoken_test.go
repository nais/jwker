package tokendings

import (
	"encoding/json"
	"github.com/nais/jwker/jwkutils"
	"github.com/stretchr/testify/assert"
	"gopkg.in/square/go-jose.v2"
	"testing"
)

func TestClientAssertion(t *testing.T) {
	jwk, err := jwkutils.GenerateJWK()
	assert.NoError(t, err)

	raw, err := ClientAssertion(&jwk, "client1", "http://endpoint/registration/client")
	assert.NoError(t, err)

	sign, err := jose.ParseSigned(raw)
	payload, err := sign.Verify(jwk.Public())
	assert.NoError(t, err)

	claims := CustomClaims{}
	err = json.Unmarshal(payload, &claims)
	assert.NoError(t, err)
	assert.Equal(t, "client1", claims.Issuer)
	assert.Equal(t, "client1", claims.Subject)
	assert.Equal(t, "http://endpoint/registration/client", claims.Audience)
}
