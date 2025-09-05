package tokendings

import (
	"encoding/json"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"

	"github.com/nais/jwker/pkg/jwk"
)

func TestClientAssertion(t *testing.T) {
	jwk, err := jwk.Generate()
	assert.NoError(t, err)

	raw, err := ClientAssertion(&jwk, "client1", "http://endpoint/registration/client")
	assert.NoError(t, err)

	sign, err := jose.ParseSignedCompact(raw, []jose.SignatureAlgorithm{jose.RS256})
	assert.NoError(t, err)
	payload, err := sign.Verify(jwk.Public())
	assert.NoError(t, err)

	claims := CustomClaims{}
	err = json.Unmarshal(payload, &claims)
	assert.NoError(t, err)
	assert.Equal(t, "client1", claims.Issuer)
	assert.Equal(t, "client1", claims.Subject)
	assert.Equal(t, "http://endpoint/registration/client", claims.Audience)
}
