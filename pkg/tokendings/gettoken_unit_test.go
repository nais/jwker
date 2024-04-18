package tokendings_test

import (
	"encoding/json"
	"net"
	"net/http"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"

	"github.com/nais/jwker/jwkutils"
	"github.com/nais/jwker/pkg/tokendings"
)

type handler struct {
	t        *testing.T
	jwk      *jose.JSONWebKey
	endpoint string
	issuer   string
}

func (h *handler) serveToken(w http.ResponseWriter, r *http.Request) {

	err := r.ParseForm()
	assert.NoError(h.t, err)
	scope := r.Form.Get("scope")
	assert.Equal(h.t, "tokendings", scope)

	assertion := r.Form.Get("client_assertion")
	sign, err := jose.ParseSignedCompact(assertion, []jose.SignatureAlgorithm{jose.RS256})
	payload, err := sign.Verify(h.jwk.Public())
	assert.NoError(h.t, err)

	claims := tokendings.CustomClaims{}
	err = json.Unmarshal(payload, &claims)
	assert.NoError(h.t, err)
	assert.Equal(h.t, h.endpoint, claims.Audience)
	assert.Equal(h.t, h.issuer, claims.Issuer)
	assert.Equal(h.t, h.issuer, claims.Subject)

	response := tokendings.TokenResponse{}
	json.NewEncoder(w).Encode(response)
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		h.serveToken(w, r)
	}
}

// Retrieve a valid token from Mock, and verify that it can be used with the correct audience.
// Needs a Azure Application private JWK in the file testdata/jwk.json, and the environment variables above.
func TestGetTokenLocally(t *testing.T) {
	clientid := "jwker-client-id"
	scope := "tokendings"
	jwk, err := jwkutils.GenerateJWK()

	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	endpoint := "http://" + listener.Addr().String()
	assert.NoError(t, err)
	assert.NotNil(t, listener)
	h := &handler{
		t:        t,
		jwk:      &jwk,
		endpoint: endpoint,
		issuer:   clientid,
	}
	go http.Serve(listener, h)

	_, err = tokendings.GetToken(&jwk, clientid, scope, endpoint)

	assert.NoError(t, err)
}
