package tokendings

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v4"
	"github.com/nais/jwker/jwkutils"
	jwkerv1 "github.com/nais/liberator/pkg/apis/nais.io/v1"
	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type clientRegistrationTest struct {
	input             jwkerv1.Jwker
	clientName        string
	softwareStatement string
}

var (
	test = clientRegistrationTest{
		input: jwkerv1.Jwker{
			TypeMeta: metav1.TypeMeta{
				Kind:       "Jwker",
				APIVersion: "v1",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "myapplication",
				Namespace: "mynamespace",
			},
			Spec: jwkerv1.JwkerSpec{
				AccessPolicy: &jwkerv1.AccessPolicy{
					Inbound: &jwkerv1.AccessPolicyInbound{
						Rules: []jwkerv1.AccessPolicyInboundRule{
							{
								AccessPolicyRule: jwkerv1.AccessPolicyRule{
									Application: "otherapplication",
									Namespace:   "othernamespace",
									Cluster:     "mycluster",
								},
							},
							{
								AccessPolicyRule: jwkerv1.AccessPolicyRule{
									Application: "otherapplicationinsamecluster",
									Namespace:   "othernamespace",
								},
							},
							{
								AccessPolicyRule: jwkerv1.AccessPolicyRule{
									Application: "otherapplicationinsamenamespace",
								},
							},
						},
					},
				},
			},
		},
		clientName:        "mycluster:mynamespace:myapplication",
		softwareStatement: `{"accessPolicyInbound":["mycluster:othernamespace:otherapplication","mycluster:othernamespace:otherapplicationinsamecluster","mycluster:mynamespace:otherapplicationinsamenamespace"],"accessPolicyOutbound":[],"appId":"mycluster:mynamespace:myapplication"}`,
	}
)

func TestNewInstance(t *testing.T) {
	jwk, err := jwkutils.GenerateJWK()
	assert.NoError(t, err)
	inst1 := NewInstance("http://localhost:8080", "jwker", &jwk)
	inst2 := NewInstance("http://localhost:8080/", "jwker", &jwk)
	assert.Equal(t, "http://localhost:8080/.well-known/oauth-authorization-server", inst1.WellKnownURL)
	assert.Equal(t, "http://localhost:8080/.well-known/oauth-authorization-server", inst2.WellKnownURL)
}

func TestDeleteClient(t *testing.T) {
	jwk, err := jwkutils.GenerateJWK()
	assert.NoError(t, err)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/registration/client/cluster1:team1:app1", r.URL.Path)
		assert.Equal(t, "DELETE", r.Method)
		verifyToken(t, r, jwk)

		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	td := NewInstance(server.URL, "jwker", &jwk)

	err = td.DeleteClient(context.Background(), ClientId{
		Name:      "app1",
		Namespace: "team1",
		Cluster:   "cluster1",
	})
	assert.NoError(t, err)
}

func TestRegisterClient(t *testing.T) {
	app := ClientId{
		Name:      "app1",
		Namespace: "team1",
		Cluster:   "cluster1",
	}

	jwk, err := jwkutils.GenerateJWK()
	assert.NoError(t, err)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		assert.Equal(t, "/registration/client", r.URL.Path)
		assert.Equal(t, "POST", r.Method)

		verifyToken(t, r, jwk)

		body, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		var clientRegistration ClientRegistration
		err = json.Unmarshal(body, &clientRegistration)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		assert.Equal(t, app.String(), clientRegistration.ClientName)
		assert.Equal(t, 1, len(clientRegistration.Jwks.Keys))
		assert.Equal(t, "signedstatement", clientRegistration.SoftwareStatement)

		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()

	td := NewInstance(server.URL, "jwker", &jwk)
	err = td.RegisterClient(ClientRegistration{
		ClientName: app.String(),
		Jwks: jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{
				jwk,
			},
		},
		SoftwareStatement: "signedstatement",
	})

	assert.NoError(t, err)
}

func TestMakeClientRegistration(t *testing.T) {
	signkey, err := jwkutils.GenerateJWK()
	if err != nil {
		panic(err)
	}

	appkey, err := jwkutils.GenerateJWK()
	if err != nil {
		panic(err)
	}
	appkeys := jwkutils.KeySetWithExisting(appkey, []jose.JSONWebKey{})

	clientid := ClientId{
		Name:      "myapplication",
		Namespace: "mynamespace",
		Cluster:   "mycluster",
	}

	output, err := MakeClientRegistration(&signkey, &appkeys.Public, clientid, test.input)

	assert.NoError(t, err)
	assert.Equal(t, test.clientName, output.ClientName)

	parser := new(jwt.Parser)
	claims := &jwt.MapClaims{}
	_, _, err = parser.ParseUnverified(output.SoftwareStatement, claims)
	assert.NoError(t, err)

	js, err := json.Marshal(claims)
	if err != nil {
		panic(err)
	}

	assert.Equal(t, test.softwareStatement, string(js))
}

func verifyToken(t *testing.T, r *http.Request, jwk jose.JSONWebKey) {
	raw := strings.Replace(r.Header.Get("Authorization"), "Bearer ", "", 1)
	sign, err := jose.ParseSignedCompact(raw, []jose.SignatureAlgorithm{jose.RS256})
	payload, err := sign.Verify(jwk.Public())
	assert.NoError(t, err)

	claims := CustomClaims{}
	err = json.Unmarshal(payload, &claims)
	assert.NoError(t, err)

	assert.Equal(t, "jwker", claims.Issuer)
	assert.Equal(t, "jwker", claims.Subject)

	aud, err := url.Parse(claims.Audience)
	assert.NoError(t, err)
	assert.Equal(t, "/registration/client", aud.Path)
}
