package tokendings

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt/v4"
	"github.com/nais/jwker/jwkutils"
	jwkerv1 "github.com/nais/liberator/pkg/apis/nais.io/v1"
	"github.com/stretchr/testify/assert"
	"gopkg.in/square/go-jose.v2"
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

func TestDeleteClient(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/registration/client/cluster1:team1:app1", r.URL.Path)
		assert.Equal(t, "DELETE", r.Method)
		assert.Equal(t, "Bearer token", r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	err := DeleteClient(context.Background(), "token", server.URL, ClientId{
		Name:      "app1",
		Namespace: "team1",
		Cluster:   "cluster1",
	})
	fmt.Printf("Error: %v\n", err)
	assert.NoError(t, err)
}

func TestRegisterClient(t *testing.T) {
	app := ClientId{
		Name:      "app1",
		Namespace: "team1",
		Cluster:   "cluster1",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		assert.Equal(t, "/registration/client", r.URL.Path)
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "Bearer token", r.Header.Get("Authorization"))

		body, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
		}

		var clientRegistration ClientRegistration
		err = json.Unmarshal(body, &clientRegistration)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
		}
		assert.Equal(t, app.String(), clientRegistration.ClientName)
		assert.Equal(t, 1, len(clientRegistration.Jwks.Keys))
		assert.Equal(t, "signedstatement", clientRegistration.SoftwareStatement)

		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()

	jwk, err := jwkutils.GenerateJWK()
	assert.NoError(t, err)

	err = RegisterClient(ClientRegistration{
		ClientName: app.String(),
		Jwks: jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{
				jwk,
			},
		},
		SoftwareStatement: "signedstatement",
	}, "token", server.URL)

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
