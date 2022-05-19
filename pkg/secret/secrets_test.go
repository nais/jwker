package secret

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/nais/liberator/pkg/oauth"
	"github.com/stretchr/testify/assert"
	"gopkg.in/square/go-jose.v2"
	corev1 "k8s.io/api/core/v1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/nais/jwker/pkg/config"
	"github.com/nais/jwker/pkg/tokendings"
	"github.com/nais/jwker/utils"
)

func GetAsSecret(jwk jose.JSONWebKey) (corev1.Secret, error) {
	j, err := jwk.MarshalJSON()
	if err != nil {
		panic(err)
	}
	return corev1.Secret{
		ObjectMeta: meta_v1.ObjectMeta{
			Namespace: corev1.NamespaceDefault,
			Name:      "some-secret",
		},
		Data: map[string][]byte{TokenXPrivateJwkKey: j},
	}, nil
}

func TestExtractJWK(t *testing.T) {
	jwk, err := utils.GenerateJWK()
	assert.NoError(t, err)

	secret, err := GetAsSecret(jwk)
	assert.NoError(t, err)

	extractedJwk, err := ExtractJWK(secret)

	assert.NoError(t, err)
	assert.Equal(t, JsonAsString(jwk), JsonAsString(extractedJwk))
}

func TestCreateSecretSpec(t *testing.T) {
	app := tokendings.ClientId{
		Name:      "test",
		Namespace: "test",
		Cluster:   "test",
	}
	secretName := "test-secret"
	jwk, err := utils.GenerateJWK()
	assert.NoError(t, err)

	secretData := PodSecretData{
		ClientId: app,
		Jwk:      jwk,
		TokendingsConfig: config.Tokendings{
			Metadata: &oauth.MetadataOAuth{
				MetadataCommon: oauth.MetadataCommon{
					Issuer:        "https://tokendings.example.com",
					JwksURI:       "https://tokendings.example.com/jwks",
					TokenEndpoint: "https://tokendings.example.com/token",
				},
			},
			WellKnownURL: "https://tokendings.example.com/.well-known/oauth-authorization-server",
		},
	}
	actual, err := CreateSecretSpec(secretName, secretData)
	assert.NoError(t, err)

	t.Run("should contain runtime variables", func(t *testing.T) {
		expected, err := json.Marshal(jwk)
		assert.NoError(t, err)
		assert.Equal(t, app.String(), actual.StringData[TokenXClientIdKey])
		assert.Equal(t, string(expected), actual.StringData[TokenXPrivateJwkKey])
		assert.Equal(t, "https://tokendings.example.com/.well-known/oauth-authorization-server", actual.StringData[TokenXWellKnownUrlKey])
		assert.Equal(t, "https://tokendings.example.com", actual.StringData[TokenXIssuerKey])
		assert.Equal(t, "https://tokendings.example.com/jwks", actual.StringData[TokenXJwksUriKey])
		assert.Equal(t, "https://tokendings.example.com/token", actual.StringData[TokenXTokenEndpointKey])
	})
}

func JsonAsString(v interface{}) string {
	j, err := json.MarshalIndent(v, "", " ")
	if err != nil {
		fmt.Printf("Error parsing to json: %s", err)
		os.Exit(1)
	}
	return string(j)
}
