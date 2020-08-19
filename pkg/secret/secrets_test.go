package secret

import (
	"encoding/json"
	"fmt"
	"github.com/nais/jwker/utils"
	"github.com/stretchr/testify/assert"
	"gopkg.in/square/go-jose.v2"
	corev1 "k8s.io/api/core/v1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"os"
	"testing"
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
		Data: map[string][]byte{"jwk": j},
	}, nil
}

func TestExtractJWK(t *testing.T) {
	jwk, err := utils.GenerateJWK()
	if err != nil {
		panic(err)
	}

	secret, err := GetAsSecret(jwk)
	if err != nil {
		panic(err)
	}

	extractedJwk, err := ExtractJWK(secret)

	assert.NoError(t, err)
	assert.Equal(t, JsonAsString(jwk), JsonAsString(extractedJwk))
}

func JsonAsString(v interface{}) []byte {
	j, err := json.MarshalIndent(v, "", " ")
	if err != nil {
		fmt.Printf("Error parsing to json: %s", err)
		os.Exit(1)
	}
	return j
}
