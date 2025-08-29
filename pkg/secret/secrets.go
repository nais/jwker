package secret

import (
	"encoding/json"
	"fmt"

	"github.com/go-jose/go-jose/v4"
	"github.com/nais/jwker/pkg/tokendings"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	TokenXClientIdKey      = "TOKEN_X_CLIENT_ID"
	TokenXIssuerKey        = "TOKEN_X_ISSUER"
	TokenXJwksUriKey       = "TOKEN_X_JWKS_URI"
	TokenXPrivateJwkKey    = "TOKEN_X_PRIVATE_JWK"
	TokenXTokenEndpointKey = "TOKEN_X_TOKEN_ENDPOINT"
	TokenXWellKnownUrlKey  = "TOKEN_X_WELL_KNOWN_URL"

	TokenXSecretLabelKey  = "type"
	TokenXSecretLabelType = "jwker.nais.io"

	StakaterReloaderAnnotationKey = "reloader.stakater.com/match"
)

type PodSecretData struct {
	ClientId   tokendings.ClientId
	Jwk        jose.JSONWebKey
	Tokendings tokendings.Instance
}

func FirstJWK(jwks jose.JSONWebKeySet) (*jose.JSONWebKey, error) {
	keysLen := len(jwks.Keys)
	if keysLen != 1 {
		return nil, fmt.Errorf("secret has %d keys, expecting exactly 1", keysLen)
	}
	return &jwks.Keys[0], nil
}

func ExtractJWK(sec corev1.Secret) (*jose.JSONWebKey, error) {
	jwk := &jose.JSONWebKey{}

	jwkBytes, found := sec.Data[TokenXPrivateJwkKey]
	if !found {
		return nil, fmt.Errorf("failed to find any expected keys in secret '%s'", sec.Name)
	}

	if err := json.Unmarshal(jwkBytes, jwk); err != nil {
		return nil, err
	}

	return jwk, nil
}

func CreateSecretSpec(secretName string, data PodSecretData) (*corev1.Secret, error) {
	jwkJson, err := json.Marshal(data.Jwk)
	if err != nil {
		return nil, fmt.Errorf("marshalling private JWK: %w", err)
	}

	wellKnownURL, err := data.Tokendings.Metadata.WellKnownURL()
	if err != nil {
		return nil, fmt.Errorf("constructing well-known URL: %w", err)
	}

	return &corev1.Secret{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Secret",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: data.ClientId.Namespace,
			Labels:    Labels(data.ClientId.Name),
			Annotations: map[string]string{
				StakaterReloaderAnnotationKey: "true",
			},
		},
		StringData: map[string]string{
			TokenXPrivateJwkKey:    string(jwkJson),
			TokenXClientIdKey:      data.ClientId.String(),
			TokenXWellKnownUrlKey:  wellKnownURL,
			TokenXIssuerKey:        data.Tokendings.Metadata.Issuer,
			TokenXJwksUriKey:       data.Tokendings.Metadata.JwksURI,
			TokenXTokenEndpointKey: data.Tokendings.Metadata.TokenEndpoint,
		},
		Type: corev1.SecretTypeOpaque,
	}, nil
}

func Labels(appName string) map[string]string {
	return map[string]string{
		"app":                appName,
		TokenXSecretLabelKey: TokenXSecretLabelType,
	}
}
