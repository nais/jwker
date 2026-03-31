package secret

import (
	"encoding/json"
	"fmt"

	"github.com/go-jose/go-jose/v4"
	"github.com/nais/jwker/pkg/tokendings"
	"github.com/nais/liberator/pkg/kubernetes"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	TokenXClientIDKey      = "TOKEN_X_CLIENT_ID"
	TokenXIssuerKey        = "TOKEN_X_ISSUER"
	TokenXJwksURIKey       = "TOKEN_X_JWKS_URI"
	TokenXPrivateJWKKey    = "TOKEN_X_PRIVATE_JWK"
	TokenXTokenEndpointKey = "TOKEN_X_TOKEN_ENDPOINT"
	TokenXWellKnownURLKey  = "TOKEN_X_WELL_KNOWN_URL"

	TokenXSecretLabelKey  = "type"
	TokenXSecretLabelType = "jwker.nais.io"

	StakaterReloaderAnnotationKey = "reloader.stakater.com/match"
)

var ErrNotFound = fmt.Errorf("not found")

type Data struct {
	ClientID   tokendings.ClientID
	Jwk        jose.JSONWebKey
	Tokendings tokendings.Instance
}

func ExtractJWK(sec corev1.Secret) (jose.JSONWebKey, error) {
	jwk := &jose.JSONWebKey{}

	jwkBytes, found := sec.Data[TokenXPrivateJWKKey]
	if !found {
		return jose.JSONWebKey{}, fmt.Errorf("failed to find any expected keys in secret '%s'", sec.Name)
	}

	if err := json.Unmarshal(jwkBytes, jwk); err != nil {
		return jose.JSONWebKey{}, err
	}

	return *jwk, nil
}

func ExtractCurrentJWK(secretName string, secrets kubernetes.SecretLists) (jose.JSONWebKey, error) {
	allSecrets := append(secrets.Unused.Items, secrets.Used.Items...)

	for _, secret := range allSecrets {
		if secret.Name == secretName {
			return ExtractJWK(secret)
		}
	}

	return jose.JSONWebKey{}, ErrNotFound
}

func ExtractPreviousInUseJWKSet(secrets kubernetes.SecretLists) (jose.JSONWebKeySet, error) {
	previousJwks := jose.JSONWebKeySet{}

	for _, usedSecret := range secrets.Used.Items {
		key, err := ExtractJWK(usedSecret)
		if err != nil {
			return jose.JSONWebKeySet{}, err
		}

		previousJwks.Keys = append(previousJwks.Keys, key)
	}

	return previousJwks, nil
}

func CreateSecretSpec(secretName string, data Data) (*corev1.Secret, error) {
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
			Namespace: data.ClientID.Namespace,
			Labels:    Labels(data.ClientID.Name),
			Annotations: map[string]string{
				StakaterReloaderAnnotationKey: "true",
			},
		},
		StringData: map[string]string{
			TokenXPrivateJWKKey:    string(jwkJson),
			TokenXClientIDKey:      data.ClientID.String(),
			TokenXWellKnownURLKey:  wellKnownURL,
			TokenXIssuerKey:        data.Tokendings.Metadata.Issuer,
			TokenXJwksURIKey:       data.Tokendings.Metadata.JwksURI,
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
