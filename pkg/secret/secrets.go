package secret

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/nais/jwker/pkg/tokendings"
	"gopkg.in/square/go-jose.v2"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const OldJwksKey = "jwks"
const OldJwkKey = "jwk"
const TokenXPrivateJwkKey = "TOKEN_X_PRIVATE_JWK"
const TokenXWellKnownUrlKey = "TOKEN_X_WELL_KNOWN_URL"
const TokenXClientIdKey = "TOKEN_X_CLIENT_ID"
const TokenXSecretLabelKey = "type"
const TokenXSecretLabelType = "jwker.nais.io"

type PodSecretData struct {
	ClientId               tokendings.ClientId
	Jwk                    jose.JSONWebKey
	TokenDingsWellKnownUrl string
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
		return extractOldJwk(sec)
	}

	if err := json.Unmarshal(jwkBytes, jwk); err != nil {
		return nil, err
	}

	return jwk, nil
}

//temporary func to handle renaming/changes to expected jwker secret
func extractOldJwk(sec corev1.Secret) (*jose.JSONWebKey, error) {
	jwks := &jose.JSONWebKeySet{}
	oldJwksBytes, found := sec.Data[OldJwksKey]

	if found {
		if err := json.Unmarshal(oldJwksBytes, jwks); err != nil {
			return nil, fmt.Errorf("failed to unmarshal '%s' from secret '%s': %w", OldJwksKey, sec.Name, err)
		}
		return FirstJWK(*jwks)
	}

	jwk := &jose.JSONWebKey{}
	oldJwkBytes, found := sec.Data[OldJwkKey]

	if found {
		if err := json.Unmarshal(oldJwkBytes, jwk); err != nil {
			return nil, fmt.Errorf("failed to unmarshal '%s' from secret '%s': %w", OldJwkKey, sec.Name, err)
		}
		return jwk, nil
	}

	return nil, errors.New(fmt.Sprintf("failed to find any expected keys in secret '%s'", sec.Name))
}

func CreateSecretSpec(secretName string, data PodSecretData) (corev1.Secret, error) {
	stringdata, err := stringData(data)
	if err != nil {
		return corev1.Secret{}, err
	}

	return corev1.Secret{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Secret",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: data.ClientId.Namespace,
			Labels:    map[string]string{"app": data.ClientId.Name, TokenXSecretLabelKey: TokenXSecretLabelType},
		},
		StringData: stringdata,
		Type:       "Opaque",
	}, nil
}

func CreateSecret(cli client.Client, ctx context.Context, secretName string, data PodSecretData) error {
	secretSpec, err := CreateSecretSpec(secretName, data)
	if err != nil {
		return fmt.Errorf("Unable to create secretSpec object: %s", err)
	}

	err = cli.Create(ctx, &secretSpec)
	if k8serrors.IsAlreadyExists(err) {
		err = cli.Update(ctx, &secretSpec)
	}

	if err != nil {
		return fmt.Errorf("Unable to apply secretSpec: %s", err)
	}

	return nil
}

func DeleteClusterSecrets(cli client.Client, ctx context.Context, app tokendings.ClientId, secretName string) error {
	secretList, err := ClusterSecrets(ctx, app, cli)
	if err != nil {
		return err
	}
	for _, clusterSecret := range secretList.Items {
		if clusterSecret.Name != secretName {
			if err := cli.Delete(ctx, &clusterSecret); err != nil {
				return fmt.Errorf("unable to delete clusterSecret: %w", err)
			}
		}
	}
	return nil
}

func ClusterSecrets(ctx context.Context, app tokendings.ClientId, cli client.Client) (corev1.SecretList, error) {
	var secrets corev1.SecretList
	var mLabels = client.MatchingLabels{}

	mLabels["app"] = app.Name
	mLabels[TokenXSecretLabelKey] = TokenXSecretLabelType
	if err := cli.List(ctx, &secrets, client.InNamespace(app.Namespace), mLabels); err != nil {
		return secrets, err
	}
	return secrets, nil
}

func stringData(data PodSecretData) (map[string]string, error) {
	jwkJson, err := json.Marshal(data.Jwk)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private JWK: %w", err)
	}
	return map[string]string{
		TokenXPrivateJwkKey:   string(jwkJson),
		TokenXClientIdKey:     data.ClientId.String(),
		TokenXWellKnownUrlKey: data.TokenDingsWellKnownUrl,
	}, nil
}

func WellKnownUrl(baseUrl string) string {
	return fmt.Sprintf("%s/.well-known/oauth-authorization-server", baseUrl)
}
