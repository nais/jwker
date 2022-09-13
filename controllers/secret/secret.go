package secret

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/go-logr/logr"
	"github.com/nais/jwker/pkg/config"
	"github.com/nais/jwker/utils"
	"gopkg.in/square/go-jose.v2"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const (
	JWKKeyName        = "privateJWK"
	PrivateSecretName = "jwker-private-jwk"
)

func SetupJwkerJwk(ctx context.Context, client kubernetes.Interface, cfg *config.Config, logger logr.Logger) error {
	jwk, err := ensurePrivateJWKSecret(ctx, client, cfg.Namespace)
	if err != nil {
		logger.Error(err, "unable to read or create private jwk secret")
		return err
	}
	// TODO: consider removing this from config struct
	cfg.AuthProvider.ClientJwk = jwk

	if err := ensurePublicSecret(ctx, client, cfg.Namespace, cfg.SharedPublicSecretName, jwk); err != nil {
		logger.Error(err, "unable to create public jwk secret")
		return err
	}
	return nil
}

func ensurePublicSecret(ctx context.Context, c kubernetes.Interface, namespace string, name string, jwk *jose.JSONWebKey) error {
	existing, err := getSecret(ctx, c, namespace, name)
	if err != nil {
		return err
	}
	if existing != nil {
		//secret already exists
		return nil
	}
	keySet := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk.Public()}}
	b, err := json.Marshal(&keySet)
	if err != nil {
		return err
	}
	return createSecret(ctx, c, namespace, name, map[string]string{"AUTH_CLIENT_JWKS": string(b)})
}

func parseJWK(json []byte) (*jose.JSONWebKey, error) {
	jwk := &jose.JSONWebKey{}
	if err := jwk.UnmarshalJSON(json); err != nil {
		return nil, err
	}

	return jwk, nil
}

func ensurePrivateJWKSecret(ctx context.Context, c kubernetes.Interface, namespace string) (*jose.JSONWebKey, error) {
	privateJWKSecret, err := getSecret(ctx, c, namespace, PrivateSecretName)
	if err != nil {
		return nil, err
	}

	if privateJWKSecret != nil {
		jwkJSON := privateJWKSecret.Data[JWKKeyName]
		if len(jwkJSON) == 0 {
			return nil, fmt.Errorf("no %s key in secret: %s", JWKKeyName, PrivateSecretName)
		}
		return parseJWK(jwkJSON)
	}

	jwk, err := utils.GenerateJWK()
	if err != nil {
		return nil, fmt.Errorf("failed to generate JWK: %w", err)
	}

	jwkJson, err := json.Marshal(jwk)
	if err != nil {
		return nil, err
	}
	data := map[string]string{
		"privateJWK": string(jwkJson),
	}

	if err := createSecret(ctx, c, namespace, PrivateSecretName, data); err != nil {
		return nil, fmt.Errorf("failed to create secret: %w", err)
	}

	return &jwk, nil
}

func createSecret(ctx context.Context, c kubernetes.Interface, namespace, name string, data map[string]string) error {
	s := &corev1.Secret{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Secret",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		StringData: data,
		Type:       "Opaque",
	}
	_, err := c.CoreV1().Secrets(namespace).Create(ctx, s, metav1.CreateOptions{})
	return err
}

func getSecret(ctx context.Context, c kubernetes.Interface, namespace, secretName string) (*corev1.Secret, error) {
	secret, err := c.CoreV1().Secrets(namespace).Get(ctx, secretName, metav1.GetOptions{})
	if errors.IsNotFound(err) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return secret, nil
}
