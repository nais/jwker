package secret

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/nais/jwker/pkg/tokendings"
	"gopkg.in/square/go-jose.v2"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const JwksSecretKey = "jwks"

func ExtractJWKS(sec corev1.Secret) (jose.JSONWebKeySet, error) {
	jwks := jose.JSONWebKeySet{}
	err := json.Unmarshal(sec.Data[JwksSecretKey], &jwks)
	return jwks, err
}

func CreateSecretSpec(app tokendings.ClientId, secretName string, clientPrivateJwks jose.JSONWebKeySet) (corev1.Secret, error) {
	clientPrivateJwksJson, err := json.MarshalIndent(clientPrivateJwks, "", " ")
	if err != nil {
		return corev1.Secret{}, err
	}
	stringdata := map[string]string{JwksSecretKey: string(clientPrivateJwksJson)}

	return corev1.Secret{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Secret",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: app.Namespace,
			Labels:    map[string]string{"app": app.Name, "type": "nais.io"},
		},
		StringData: stringdata,
		Type:       "Opaque",
	}, nil
}

func CreateSecret(cli client.Client, ctx context.Context, app tokendings.ClientId, secretName string, clientPrivateJwks jose.JSONWebKeySet) error {
	secretSpec, err := CreateSecretSpec(app, secretName, clientPrivateJwks)
	if err != nil {
		return fmt.Errorf("Unable to create secretSpec object: %s", err)
	}

	err = cli.Create(ctx, &secretSpec)
	if errors.IsAlreadyExists(err) {
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
				return fmt.Errorf("Unable to delete clusterSecret: %s", err)
			}
		}
	}
	return nil
}

func ClusterSecrets(ctx context.Context, app tokendings.ClientId, cli client.Client) (corev1.SecretList, error) {
	var secrets corev1.SecretList
	var mLabels = client.MatchingLabels{}

	mLabels["app"] = app.Name
	mLabels["type"] = "nais.io"
	if err := cli.List(ctx, &secrets, client.InNamespace(app.Namespace), mLabels); err != nil {
		return secrets, err
	}
	return secrets, nil
}
