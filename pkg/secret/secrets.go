package secret

import (
	"context"
	"encoding/json"
	"fmt"

	jwkermetrics "github.com/nais/jwker/pkg/metrics"
	"github.com/nais/jwker/pkg/tokendings"
	"gopkg.in/square/go-jose.v2"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func CreateSecretSpec(app tokendings.ClientId, secretName string, clientPrivateJwks jose.JSONWebKeySet) (corev1.Secret, error) {
	clientPrivateJwksJson, err := json.MarshalIndent(clientPrivateJwks, "", " ")
	if err != nil {
		return corev1.Secret{}, err
	}
	stringdata := map[string]string{"jwks": string(clientPrivateJwksJson)}

	return corev1.Secret{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Secret",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: app.Namespace,
			Labels:    map[string]string{"app": app.Name, "type": "jwker.nais.io"},
		},
		StringData: stringdata,
		Type:       "Opaque",
	}, nil
}

func ReconcileSecrets(cli client.Client, ctx context.Context, app tokendings.ClientId, secretName string, clientPrivateJwks jose.JSONWebKeySet) error {
	if err := DeleteClusterSecrets(cli, ctx, app, secretName); err != nil {
		return fmt.Errorf("Unable to delete clusterSecrets from cluster: %s", err)
	}

	secretSpec, err := CreateSecretSpec(app, secretName, clientPrivateJwks)
	if err != nil {
		return fmt.Errorf("Unable to create secretSpec object: %s", err)
	}

	// if err := cli.Get(ctx, client.ObjectKey{Namespace: app.Namespace, Name: secretName}, secretSpec.DeepCopyObject()); err != nil {
	// if !errors.IsNotFound(err) {
	//	return fmt.Errorf("Unable to fetch secret: %s", err)
	// }
	if err := cli.Create(ctx, secretSpec.DeepCopyObject()); err != nil {
		return fmt.Errorf("Unable to apply secretSpec: %s", err)
	}
	// }
	if err := jwkermetrics.SetTotalJwkerSecrets(cli); err != nil {
		return err
	}
	return nil
}

// TODO: Make exclusion optional
func DeleteClusterSecrets(cli client.Client, ctx context.Context, app tokendings.ClientId, secretName string) error {
	secretList, err := ClusterSecrets(ctx, app, cli)
	if err != nil {
		return err
	}
	for _, clusterSecret := range secretList.Items {
		if clusterSecret.Name != secretName {
			// r.Log.Info(fmt.Sprintf("Deleting clusterSecret %s in %s", clusterSecret.Name, clusterSecret.Namespace))
			if err := cli.Delete(ctx, clusterSecret.DeepCopyObject()); err != nil {
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
	mLabels["type"] = "jwker.nais.io"
	if err := cli.List(ctx, &secrets, client.InNamespace(app.Namespace), mLabels); err != nil {
		return secrets, err
	}
	return secrets, nil
}
