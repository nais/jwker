package secretscreator

import (
	"encoding/json"

	"gopkg.in/square/go-jose.v2"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func CreateSecret(appName, name, namespace string, clientPrivateJwks jose.JSONWebKeySet) (v1.Secret, error) {
	clientPrivateJwksJson, err := json.MarshalIndent(clientPrivateJwks, "", " ")
	if err != nil {
		return v1.Secret{}, err
	}
	stringdata := map[string]string{"jwks": string(clientPrivateJwksJson)}

	return v1.Secret{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Secret",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels:    map[string]string{"app": appName, "type": "jwker.nais.io"},
		},
		StringData: stringdata,
		Type:       "Opaque",
	}, nil
}
