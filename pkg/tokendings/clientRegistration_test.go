package tokendings_test

import (
	"testing"

	jwkerv1 "github.com/nais/jwker/api/v1"
	"github.com/nais/jwker/pkg/tokendings"
	"github.com/nais/jwker/utils"
	"github.com/stretchr/testify/assert"
	"gopkg.in/square/go-jose.v2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var input = &jwkerv1.Jwker{
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
				Rules: []jwkerv1.AccessPolicyRule{
					{
						Application: "otherapplication",
						Namespace:   "othernamespace",
						Cluster:     "mycluster",
					},
				},
			},
		},
	},
}

var expected = &tokendings.ClientRegistration{
	ClientName:        "mycluster:mynamespace:myapplication",
	Jwks:              jose.JSONWebKeySet{},
	SoftwareStatement: "",
}

func TestMakeClientRegistration(t *testing.T) {
	signkey, err := utils.GenerateJWK()
	if err != nil {
		panic(err)
	}

	appkey, err := utils.GenerateJWK()
	if err != nil {
		panic(err)
	}
	appkeys := utils.KeySetWithoutExisting(appkey)

	clientid := tokendings.ClientId{
		Name:      "myapplication",
		Namespace: "mynamespace",
		Cluster:   "mycluster",
	}

	_, err = tokendings.MakeClientRegistration(&signkey, &appkeys.Public, clientid, *input)

	assert.NoError(t, err)

	// TODO: make a useful test
}
