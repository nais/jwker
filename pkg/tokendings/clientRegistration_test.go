package tokendings_test

import (
	"encoding/json"
	"testing"

	"github.com/golang-jwt/jwt/v4"
	jwkerv1 "github.com/nais/liberator/pkg/apis/nais.io/v1"
	"github.com/stretchr/testify/assert"
	"gopkg.in/square/go-jose.v2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/nais/jwker/pkg/tokendings"
	"github.com/nais/jwker/utils"
)

type clientRegistrationTest struct {
	input             jwkerv1.Jwker
	clientName        string
	softwareStatement string
}

var (
	test = clientRegistrationTest{
		input: jwkerv1.Jwker{
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
						Rules: []jwkerv1.AccessPolicyInboundRule{
							{
								AccessPolicyRule: jwkerv1.AccessPolicyRule{
									Application: "otherapplication",
									Namespace:   "othernamespace",
									Cluster:     "mycluster",
								},
							},
							{
								AccessPolicyRule: jwkerv1.AccessPolicyRule{
									Application: "otherapplicationinsamecluster",
									Namespace:   "othernamespace",
								},
							},
							{
								AccessPolicyRule: jwkerv1.AccessPolicyRule{
									Application: "otherapplicationinsamenamespace",
								},
							},
						},
					},
				},
			},
		},
		clientName:        "mycluster:mynamespace:myapplication",
		softwareStatement: `{"accessPolicyInbound":["mycluster:othernamespace:otherapplication","mycluster:othernamespace:otherapplicationinsamecluster","mycluster:mynamespace:otherapplicationinsamenamespace"],"accessPolicyOutbound":[],"appId":"mycluster:mynamespace:myapplication"}`,
	}
)

func TestMakeClientRegistration(t *testing.T) {
	signkey, err := utils.GenerateJWK()
	if err != nil {
		panic(err)
	}

	appkey, err := utils.GenerateJWK()
	if err != nil {
		panic(err)
	}
	appkeys := utils.KeySetWithExisting(appkey, []jose.JSONWebKey{})

	clientid := tokendings.ClientId{
		Name:      "myapplication",
		Namespace: "mynamespace",
		Cluster:   "mycluster",
	}

	output, err := tokendings.MakeClientRegistration(&signkey, &appkeys.Public, clientid, test.input)

	assert.NoError(t, err)
	assert.Equal(t, test.clientName, output.ClientName)

	parser := new(jwt.Parser)
	claims := &jwt.MapClaims{}
	_, _, err = parser.ParseUnverified(output.SoftwareStatement, claims)
	assert.NoError(t, err)

	js, err := json.Marshal(claims)
	if err != nil {
		panic(err)
	}

	assert.Equal(t, test.softwareStatement, string(js))
}
