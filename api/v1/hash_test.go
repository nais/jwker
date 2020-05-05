package v1_test

import (
	"testing"

	v1 "github.com/nais/jwker/api/v1"
	"github.com/stretchr/testify/assert"
)

const secretName = "verysecret"

var accessPolicy = &v1.AccessPolicy{
	Inbound: &v1.AccessPolicyInbound{
		Rules: []v1.AccessPolicyRule{
			{
				Application: "app1",
				Namespace:   "ns1",
				Cluster:     "firstcluster",
			},
		},
	},
	Outbound: &v1.AccessPolicyOutbound{
		Rules: []v1.AccessPolicyRule{
			{
				Application: "app1",
				Namespace:   "ns1",
				Cluster:     "firstcluster",
			},
		},
	},
}

func TestHash(t *testing.T) {
	spec := v1.JwkerSpec{
		AccessPolicy: accessPolicy,
		SecretName:   secretName,
	}
	hash, err := spec.Hash()
	assert.NoError(t, err)
	assert.Equal(t, "b6b03694476d8028", hash)
}
