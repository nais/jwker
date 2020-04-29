package deployment

import (
	"context"

	"github.com/nais/jwker/pkg/tokendings"
	v1 "k8s.io/api/apps/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func Deployment(ctx context.Context, app tokendings.ClientId, cli client.Client) (*v1.Deployment, error) {
	dep := &v1.Deployment{}
	key := client.ObjectKey{Namespace: app.Namespace, Name: app.Name}
	err := cli.Get(ctx, key, dep)
	if err != nil {
		return nil, err
	}

	return dep, nil
}
