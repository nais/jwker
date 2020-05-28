package pods

import (
	"context"

	"github.com/nais/jwker/pkg/tokendings"
	v1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func ApplicationPods(ctx context.Context, app tokendings.ClientId, cli client.Client) (*v1.PodList, error) {
	selector := client.MatchingLabels{
		"app": app.Name,
	}
	namespace := client.InNamespace(app.Namespace)
	podList := &v1.PodList{}
	err := cli.List(ctx, podList, selector, namespace)
	if err != nil {
		return nil, err
	}

	return podList, nil
}
