package metrics

import (
	"context"

	jwkerv1 "github.com/nais/jwker/api/v1"
	"github.com/prometheus/client_golang/prometheus"
	v1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var (
	// metrics
	JwkersTotal = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "jwker_total",
		})
	JwkersProcessedCount = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "jwker_processed_count",
			Help: "Number of jwkers processed",
		},
	)
	JwkerSecretsTotal = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "jwker_secrets_total",
			Help: "Number of jwker secrets total",
		},
	)

	ctx = context.Background()
)

func SetTotalJwkersMetric(cli client.Client) error {
	var jwkerList jwkerv1.JwkerList
	if err := cli.List(ctx, &jwkerList); err != nil {
		return err
	}
	JwkersTotal.Set(float64(len(jwkerList.Items)))
	return nil
}
func SetTotalJwkerSecrets(cli client.Client) error {
	var secretList v1.SecretList
	var mLabels = client.MatchingLabels{}
	mLabels["type"] = "jwker.nais.io"
	if err := cli.List(ctx, &secretList, mLabels); err != nil {
		return err
	}
	JwkerSecretsTotal.Set(float64(len(secretList.Items)))
	return nil
}
