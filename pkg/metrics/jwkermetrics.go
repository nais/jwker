package metrics

import (
	"context"
	"time"

	"github.com/nais/jwker/pkg/secret"
	jwkerv1 "github.com/nais/liberator/pkg/apis/nais.io/v1"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var (
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
	JwkersFinalizedCount = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "jwker_finalized_count",
			Help: "Number of jwkers finalized",
		},
	)
	JwkerSecretsTotal = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "jwker_secrets_total",
			Help: "Number of jwker secrets total",
		},
	)
	JwkersProcessingFailedCount = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "jwker_processing_failed_count",
			Help: "Number of jwkers that failed to process",
		},
	)

	ctx = context.Background()
)

func RefreshTotalJwkerClusterMetrics(cli client.Client) error {
	var err error
	exp := 10 * time.Second

	var secretList v1.SecretList
	mLabels := client.MatchingLabels{}
	mLabels["type"] = secret.TokenXSecretLabelType
	var jwkerList jwkerv1.JwkerList

	t := time.NewTicker(exp)
	for range t.C {
		log.Debug("Fetching metrics from cluster")
		if err = cli.List(ctx, &secretList, mLabels); err != nil {
			return err
		}
		JwkerSecretsTotal.Set(float64(len(secretList.Items)))
		if err = cli.List(ctx, &jwkerList); err != nil {
			return err
		}
		JwkersTotal.Set(float64(len(jwkerList.Items)))
	}
	return nil
}
