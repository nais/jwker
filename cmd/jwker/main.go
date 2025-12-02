package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/go-logr/logr"
	"github.com/nais/jwker/controllers"
	"github.com/nais/jwker/pkg/config"
	jwkermetrics "github.com/nais/jwker/pkg/metric"
	jwkerv1 "github.com/nais/liberator/pkg/apis/nais.io/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
	ctrlmetricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	// +kubebuilder:scaffold:imports
)

var scheme = runtime.NewScheme()

func init() {
	// Register custom metrics with the global prometheus registry
	metrics.Registry.MustRegister(
		jwkermetrics.JwkersTotal,
		jwkermetrics.JwkersProcessedCount,
		jwkermetrics.JwkersFinalizedCount,
		jwkermetrics.JwkerSecretsTotal,
		jwkermetrics.JwkersProcessingFailedCount,
	)

	_ = clientgoscheme.AddToScheme(scheme)
	_ = jwkerv1.AddToScheme(scheme)
	// +kubebuilder:scaffold:scheme
}

func main() {
	ctx := context.Background()
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil)).With("logger", "setup")

	cfg, err := config.New(ctx)
	if err != nil {
		log.Error("initializing config", "error", err)
		os.Exit(1)
	}

	if err := setupLogger(cfg.LogLevel); err != nil {
		log.Error("unable to set up logger", "error", err)
		os.Exit(1)
	}

	log.Info("starting jwker")
	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme: scheme,
		Metrics: ctrlmetricsserver.Options{
			BindAddress: cfg.MetricsAddr,
		},
		HealthProbeBindAddress: cfg.ProbeAddr,
		LivenessEndpointName:   "/healthz",
		ReadinessEndpointName:  "/readyz",
		LeaderElection:         cfg.LeaderElection,
		LeaderElectionID:       "722f3604.nais.io",
	})
	if err != nil {
		log.Error("unable to create manager", "error", err)
		os.Exit(1)
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		log.Error("unable to set up health check", "error", err)
		os.Exit(1)
	}

	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		log.Error("unable to set up ready check", "error", err)
		os.Exit(1)
	}

	if err = (&controllers.JwkerReconciler{
		Client:   mgr.GetClient(),
		Config:   cfg,
		Reader:   mgr.GetAPIReader(),
		Recorder: mgr.GetEventRecorderFor("Jwker"),
		Scheme:   mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		log.Error("unable to create controller", "controller", "jwker", "error", err)
		os.Exit(1)
	}

	log.Info("starting metrics refresh goroutine")
	go jwkermetrics.RefreshTotalJwkerClusterMetrics(mgr.GetClient())

	log.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		log.Error("problem running manager", "error", err)
		os.Exit(1)
	}
}

func setupLogger(logLevel string) error {
	var level slog.Level
	if err := level.UnmarshalText([]byte(logLevel)); err != nil {
		return fmt.Errorf("parsing log level: %w", err)
	}

	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: level,
	})

	slog.SetDefault(slog.New(handler))
	ctrl.SetLogger(logr.FromSlogHandler(handler))

	return nil
}
