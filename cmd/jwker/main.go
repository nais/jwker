package main

import (
	"os"
	"strings"
	"time"

	"github.com/go-logr/zapr"
	jwkerv1 "github.com/nais/liberator/pkg/apis/nais.io/v1"
	log "github.com/sirupsen/logrus"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
	ctrlmetricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/nais/jwker/controllers"
	"github.com/nais/jwker/pkg/config"
	jwkermetrics "github.com/nais/jwker/pkg/metrics"
	// +kubebuilder:scaffold:imports
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	// Register custom metrics with the global prometheus registry

	metrics.Registry.MustRegister(
		jwkermetrics.JwkersTotal,
		jwkermetrics.JwkersProcessedCount,
		jwkermetrics.JwkerSecretsTotal,
		jwkermetrics.JwkersProcessingFailedCount,
	)

	formatter := log.JSONFormatter{
		TimestampFormat: time.RFC3339Nano,
	}
	log.SetFormatter(&formatter)

	level, err := log.ParseLevel(strings.ToLower(os.Getenv("LOG_LEVEL")))
	if err != nil {
		log.SetLevel(log.InfoLevel)
	}

	log.SetLevel(level)

	_ = clientgoscheme.AddToScheme(scheme)

	_ = jwkerv1.AddToScheme(scheme)
	// +kubebuilder:scaffold:scheme
}

func main() {
	cfg, err := config.New()
	if err != nil {
		log.Fatalf("initializing config: %+v", err)
	}

	zapLogger, err := setupZapLogger(cfg.LogLevel)
	if err != nil {
		log.Fatalf("unable to set up logger: %+v", err)
	}

	ctrl.SetLogger(zapr.NewLogger(zapLogger))
	setupLog.Info("starting jwker")

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme: scheme,
		Metrics: ctrlmetricsserver.Options{
			BindAddress: cfg.MetricsAddr,
		},
	})

	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}
	reconciler := &controllers.JwkerReconciler{
		Client:   mgr.GetClient(),
		Log:      ctrl.Log.WithName("controllers").WithName("Jwker"),
		Reader:   mgr.GetAPIReader(),
		Recorder: mgr.GetEventRecorderFor("Jwker"),
		Scheme:   mgr.GetScheme(),
		Config:   cfg,
	}

	if err = reconciler.SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "Jwker")
		os.Exit(1)
	}

	metrics.Registry.MustRegister()
	setupLog.Info("starting metrics refresh goroutine")
	go jwkermetrics.RefreshTotalJwkerClusterMetrics(mgr.GetClient())

	setupLog.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}

func setupZapLogger(logLevel string) (*zap.Logger, error) {
	loggerConfig := zap.NewProductionConfig()
	level, err := zap.ParseAtomicLevel(strings.ToLower(logLevel))
	if err != nil {
		return nil, err
	}
	loggerConfig.Level = level
	loggerConfig.EncoderConfig.TimeKey = "timestamp"
	loggerConfig.EncoderConfig.EncodeTime = zapcore.RFC3339NanoTimeEncoder
	return loggerConfig.Build()
}
