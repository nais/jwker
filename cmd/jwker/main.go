package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/go-logr/zapr"
	"github.com/nais/jwker/pkg/secret"
	"github.com/nais/jwker/utils"
	log "github.com/sirupsen/logrus"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/square/go-jose.v2"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/metrics"

	jwkerv1 "github.com/nais/liberator/pkg/apis/nais.io/v1"

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
	log.SetLevel(log.DebugLevel)

	_ = clientgoscheme.AddToScheme(scheme)

	_ = jwkerv1.AddToScheme(scheme)
	// +kubebuilder:scaffold:scheme
}

func main() {
	zapLogger, err := setupZapLogger()
	if err != nil {
		setupLog.Error(err, "unable to set up logger")
		os.Exit(1)
	}
	ctrl.SetLogger(zapr.NewLogger(zapLogger))

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()
	cfg, err := config.New(ctx)
	if err != nil {
		setupLog.Error(err, "initializing config")
		os.Exit(1)
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:             scheme,
		MetricsBindAddress: cfg.MetricsAddr,
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

	setupLog.Info("starting token refresh goroutine")
	go reconciler.RefreshToken()

	metrics.Registry.MustRegister()
	setupLog.Info("starting metrics refresh goroutine")
	go jwkermetrics.RefreshTotalJwkerClusterMetrics(mgr.GetClient())

	setupLog.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}

type RequiredSecrets struct {
	PrivateJWKSecretName string
	PublicJWKSSecretName string
}

func yolo() {
	_ := map[string]string{
		"app":        "jwker",
		"share-with": "tokendings",
	}
}
func EnsurePrivateJWKSecret(ctx context.Context, c client.Client, namespace, secretName string) (*corev1.Secret, error) {
	privateJWKSecret, err := getSecret(ctx, c, namespace, secretName)
	if err != nil {
		return nil, err
	}
	if privateJWKSecret != nil {
		return privateJWKSecret, nil
	}
	jwk, err := utils.GenerateJWK()
	if err != nil {
		return nil, fmt.Errorf("failed to generate JWK: %w", err)
	}

	jwkJson, err := json.Marshal(jwk)
	if err != nil {
		return nil, err
	}
	data := map[string]string{
		"privateJWK": string(jwkJson),
	}

	s, err := secret.CreateSecret(c, ctx, secretName, namespace, nil, data)
	if err != nil {
		return nil, fmt.Errorf("failed to create secret: %w", err)
	}
	return s, nil
}

func CreateSharedJWKSSecret(jwk jose.JSONWebKey) error {
	return nil
}

func getSecret(ctx context.Context, c client.Client, namespace, secretName string) (*corev1.Secret, error) {
	var existingSecret corev1.Secret
	if err := c.Get(ctx, client.ObjectKey{Namespace: namespace, Name: secretName}, &existingSecret); errors.IsNotFound(err) {
		return nil, nil
	} else if err != nil {
		return nil, err
	} else {
		return &existingSecret, nil
	}
}

func setupZapLogger() (*zap.Logger, error) {
	loggerConfig := zap.NewProductionConfig()
	loggerConfig.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
	loggerConfig.EncoderConfig.TimeKey = "timestamp"
	loggerConfig.EncoderConfig.EncodeTime = zapcore.RFC3339NanoTimeEncoder
	return loggerConfig.Build()
}
