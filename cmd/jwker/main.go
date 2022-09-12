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

const (
	JWKKeyName        = "privateJWK"
	PrivateSecretName = "jwker-private-jwk"
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
	setupLog.Info("starting jwker")
	if err != nil {
		setupLog.Error(err, "unable to set up logger")
		os.Exit(1)
	}
	ctrl.SetLogger(zapr.NewLogger(zapLogger))

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()
	cfg, err := config.New()
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

	jwk, err := ensurePrivateJWKSecret(ctx, mgr.GetClient(), cfg.Namespace, PrivateSecretName)
	if err != nil {
		setupLog.Error(err, "unable to read or create private jwk secret")
		os.Exit(1)
	}

	cfg.AuthProvider.ClientJwk = jwk

	if err := ensurePublicSecret(ctx, mgr.GetClient(), cfg.Namespace, cfg.SharedPublicSecretName, jwk); err != nil {
		setupLog.Error(err, "unable to create public jwk secret")
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

func ensurePublicSecret(ctx context.Context, c client.Client, namespace string, name string, jwk *jose.JSONWebKey) error {
	keySet := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk.Public()}}
	b, err := json.Marshal(&keySet)
	if err != nil {
		return err
	}
	_, err = secret.CreateSecret(ctx, c, name, namespace, nil, map[string]string{"AUTH_CLIENT_JWKS": string(b)})
	return err
}

func parseJWK(json []byte) (*jose.JSONWebKey, error) {
	jwk := &jose.JSONWebKey{}
	if err := jwk.UnmarshalJSON(json); err != nil {
		return nil, err
	}

	return jwk, nil
}
func ensurePrivateJWKSecret(ctx context.Context, c client.Client, namespace, secretName string) (*jose.JSONWebKey, error) {
	privateJWKSecret, err := getSecret(ctx, c, namespace, secretName)
	if err != nil {
		return nil, err
	}

	if privateJWKSecret != nil {
		jwkJSON := privateJWKSecret.StringData[JWKKeyName]
		if len(jwkJSON) == 0 {
			return nil, fmt.Errorf("no jwk key in secret: %s", secretName)
		}
		return parseJWK([]byte(jwkJSON))
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

	_, err = secret.CreateSecret(ctx, c, secretName, namespace, nil, data)

	if err != nil {
		return nil, fmt.Errorf("failed to create secret: %w", err)
	}
	return &jwk, nil
}

func getSecret(ctx context.Context, c client.Client, namespace, secretName string) (*corev1.Secret, error) {
	var existingSecret corev1.Secret
	if err := c.Get(ctx, client.ObjectKey{Namespace: namespace, Name: secretName}, &existingSecret); errors.IsNotFound(err) {
		log.Info("secret not found", "secret", secretName)
		return nil, nil
	} else if err != nil {
		log.Info("error getting secret", "secret", secretName, "error", err)
		return nil, err
	} else {
		log.Info("found secret", "secret", secretName)
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
