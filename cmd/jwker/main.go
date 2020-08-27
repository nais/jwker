package main

import (
	"flag"
	"github.com/go-logr/zapr"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"io/ioutil"
	"os"

	"gopkg.in/square/go-jose.v2"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/metrics"

	jwkerv1 "github.com/nais/jwker/api/v1"
	"github.com/nais/jwker/controllers"
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
	)

	_ = clientgoscheme.AddToScheme(scheme)

	_ = jwkerv1.AddToScheme(scheme)
	// +kubebuilder:scaffold:scheme
}

func loadCredentials(path string) (*jose.JSONWebKey, error) {
	creds, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	jwk := &jose.JSONWebKey{}
	err = jwk.UnmarshalJSON(creds)
	if err != nil {
		return nil, err
	}

	return jwk, nil
}

func main() {
	var clientID string
	var authProviderURL string
	var metricsAddr string
	var tokenDingsUrl string
	var tokenDingsClientId string
	var azureJWKFile string
	var clusterName string

	flag.StringVar(&azureJWKFile, "azureJWKFile", "/var/run/secrets/azure/jwk.json", "file with JWK credential for Azure")
	flag.StringVar(&clientID, "clientID", os.Getenv("JWKER_CLIENT_ID"), "azure client id")
	flag.StringVar(&metricsAddr, "metrics-addr", ":8181", "The address the metric endpoint binds to.")
	flag.StringVar(&authProviderURL, "authProviderURL", os.Getenv("AUTH_PROVIDER_URL"), "")
	flag.StringVar(&tokenDingsClientId, "tokendingsClientId", os.Getenv("TOKENDINGS_CLIENT_ID"), "ClientID of tokendings")
	flag.StringVar(&tokenDingsUrl, "tokendingsUrl", os.Getenv("TOKENDINGS_URL"), "URL to tokendings")
	flag.StringVar(&clusterName, "clusterName", os.Getenv("CLUSTER_NAME"), "nais cluster")
	flag.Parse()

	zapLogger, err := setupZapLogger()
	if err != nil {
		setupLog.Error(err, "unable to set up logger")
		os.Exit(1)
	}
	ctrl.SetLogger(zapr.NewLogger(zapLogger))

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:             scheme,
		MetricsBindAddress: metricsAddr,
	})

	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	creds, err := loadCredentials(azureJWKFile)
	if err != nil {
		setupLog.Error(err, "unable to load azure credentials")
		os.Exit(1)
	}

	reconciler := &controllers.JwkerReconciler{
		AzureCredentials:   *creds,
		Client:             mgr.GetClient(),
		ClientID:           clientID,
		ClusterName:        clusterName,
		Endpoint:           authProviderURL,
		Log:                ctrl.Log.WithName("controllers").WithName("Jwker"),
		Scheme:             mgr.GetScheme(),
		TokenDingsUrl:      tokenDingsUrl,
		TokendingsClientID: tokenDingsClientId,
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

func setupZapLogger() (*zap.Logger, error) {
	loggerConfig := zap.NewProductionConfig()
	loggerConfig.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
	loggerConfig.EncoderConfig.TimeKey = "timestamp"
	loggerConfig.EncoderConfig.EncodeTime = zapcore.RFC3339NanoTimeEncoder
	return loggerConfig.Build()
}
