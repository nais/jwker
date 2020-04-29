package main

import (
	"flag"
	"io/ioutil"
	"os"

	"gopkg.in/square/go-jose.v2"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
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
	var tenantID string
	var metricsAddr string
	var clusterName string
	var tokenDingsUrl string
	var tokenDingsClientId string
	var azureJWKFile string

	flag.StringVar(&azureJWKFile, "azureJWKFile", "/var/run/secrets/azure/jwk.json", "file with JWK credential for Azure")
	flag.StringVar(&clientID, "clientID", "I DIDNT CONFIGURE AZURE CLIENT ID", "azure client id")
	flag.StringVar(&clusterName, "clustername", "cluster_name_not_set", "Name of runtime cluster")
	flag.StringVar(&metricsAddr, "metrics-addr", ":8181", "The address the metric endpoint binds to.")
	flag.StringVar(&tenantID, "tenantID", "common", "azure tenant id")
	flag.StringVar(&tokenDingsClientId, "tokendingsClientId", "tokendings-dev-gcp", "ClientID of tokendings")
	flag.StringVar(&tokenDingsUrl, "tokendingsUrl", "http://localhost:8080", "URL to tokendings")
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseDevMode(true)))

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
		Log:                ctrl.Log.WithName("controllers").WithName("Jwker"),
		Scheme:             mgr.GetScheme(),
		TenantID:           tenantID,
		TokenDingsUrl:      tokenDingsUrl,
		TokendingsClientID: tokenDingsClientId,
	}
	if err = reconciler.SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "Jwker")
		os.Exit(1)
	}

	metrics.Registry.MustRegister()
	setupLog.Info("starting token refresh goroutine")
	go reconciler.RefreshToken()

	setupLog.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}
