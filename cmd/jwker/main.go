package main

import (
	"encoding/json"
	"flag"
	"net/http"
	"os"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/nais/jwker/pkg/storage"
	"github.com/nais/jwker/utils"
	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/metrics"

	jwkerv1 "github.com/nais/jwker/api/v1"
	"github.com/nais/jwker/controllers"
	// +kubebuilder:scaffold:imports
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")

	// metrics
	jwkersTotal = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "jwkers_total",
		})
	jwkersProcessedTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "jwkers_processed_total",
			Help: "Number of jwkers processed",
		},
	)
	jwkersDeleted = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "jwkers_deleted",
			Help: "Number of jwkers deleted",
		},
	)
	jwkerSecretsCreated = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "jwkers_secrets_created",
			Help: "Number of jwker secrets created",
		},
	)
	jwkerSecretsDeleted = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "jwkers_secrets_deleted",
			Help: "Number of jwker secrets deleted",
		})
	jwkerSecretsTotal = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "jwker_secrets_total",
			Help: "Number of jwker secrets total",
		},
	)
	jwkerMetrics = make(map[string]prometheus.Metric)
)

func init() {
	// Register custom metrics with the global prometheus registry
	metrics.Registry.MustRegister(jwkersTotal, jwkersProcessedTotal)
	jwkerMetrics["jwkers_total"] = jwkersTotal
	jwkerMetrics["jwkers_processed_total"] = jwkersProcessedTotal
	jwkerMetrics["jwkers_deleted"] = jwkersDeleted
	jwkerMetrics["jwkers_secrets_created"] = jwkerSecretsCreated
	jwkerMetrics["jwkers_secrets_total"] = jwkerSecretsTotal

	_ = clientgoscheme.AddToScheme(scheme)

	_ = jwkerv1.AddToScheme(scheme)
	// +kubebuilder:scaffold:scheme
}

func main() {
	var metricsAddr string
	var clusterName string
	var storagePath string
	var tokenDingsUrl string
	var storageBucket string
	var credentialsPath string
	var port string

	flag.StringVar(&metricsAddr, "metrics-addr", ":8181", "The address the metric endpoint binds to.")
	flag.StringVar(&port, "port", "8080", "The address the .well-know endpoints is served on.")
	flag.StringVar(&clusterName, "clustername", "cluster_name_not_set", "Name of runtime cluster")
	flag.StringVar(&storagePath, "storagepath", "storage.json", "path to storage object")
	flag.StringVar(&tokenDingsUrl, "tokendingsUrl", "http://localhost:8080", "URL to tokendings")
	flag.StringVar(&storageBucket, "storageBucket", "jwker-dev", "Bucket name")
	flag.StringVar(&credentialsPath, "credentialsPath", "./sa-credentials.json", "path to sa-credentials.json")
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

	privateJwks, publicJwks, err := utils.GenerateJwkerKeys()
	if err != nil {
		setupLog.Error(err, "Unable to generate jwks")
	}

	if _, err := os.Stat(credentialsPath); err != nil {
		setupLog.Error(err, "Credentials file is missing. Exiting...\n")
		os.Exit(1)
	}
	jwkerStorage, err := storage.New(credentialsPath, storageBucket)
	if err != nil {
		setupLog.Error(err, "Unable to instantiate jwkerStorage")
	}
	if err = (&controllers.JwkerReconciler{
		Client:           mgr.GetClient(),
		Log:              ctrl.Log.WithName("controllers").WithName("Jwker"),
		Scheme:           mgr.GetScheme(),
		ClusterName:      clusterName,
		StoragePath:      storagePath,
		JwkerPrivateJwks: &privateJwks,
		TokenDingsUrl:    tokenDingsUrl,
		JwkerStorage:     jwkerStorage,
		JwkerMetrics:     jwkerMetrics,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "Jwker")
		os.Exit(1)
	}
	// +kubebuilder:scaffold:builder
	res, err := json.MarshalIndent(publicJwks, "", " ")

	r := chi.NewRouter()
	r.Use(middleware.Logger)

	r.Get("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Write(res)
	})
	go http.ListenAndServe(":"+port, r)
	metrics.Registry.MustRegister()

	setupLog.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}
