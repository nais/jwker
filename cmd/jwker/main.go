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
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	jwkerv1 "github.com/nais/jwker/api/v1"
	"github.com/nais/jwker/controllers"
	// +kubebuilder:scaffold:imports
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	_ = clientgoscheme.AddToScheme(scheme)

	_ = jwkerv1.AddToScheme(scheme)
	// +kubebuilder:scaffold:scheme
}

func main() {
	var metricsAddr string
	var enableLeaderElection bool
	var clusterName string
	var storagePath string
	var tokenDingsUrl string
	var storageBucket string
	var credentialsPath string

	flag.StringVar(&metricsAddr, "metrics-addr", ":8181", "The address the metric endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "enable-leader-election", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
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
		Port:               9443,
		LeaderElection:     enableLeaderElection,
		LeaderElectionID:   "5d873130.nais.io",
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	privateJwks, publicJwks, err := utils.GenerateJwkerKeys()
	if err != nil {
		setupLog.Error(err, "Unable to generate jwks")
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
	go http.ListenAndServe(":3000", r)

	setupLog.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}
