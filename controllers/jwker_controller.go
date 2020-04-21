package controllers

import (
	"context"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	jwkerv1 "github.com/nais/jwker/api/v1"
	"github.com/nais/jwker/pkg/secret"
	"github.com/nais/jwker/pkg/storage"
	"github.com/nais/jwker/pkg/tokendings"
	"github.com/nais/jwker/utils"
	"github.com/prometheus/client_golang/prometheus"
	"gopkg.in/square/go-jose.v2"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// JwkerReconciler reconciles a Jwker object
type JwkerReconciler struct {
	client.Client
	Log              logr.Logger
	Scheme           *runtime.Scheme
	ClusterName      string
	StoragePath      string
	JwkerPrivateJwks *jose.JSONWebKeySet
	TokenDingsUrl    string
	logger           logr.Logger
	JwkerStorage     storage.JwkerStorage
	JwkerMetrics     map[string]prometheus.Metric
}

// +kubebuilder:rbac:groups=jwker.nais.io,resources=jwkers,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=jwker.nais.io,resources=jwkers/status,verbs=get;update;patch

func (r *JwkerReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	ctx := context.Background()
	changed := false
	hash := ""
	var j jwkerv1.Jwker

	// Update Jwker resource with status event
	defer func() {
		if !changed {
			return
		}
		var existing jwkerv1.Jwker
		if err := r.Get(ctx, req.NamespacedName, &existing); err != nil {
			r.logger.Error(err, "Unable to fetch current jwker from cluster")
			return
		}
		existing.Status = j.Status
		r.Update(ctx, &existing)
	}()
	r.logger = r.Log.WithValues("jwker", req.NamespacedName)

	// Fetching a token for communicating with tokendings
	jwkerClientID := tokendings.ClientId{Name: "jwker", Namespace: "nais", Cluster: r.ClusterName}
	jwkerPrivateJwk := r.JwkerPrivateJwks.Keys[0]
	tokendingsToken, err := tokendings.GetToken(&jwkerPrivateJwk, jwkerClientID, r.TokenDingsUrl)
	if err != nil {
		r.logger.Error(err, "unable to fetch jwker-token from tokendings. will retry in 10 secs.")
		return ctrl.Result{
			RequeueAfter: time.Second * 10,
		}, nil
	}
	appClientId := tokendings.ClientId{
		Name:      req.Name,
		Namespace: req.Namespace,
		Cluster:   r.ClusterName,
	}

	if err := r.Get(ctx, req.NamespacedName, &j); errors.IsNotFound(err) {
		r.logger.Info(fmt.Sprintf("Jwker resource %s in namespace: %s has been deleted. Cleaning up resources", req.Name, req.Namespace))

		r.logger.Info(fmt.Sprintf("Deleting resource %s in namespace %s from tokendings", req.Name, req.Namespace))
		if err := tokendings.DeleteClient(tokendingsToken.AccessToken, r.TokenDingsUrl, appClientId); err != nil {
			r.logger.Error(err, "Failed deleting resource from Tokendings")
			return ctrl.Result{}, err
		}

		r.logger.Info(fmt.Sprintf("Deleting application %s jwker secrets in namespace %s from cluster", req.Name, req.Namespace))
		if err := secret.DeleteClusterSecrets(r, ctx, appClientId, ""); err != nil {
			r.logger.Error(err, "Failed deleting secrets from cluster")
			return ctrl.Result{}, err
		}

		r.logger.Info(fmt.Sprintf("Deleting application %s jwker secrets in namespace %s from storage bucket", req.Name, req.Namespace))
		if err := r.JwkerStorage.Delete(appClientId.ToFileName()); err != nil {
			r.logger.Error(err, "Failed deleting application from storage bucket")
			return ctrl.Result{}, err
		}

		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	hash, err = utils.Hash(j.Spec)
	if err != nil {
		return ctrl.Result{}, err
	}
	if j.Status.SynchronizationHash == hash && j.Status.SynchronizationState == jwkerv1.EventRolloutComplete {
		return ctrl.Result{}, nil
	}

	existingJwk, keyIds, err := r.JwkerStorage.Read(appClientId.ToFileName())
	if err != nil {
		if err.Error() != "storage: object doesn't exist" {
			return ctrl.Result{}, err
		}
	}

	clientJwk, err := utils.JwkKeyGenerator()
	if err != nil {
		r.logger.Error(err, "Unable to generate client JWK")
		j.Status = j.Status.FailedPrepare(hash)
		return ctrl.Result{RequeueAfter: time.Second * 10}, nil
	}

	clientPrivateJwks, clientPublicJwks, err := utils.JwksGenerator(clientJwk, existingJwk)

	if err != nil {
		r.logger.Error(err, "Unable to generate client JWKS")
		j.Status = j.Status.FailedPrepare(hash)
		return ctrl.Result{}, err
	}

	r.logger.Info(fmt.Sprintf("Registering app %s:%s:%s with token-dingz", appClientId.Cluster, appClientId.Namespace, appClientId.Name))
	clientRegistrationResponse, err := tokendings.RegisterClient(&jwkerPrivateJwk, &clientPublicJwks, tokendingsToken.AccessToken, r.TokenDingsUrl, appClientId, &j)
	if err != nil {
		r.logger.Error(err, "failed registering client")
		return ctrl.Result{RequeueAfter: time.Second * 10}, nil
	}

	keys := make(map[string]int64)
	if len(existingJwk.KeyID) > 0 {
		keys[existingJwk.KeyID] = keyIds[existingJwk.KeyID]
	}
	keys[clientJwk.KeyID] = time.Now().UnixNano()

	if err := r.JwkerStorage.Write(appClientId.ToFileName(), clientRegistrationResponse, keys); err != nil {
		return ctrl.Result{}, err
	}

	r.logger.Info(fmt.Sprintf("Reconciling secrets for app %s in namespace %s", appClientId.Namespace, appClientId.Name))
	if err := secret.ReconcileSecrets(r, ctx, appClientId, j.Spec.SecretName, clientPrivateJwks); err != nil {
		r.logger.Error(err, "Reconciling secrets failed...")
		return ctrl.Result{}, err
	}

	j.Status = j.Status.Successfull(hash)
	changed = true
	r.JwkerMetrics["jwkers_processed_total"].(prometheus.Counter).Inc()
	r.JwkerMetrics["jwkers_total"].(prometheus.Gauge).Inc()
	return ctrl.Result{}, nil
}

func (r *JwkerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&jwkerv1.Jwker{}).
		Complete(r)
}
