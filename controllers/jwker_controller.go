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
}

// +kubebuilder:rbac:groups=jwker.nais.io,resources=jwkers,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=jwker.nais.io,resources=jwkers/status,verbs=get;update;patch

const (
	EventSynchronized          = "Synchronized"
	EventRolloutComplete       = "RolloutComplete"
	EventFailedPrepare         = "FailedPrepare"
	EventFailedSynchronization = "FailedSynchronization"
	EventFailedStatusUpdate    = "FailedStatusUpdate"
	EventRetrying              = "Retrying"
)

func (r *JwkerReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	ctx := context.Background()
	changed := false
	hash := ""
	state := EventFailedSynchronization

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
		existing.Status = jwkerv1.JwkerStatus{
			SynchronizationTime:  time.Now().UnixNano(),
			SynchronizationState: state,
			SynchronizationHash:  hash,
		}
		r.Update(ctx, &existing)
	}()
	r.logger = r.Log.WithValues("jwker", req.NamespacedName)

	// Fetching a token for communicating with tokendings
	jwkerClientID := tokendings.AppId{Name: "jwker", Namespace: "nais", Cluster: r.ClusterName}
	jwkerPrivateJwk := r.JwkerPrivateJwks.Keys[0]
	tokendingsToken, err := tokendings.GetToken(&jwkerPrivateJwk, jwkerClientID, r.TokenDingsUrl)
	if err != nil {
		r.logger.Error(err, "unable to fetch token from tokendings")
		return ctrl.Result{}, err
	}
	appClientId := tokendings.AppId{
		Name:      req.Name,
		Namespace: req.Namespace,
		Cluster:   r.ClusterName,
	}

	var j jwkerv1.Jwker
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

	existingJwks, err := r.JwkerStorage.Read(appClientId.ToFileName())
	fmt.Printf(existingJwks.Keys[0].KeyID)

	hash, err = utils.Hash(j.Spec)
	if err != nil {
		return ctrl.Result{}, err
	}

	if j.Status.SynchronizationHash == hash && j.Status.SynchronizationState == EventRolloutComplete {
		return ctrl.Result{}, nil
	}

	// Her må vi hente jwks fra storage før vi lager ny jwk.
	clientJwk, err := utils.JwkKeyGenerator()
	if err != nil {
		r.logger.Error(err, "Unable to generate client JWK")
		return ctrl.Result{}, err
	}

	clientPrivateJwks, clientPublicJwks, err := utils.JwksGenerator(clientJwk)
	if err != nil {
		r.logger.Error(err, "Unable to generate client JWKS")
		return ctrl.Result{}, err
	}

	r.logger.Info(fmt.Sprintf("Reconciling secrets for app %s in namespace %s", appClientId.Namespace, appClientId.Name))
	if err := secret.ReconcileSecrets(r, ctx, appClientId, j.Spec.SecretName, clientPrivateJwks); err != nil {
		r.logger.Error(err, "Reconciling secrets failed...")
		return ctrl.Result{}, err
	}

	r.logger.Info(fmt.Sprintf("Registering app %s:%s:%s with token-dingz", appClientId.Cluster, appClientId.Namespace, appClientId.Name))
	clientRegistrationResponse, err := tokendings.RegisterClient(&jwkerPrivateJwk, &clientPublicJwks, tokendingsToken.AccessToken, r.TokenDingsUrl, appClientId, &j)
	if err != nil {
		r.logger.Error(err, "failed registering client")
		return ctrl.Result{
			Requeue:      false,
			RequeueAfter: time.Second * 10,
		}, err
	}

	if err := r.JwkerStorage.Write(appClientId.ToFileName(), clientRegistrationResponse); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

func (r *JwkerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&jwkerv1.Jwker{}).
		Complete(r)
}
