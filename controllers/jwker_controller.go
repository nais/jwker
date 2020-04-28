package controllers

import (
	"context"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	jwkerv1 "github.com/nais/jwker/api/v1"
	jwkermetrics "github.com/nais/jwker/pkg/metrics"
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
	TokendingsToken  *tokendings.TokenResponse
}

func (r *JwkerReconciler) privateKey() *jose.JSONWebKey {
	return &r.JwkerPrivateJwks.Keys[0]
}

func (r *JwkerReconciler) appClientID(req ctrl.Request) tokendings.ClientId {
	return tokendings.ClientId{
		Name:      req.Name,
		Namespace: req.Namespace,
		Cluster:   r.ClusterName,
	}
}

func (r *JwkerReconciler) refreshToken() {
	var err error
	exp := 1 * time.Second

	t := time.NewTimer(exp)
	for range t.C {

		// Fetching a token for communicating with tokendings
		jwkerClientID := tokendings.ClientId{Name: "jwker", Namespace: "nais", Cluster: r.ClusterName}
		r.TokendingsToken, err = tokendings.GetToken(r.privateKey(), jwkerClientID, r.TokenDingsUrl)
		if err != nil {
			r.logger.Error(err, "unable to fetch jwker-token from tokendings. will retry in 10 secs.")
		} else {
			secs := float64(r.TokendingsToken.ExpiresIn) / 3
			exp = time.Duration(int(secs)) * time.Second
			t.Reset(exp)
		}
	}
}

// delete all associated objects
// TODO: needs finalizer
func (r *JwkerReconciler) purge(ctx context.Context, req ctrl.Request) error {

	var err error

	aid := r.appClientID(req)

	r.logger.Info(fmt.Sprintf("Jwker resource %s in namespace: %s has been deleted. Cleaning up resources", req.Name, req.Namespace))

	r.logger.Info(fmt.Sprintf("Deleting resource %s in namespace %s from tokendings", req.Name, req.Namespace))
	if err = tokendings.DeleteClient(ctx, r.TokendingsToken.AccessToken, r.TokenDingsUrl, aid); err != nil {
		return fmt.Errorf("deleting resource from Tokendings: %s", err)
	}

	r.logger.Info(fmt.Sprintf("Deleting application %s jwker secrets in namespace %s from cluster", req.Name, req.Namespace))
	if err := secret.DeleteClusterSecrets(r, ctx, aid, ""); err != nil {
		return fmt.Errorf("deleting secrets from cluster: %s", err)
	}
	jwkermetrics.JwkerSecretsTotal.Dec()

	r.logger.Info(fmt.Sprintf("Deleting application %s jwker secrets in namespace %s from storage bucket", req.Name, req.Namespace))
	// TODO: pass context
	if err := r.JwkerStorage.Delete(aid.ToFileName()); err != nil {
		return fmt.Errorf("deleting application from storage bucket: %s", err)
	}
	if err := jwkermetrics.UpdateBucketMetric(r.JwkerStorage); err != nil {
		return err
	}

	return client.IgnoreNotFound(err)
}

func (r *JwkerReconciler) prepareJwks(ctx context.Context, req ctrl.Request) (utils.KeySet, error) {
	appClientId := r.appClientID(req)

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

	clientPrivateJwks, clientPublicJwks:= utils.JwksWithExistingPublicKey(clientJwk, existingJwk)


}

func (r *JwkerReconciler) create(ctx context.Context, req ctrl.Request) error {

	keyset, err := r.prepareJwks(ctx, req)
	r.logger.Info(fmt.Sprintf("Registering app %s:%s:%s with token-dingz", appClientId.Cluster, appClientId.Namespace, appClientId.Name))
	clientRegistrationResponse, err := tokendings.RegisterClient(r.privateKey(), &clientPublicJwks, r.TokendingsToken.AccessToken, r.TokenDingsUrl, appClientId, &j)
	if err != nil {
		r.logger.Error(err, "failed registering client")
		return ctrl.Result{RequeueAfter: time.Second * 10}, nil
	}

	keys := make(map[string]int64)
	if len(existingJwk.KeyID) > 0 {
		keys[existingJwk.KeyID] = keyIds[existingJwk.KeyID]
	}
	keys[clientJwk.KeyID] = time.Now().UnixNano()

	r.logger.Info(fmt.Sprintf("Reconciling secrets for app %s in namespace %s", appClientId.Namespace, appClientId.Name))
	if err := secret.ReconcileSecrets(r, ctx, appClientId, j.Spec.SecretName, clientPrivateJwks); err != nil {
		r.logger.Error(err, "Reconciling secrets failed...")
		return ctrl.Result{}, err
	}

	if err := r.JwkerStorage.Write(appClientId.ToFileName(), clientRegistrationResponse, keys); err != nil {
		return ctrl.Result{}, err
	}

	if err := jwkermetrics.SetTotalJwkerSecrets(r); err != nil {
		return ctrl.Result{}, err
	}
}

// +kubebuilder:rbac:groups=jwker.nais.io,resources=jwkers,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=jwker.nais.io,resources=jwkers/status,verbs=get;update;patch

func (r *JwkerReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	ctx := context.Background()
	changed := false
	hash := ""
	var j jwkerv1.Jwker
	jwkermetrics.JwkersProcessedCount.Inc()
	if err := jwkermetrics.UpdateBucketMetric(r.JwkerStorage); err != nil {
		return ctrl.Result{}, err
	}
	if err := jwkermetrics.SetTotalJwkersMetric(r); err != nil {
		return ctrl.Result{}, err
	}
	if err := jwkermetrics.SetTotalJwkerSecrets(r); err != nil {
		return ctrl.Result{}, err
	}

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

	if r.TokendingsToken == nil {
		return ctrl.Result{
			RequeueAfter: time.Second * 10,
		}, nil
	}

	// purge other systems if resource was deleted
	if err := r.Get(ctx, req.NamespacedName, &j); errors.IsNotFound(err) {
		err := r.purge(ctx, req)
		if err != nil {
			r.logger.Error(err, "failed purge")
		}
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	hash, err := utils.Hash(j.Spec)
	if err != nil {
		return ctrl.Result{}, err
	}
	if j.Status.SynchronizationHash == hash && j.Status.SynchronizationState == jwkerv1.EventRolloutComplete {
		return ctrl.Result{}, nil
	}


	j.Status = j.Status.Successful(hash)
	changed = true

	return ctrl.Result{}, nil
}

func (r *JwkerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&jwkerv1.Jwker{}).
		Complete(r)
}
