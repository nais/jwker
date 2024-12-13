package controllers

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-logr/logr"
	"github.com/google/uuid"
	jwkerv1 "github.com/nais/liberator/pkg/apis/nais.io/v1"
	"github.com/nais/liberator/pkg/events"
	libernetes "github.com/nais/liberator/pkg/kubernetes"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	"github.com/nais/jwker/jwkutils"
	"github.com/nais/jwker/pkg/config"
	jwkermetrics "github.com/nais/jwker/pkg/metrics"
	"github.com/nais/jwker/pkg/pods"
	"github.com/nais/jwker/pkg/secret"
	"github.com/nais/jwker/pkg/tokendings"
)

const (
	requeueInterval = 10 * time.Second
)

// JwkerReconciler reconciles a Jwker object
type JwkerReconciler struct {
	client.Client
	Log      logr.Logger
	Scheme   *runtime.Scheme
	Reader   client.Reader
	Recorder record.EventRecorder
	logger   logr.Logger
	Config   *config.Config
}

func (r *JwkerReconciler) appClientID(req ctrl.Request) tokendings.ClientId {
	return tokendings.ClientId{
		Name:      req.Name,
		Namespace: req.Namespace,
		Cluster:   r.Config.ClusterName,
	}
}

// delete all associated objects
// TODO: needs finalizer
func (r *JwkerReconciler) purge(ctx context.Context, req ctrl.Request) error {
	aid := r.appClientID(req)

	r.logger.Info(fmt.Sprintf("Jwker resource %s in namespace: %s has been deleted. Cleaning up resources", req.Name, req.Namespace))

	r.logger.Info(fmt.Sprintf("Deleting resource %s in namespace %s from %d tokendings instances", req.Name, req.Namespace, len(r.Config.TokendingsInstances)))
	for _, instance := range r.Config.TokendingsInstances {
		r.logger.Info(fmt.Sprintf("Deleting client from tokendings instance %s", instance.BaseURL))
		if err := instance.DeleteClient(ctx, aid); err != nil {
			return fmt.Errorf("deleting resource from Tokendings instance '%s': %w", instance.BaseURL, err)
		}
	}

	r.logger.Info(fmt.Sprintf("Deleting application %s jwker secrets in namespace %s from cluster", req.Name, req.Namespace))
	if err := secret.DeleteClusterSecrets(r.Client, ctx, aid, ""); err != nil {
		return fmt.Errorf("deleting secrets from cluster: %s", err)
	}
	jwkermetrics.JwkerSecretsTotal.Dec()

	return nil
}

type transaction struct {
	ctx         context.Context
	req         ctrl.Request
	keyset      jwkutils.KeySet
	secretLists libernetes.SecretLists
	jwker       jwkerv1.Jwker
}

func (r *JwkerReconciler) prepare(ctx context.Context, req ctrl.Request, jwker jwkerv1.Jwker) (*transaction, error) {
	app := r.appClientID(req)

	// fetch running pods for this app
	podList, err := pods.ApplicationPods(ctx, app, r.Client)
	if err != nil {
		return nil, err
	}

	// fetch all jwker managed secrets
	allSecrets, err := secret.ClusterSecrets(ctx, app, r.Client)
	if err != nil {
		return nil, err
	}

	// find intersect between secrets in use by deployment and all jwker managed secrets
	secrets := libernetes.ListUsedAndUnusedSecretsForPods(allSecrets, *podList)

	existingJwks := jose.JSONWebKeySet{}

	var newJwk jose.JSONWebKey

	for _, sec := range secrets.Used.Items {
		jwk, err := secret.ExtractJWK(sec)
		if err != nil {
			return nil, err
		}

		if sec.Name == jwker.Status.SynchronizationSecretName {
			newJwk = *jwk
		} else {
			existingJwks.Keys = append(existingJwks.Keys, *jwk)
		}
	}

	if r.shouldUpdateSecrets(jwker) || newJwk.Key == nil {
		r.logger.Info("Generating new JWK")
		newJwk, err = jwkutils.GenerateJWK()
		if err != nil {
			return nil, err
		}
	}

	keyset := jwkutils.KeySetWithExisting(newJwk, existingJwks.Keys)

	return &transaction{
		ctx:         ctx,
		req:         req,
		keyset:      keyset,
		secretLists: secrets,
	}, nil
}

func (r *JwkerReconciler) create(tx transaction) error {
	app := r.appClientID(tx.req)

	cr, err := tokendings.MakeClientRegistration(
		r.Config.ClientJwk,
		&tx.keyset.Public,
		app,
		tx.jwker,
	)
	if err != nil {
		return fmt.Errorf("create client registration payload: %s", err)
	}

	instances := r.Config.TokendingsInstances
	r.logger.Info(fmt.Sprintf("Registering app %s with %d tokendings instances", app.String(), len(instances)))

	for _, instance := range instances {
		r.logger.Info(fmt.Sprintf("Registering client with tokendings instance %s", instance.BaseURL))
		if err := instance.RegisterClient(*cr); err != nil {
			return fmt.Errorf("registering client with Tokendings instance '%s': %w", instance.BaseURL, err)
		}
	}

	r.logger.Info(fmt.Sprintf("Reconciling secrets for app %s in namespace %s", app.Name, app.Namespace))

	jwk, err := secret.FirstJWK(tx.keyset.Private)
	if err != nil {
		return fmt.Errorf("unable to get first jwk from jwks: %s", err)
	}

	secretName := tx.jwker.Spec.SecretName
	secretData := secret.PodSecretData{
		ClientId: app,
		Jwk:      *jwk,
		TokendingsConfig: config.Tokendings{
			BaseURL:      instances[0].BaseURL,
			Metadata:     instances[0].Metadata,
			WellKnownURL: instances[0].WellKnownURL,
		},
	}
	secretSpec, err := secret.CreateSecretSpec(secretName, secretData)
	if err != nil {
		return fmt.Errorf("creating secret spec: %w", err)
	}

	target := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
		Name:      secretName,
		Namespace: tx.req.Namespace,
	}}
	res, err := controllerutil.CreateOrUpdate(tx.ctx, r.Client, target, func() error {
		target.SetAnnotations(secretSpec.GetAnnotations())
		target.SetLabels(secretSpec.GetLabels())
		target.StringData = secretSpec.StringData

		return ctrl.SetControllerReference(&tx.jwker, target, r.Scheme)
	})
	if err != nil {
		return fmt.Errorf("creating or updating secret %s: %w", secretName, err)
	}

	r.logger.Info(fmt.Sprintf("Secret '%s' %s", secretName, res))

	return nil
}

// +kubebuilder:rbac:groups=nais.io,resources=jwkers,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=nais.io,resources=jwkers/status,verbs=get;update;patch

func (r *JwkerReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	hash := ""
	correlationId := uuid.New().String()
	var jwker jwkerv1.Jwker

	jwkermetrics.JwkersProcessedCount.Inc()

	r.logger = r.Log.WithValues(
		"jwker", req.NamespacedName,
		"jwker_name", req.Name,
		"jwker_namespace", req.Namespace,
		"correlation_id", correlationId,
	)

	// purge other systems if resource was deleted
	err := r.Get(ctx, req.NamespacedName, &jwker)
	switch {
	case errors.IsNotFound(err):
		err := r.purge(ctx, req)
		if err == nil {
			return ctrl.Result{}, nil
		}
		r.reportError(err, "failed purge")
		return ctrl.Result{
			RequeueAfter: requeueInterval,
		}, err

	case err != nil:
		r.reportError(err, "unable to get jwker resource from cluster")
		return ctrl.Result{
			RequeueAfter: requeueInterval,
		}, nil
	}

	hash, err = jwker.Spec.Hash()
	if err != nil {
		r.reportError(err, "failed to calculate hash")
		return ctrl.Result{}, err
	}
	if jwker.Status.SynchronizationHash == hash {
		return ctrl.Result{}, nil
	}

	// Update Jwker resource with status event
	defer func() {
		jwker.Status.SynchronizationTime = time.Now().UnixNano()
		if jwker.Status.SynchronizationState == events.FailedSynchronization || jwker.Status.SynchronizationState == events.FailedPrepare {
			return
		}

		err := r.updateJwker(ctx, jwker, func(existing *jwkerv1.Jwker) error {
			existing.Status = jwker.Status
			return r.Update(ctx, existing)
		})
		if err != nil {
			r.logger.Error(err, "failed writing status")
		}
	}()

	// prepare and commit
	tx, err := r.prepare(ctx, req, jwker)
	if err != nil {
		jwker.Status.SynchronizationState = events.FailedPrepare
		r.reportError(err, "failed prepare jwks")
		return ctrl.Result{
			RequeueAfter: requeueInterval,
		}, nil
	}

	tx.jwker = jwker
	err = r.create(*tx)
	if err != nil {
		jwker.Status.SynchronizationState = events.FailedSynchronization
		r.reportError(err, "failed synchronization")
		return ctrl.Result{
			RequeueAfter: requeueInterval,
		}, nil
	}

	jwker.Status.SynchronizationState = events.RolloutComplete
	jwker.Status.SynchronizationHash = hash
	jwker.Status.SynchronizationSecretName = tx.jwker.Spec.SecretName

	// delete unused secrets from cluster
	for _, oldSecret := range tx.secretLists.Unused.Items {
		if oldSecret.GetName() == jwker.Spec.SecretName {
			continue
		}

		if err := r.Delete(tx.ctx, &oldSecret); err != nil {
			r.logger.Error(err, "failed deletion")
		}
	}

	return ctrl.Result{}, nil
}

var jwkersync sync.Mutex

func (r *JwkerReconciler) updateJwker(ctx context.Context, jwker jwkerv1.Jwker, updateFunc func(existing *jwkerv1.Jwker) error) error {
	jwkersync.Lock()
	defer jwkersync.Unlock()

	existing := &jwkerv1.Jwker{}
	err := r.Get(ctx, client.ObjectKey{Namespace: jwker.GetNamespace(), Name: jwker.GetName()}, existing)
	if err != nil {
		return fmt.Errorf("get newest version of Jwker: %s", err)
	}

	return updateFunc(existing)
}

func (r *JwkerReconciler) shouldUpdateSecrets(jwker jwkerv1.Jwker) bool {
	return jwker.Spec.SecretName != jwker.Status.SynchronizationSecretName
}

func (r *JwkerReconciler) reportError(err error, message string) {
	r.logger.Error(err, message)
	jwkermetrics.JwkersProcessingFailedCount.Inc()
}

func (r *JwkerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	opts := controller.Options{
		MaxConcurrentReconciles: r.Config.MaxConcurrentReconciles,
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&jwkerv1.Jwker{}).
		WithOptions(opts).
		Complete(r)
}
