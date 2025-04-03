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

	"github.com/nais/jwker/pkg/config"
	"github.com/nais/jwker/pkg/jwk"
	jwkermetrics "github.com/nais/jwker/pkg/metric"
	"github.com/nais/jwker/pkg/secret"
	"github.com/nais/jwker/pkg/tokendings"
)

const (
	finalizer       = "jwker.nais.io/finalizer"
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

// finalize purges relevant resources from external systems (i.e. the tokendings instances)
func (r *JwkerReconciler) finalize(ctx context.Context, clientId tokendings.ClientId, jwker *jwkerv1.Jwker) error {
	if !controllerutil.ContainsFinalizer(jwker, finalizer) {
		return nil
	}

	for _, instance := range r.Config.TokendingsInstances {
		if err := instance.DeleteClient(ctx, clientId); err != nil {
			return fmt.Errorf("deleting resource from tokendings at %q: %w", instance.BaseURL, err)
		}
		r.logger.Info(fmt.Sprintf("Finalizer: deleted client from tokendings at %q", instance.BaseURL))
	}

	r.logger.Info(fmt.Sprintf("Finalizer: client deleted from %d tokendings instances", len(r.Config.TokendingsInstances)))

	// finally (heh, get it?), remove finalizer from Jwker resource to allow for garbage collection
	controllerutil.RemoveFinalizer(jwker, finalizer)
	err := r.Client.Update(ctx, jwker)
	if err != nil {
		return fmt.Errorf("removing finalizer: %w", err)
	}

	jwkermetrics.JwkersFinalizedCount.Inc()
	return nil
}

type transaction struct {
	ctx         context.Context
	req         ctrl.Request
	keyset      jwk.KeySet
	secretLists libernetes.SecretLists
	jwker       jwkerv1.Jwker
}

func (r *JwkerReconciler) prepare(ctx context.Context, req ctrl.Request, jwker jwkerv1.Jwker) (*transaction, error) {
	app := r.appClientID(req)

	secrets, err := libernetes.ListSecretsForApplication(ctx, r.Client, app.KubeObjectKey(), secret.Labels(app.Name))
	if err != nil {
		return nil, fmt.Errorf("list secrets for app: %w", err)
	}

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
		newJwk, err = jwk.Generate()
		if err != nil {
			return nil, err
		}
	}

	keyset := jwk.KeySetWithExisting(newJwk, existingJwks.Keys)

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

	// FIXME: this is wrong if we enable concurrent reconciles for the controller
	r.logger = r.Log.WithValues(
		"jwker", req.NamespacedName,
		"jwker_name", req.Name,
		"jwker_namespace", req.Namespace,
		"correlation_id", correlationId,
	)

	err := r.Get(ctx, req.NamespacedName, &jwker)
	if err != nil {
		// we ignore not found errors as cleanup should already be handled by the finalizer
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// object is marked for deletion
	if !jwker.ObjectMeta.DeletionTimestamp.IsZero() {
		if err := r.finalize(ctx, r.appClientID(req), &jwker); err != nil {
			r.reportError(err, "failed purge")
			return ctrl.Result{}, fmt.Errorf("finalize: %w", err)
		}
		return ctrl.Result{}, nil
	}

	if !controllerutil.ContainsFinalizer(&jwker, finalizer) {
		if err := r.updateJwker(ctx, jwker, func(existing *jwkerv1.Jwker) error {
			controllerutil.AddFinalizer(existing, finalizer)
			return r.Update(ctx, existing)
		}); err != nil {
			return ctrl.Result{}, fmt.Errorf("registering finalizer: %w", err)
		}
		return ctrl.Result{}, nil
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

		r.logger.Info(fmt.Sprintf("Deleting unused secret '%s'...", oldSecret.GetName()))
		if err := r.Delete(tx.ctx, &oldSecret); err != nil {
			if !errors.IsNotFound(err) {
				r.logger.Error(err, "failed deletion")
			}
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
