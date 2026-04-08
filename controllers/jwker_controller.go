package controllers

import (
	"context"
	"errors"
	"fmt"

	"github.com/go-jose/go-jose/v4"
	"github.com/nais/jwker/pkg/config"
	"github.com/nais/jwker/pkg/jwk"
	jwkermetrics "github.com/nais/jwker/pkg/metric"
	"github.com/nais/jwker/pkg/secret"
	"github.com/nais/jwker/pkg/tokendings"
	jwkerv1 "github.com/nais/liberator/pkg/apis/nais.io/v1"
	"github.com/nais/liberator/pkg/events"
	libernetes "github.com/nais/liberator/pkg/kubernetes"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kevents "k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

const (
	finalizer = "jwker.nais.io/finalizer"
)

// JwkerReconciler reconciles a Jwker object
type JwkerReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Reader   client.Reader
	Recorder kevents.EventRecorder
	Config   *config.Config
}

type transaction struct {
	ctx         context.Context
	req         ctrl.Request
	jwks        jwk.KeySet
	secretLists libernetes.SecretLists
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

// +kubebuilder:rbac:groups=nais.io,resources=jwkers,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=nais.io,resources=jwkers/status,verbs=get;update;patch

func (r *JwkerReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := ctrl.LoggerFrom(ctx).WithName("reconciler")
	ctx = ctrl.LoggerInto(ctx, log)
	defer jwkermetrics.JwkersProcessedCount.Inc()

	var jwker jwkerv1.Jwker
	err := r.Get(ctx, req.NamespacedName, &jwker)
	if err != nil {
		// we ignore not found errors as cleanup should already be handled by the finalizer
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// object is marked for deletion
	if !jwker.ObjectMeta.DeletionTimestamp.IsZero() {
		if err := r.finalize(ctx, r.clientID(req), &jwker); err != nil {
			jwkermetrics.JwkersProcessingFailedCount.Inc()
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

	if jwker.GetGeneration() == jwker.Status.ObservedGeneration {
		log.V(4).WithValues(
			".metadata.generation", jwker.GetGeneration(),
			".status.observedGeneration", jwker.Status.ObservedGeneration,
		).Info("generation is unchanged; skipping reconciliation")
		return ctrl.Result{}, nil
	}

	// update status subresource at the end of reconciliation, regardless of success or failure
	defer func() {
		jwker.Status.SynchronizationTimestamp = metav1.Now()

		if err := r.updateJwker(ctx, jwker, func(existing *jwkerv1.Jwker) error {
			existing.Status = jwker.Status
			return r.Status().Update(ctx, existing)
		}); err != nil {
			log.Error(err, "failed to update status subresource")
			return
		}
	}()

	tx, err := r.prepare(ctx, req, jwker)
	if err != nil {
		jwker.Status.SynchronizationState = events.FailedPrepare
		jwkermetrics.JwkersProcessingFailedCount.Inc()
		return ctrl.Result{}, fmt.Errorf("prepare: %w", err)
	}

	err = r.synchronize(*tx, jwker)
	if err != nil {
		jwker.Status.SynchronizationState = events.FailedSynchronization
		jwkermetrics.JwkersProcessingFailedCount.Inc()
		return ctrl.Result{}, fmt.Errorf("synchronize: %w", err)
	}

	jwker.Status.ObservedGeneration = jwker.GetGeneration()
	jwker.Status.SynchronizationState = events.RolloutComplete
	jwker.Status.SynchronizationSecretName = jwker.Spec.SecretName
	jwker.Status.ClientID = r.clientID(req).String()
	jwker.Status.KeyIDs = tx.jwks.KeyIDs()

	for _, oldSecret := range tx.secretLists.Unused.Items {
		if oldSecret.GetName() == jwker.Spec.SecretName {
			continue
		}

		log.Info(fmt.Sprintf("deleting unused secret %q...", oldSecret.GetName()))
		if err := r.Delete(tx.ctx, &oldSecret); err != nil {
			if !k8serrors.IsNotFound(err) {
				log.Error(err, fmt.Sprintf("failed to delete unused secret %q", oldSecret.GetName()))
			}
		}
	}

	log.Info("successfully reconciled")
	return ctrl.Result{}, nil
}

func (r *JwkerReconciler) prepare(ctx context.Context, req ctrl.Request, jwker jwkerv1.Jwker) (*transaction, error) {
	log := ctrl.LoggerFrom(ctx).WithValues("subsystem", "prepare")

	secrets, err := libernetes.ListSecretsForApplication(ctx, r.Client, client.ObjectKeyFromObject(&jwker), secret.Labels(req.Name))
	if err != nil {
		return nil, fmt.Errorf("list secrets for app: %w", err)
	}

	previousInUseJWKSet, err := secret.ExtractPreviousInUseJWKSet(secrets)
	if err != nil {
		return nil, fmt.Errorf("extract previous JWK set: %w", err)
	}

	if jwker.Status.SynchronizationSecretName == "" {
		log.Info("status has no known secretName; will generate new JWK")
		return r.generateNewKeySet(ctx, req, previousInUseJWKSet, secrets)
	}

	currentJWK, err := secret.ExtractCurrentJWK(jwker.Status.SynchronizationSecretName, secrets)
	if err != nil {
		if !errors.Is(err, secret.ErrNotFound) {
			return nil, fmt.Errorf("extract current JWK: %w", err)
		}
	}

	if jwker.Spec.SecretName == jwker.Status.SynchronizationSecretName && currentJWK.Key != nil {
		log.Info("secret name unchanged; will reuse existing JWK", "keyID", currentJWK.KeyID, "secretName", jwker.Spec.SecretName)
		keyset := jwk.KeySetWithExisting(currentJWK, previousInUseJWKSet)
		return &transaction{ctx, req, keyset, secrets}, nil
	}

	if currentJWK.Key != nil {
		jwk.EnsureKeyInSet(&previousInUseJWKSet, currentJWK)
		log.Info("secret name has changed; will generate new JWK", "oldSecretName", jwker.Status.SynchronizationSecretName, "newSecretName", jwker.Spec.SecretName)
	} else {
		log.Info("current JWK not found; will generate new JWK", "expectedSecretName", jwker.Status.SynchronizationSecretName)
	}

	return r.generateNewKeySet(ctx, req, previousInUseJWKSet, secrets)
}

func (r *JwkerReconciler) generateNewKeySet(ctx context.Context, req ctrl.Request, previousInUseJWKSet jose.JSONWebKeySet, secrets libernetes.SecretLists) (*transaction, error) {
	newJWK, err := jwk.Generate()
	if err != nil {
		return nil, err
	}

	keyset := jwk.KeySetWithExisting(newJWK, previousInUseJWKSet)
	return &transaction{ctx, req, keyset, secrets}, nil
}

func (r *JwkerReconciler) synchronize(tx transaction, jwker jwkerv1.Jwker) error {
	clientID := r.clientID(tx.req)
	log := ctrl.LoggerFrom(tx.ctx).WithValues("subsystem", "synchronize")

	registration, err := tokendings.MakeClientRegistration(r.Config.ClientJwk, &tx.jwks.PublicKeys, clientID, jwker)
	if err != nil {
		return fmt.Errorf("create client registration payload: %s", err)
	}

	instances := r.Config.TokendingsInstances
	for _, instance := range instances {
		if err := instance.RegisterClient(registration); err != nil {
			return fmt.Errorf("registering client with Tokendings %q: %w", instance.BaseURL, err)
		}
		log.Info(fmt.Sprintf("registered %q with Tokendings at %q", clientID.String(), instance.BaseURL))
	}

	secretName := jwker.Spec.SecretName
	secretData := secret.Data{ClientID: clientID, Jwk: tx.jwks.PrivateKey, Tokendings: instances[0]}
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

		return ctrl.SetControllerReference(&jwker, target, r.Scheme)
	})
	if err != nil {
		return fmt.Errorf("creating or updating secret %s: %w", secretName, err)
	}

	log.Info(fmt.Sprintf("secret %q %s", secretName, res))
	return nil
}

// finalize purges relevant resources from external systems (i.e. the tokendings instances)
func (r *JwkerReconciler) finalize(ctx context.Context, clientId tokendings.ClientID, jwker *jwkerv1.Jwker) error {
	if !controllerutil.ContainsFinalizer(jwker, finalizer) {
		return nil
	}

	log := ctrl.LoggerFrom(ctx).WithValues("subsystem", "finalize")

	for _, instance := range r.Config.TokendingsInstances {
		if err := instance.DeleteClient(ctx, clientId); err != nil {
			return fmt.Errorf("deleting client from Tokendings at %q: %w", instance.BaseURL, err)
		}
		log.Info(fmt.Sprintf("deleted %q from Tokendings at %q", clientId.String(), instance.BaseURL))
	}

	controllerutil.RemoveFinalizer(jwker, finalizer)
	if err := r.Client.Update(ctx, jwker); err != nil {
		return fmt.Errorf("removing finalizer: %w", err)
	}

	jwkermetrics.JwkersFinalizedCount.Inc()
	return nil
}

func (r *JwkerReconciler) updateJwker(ctx context.Context, jwker jwkerv1.Jwker, updateFunc func(existing *jwkerv1.Jwker) error) error {
	existing := &jwkerv1.Jwker{}
	err := r.Get(ctx, client.ObjectKey{Namespace: jwker.GetNamespace(), Name: jwker.GetName()}, existing)
	if err != nil {
		return fmt.Errorf("get newest version of Jwker: %s", err)
	}

	return updateFunc(existing)
}

func (r *JwkerReconciler) clientID(req ctrl.Request) tokendings.ClientID {
	return tokendings.ClientID{
		Name:      req.Name,
		Namespace: req.Namespace,
		Cluster:   r.Config.ClusterName,
	}
}
