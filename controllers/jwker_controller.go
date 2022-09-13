package controllers

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/go-logr/logr"
	"github.com/google/uuid"
	jwkerv1 "github.com/nais/liberator/pkg/apis/nais.io/v1"
	"github.com/nais/liberator/pkg/events"
	"github.com/nais/liberator/pkg/kubernetes"
	log "github.com/sirupsen/logrus"
	"gopkg.in/square/go-jose.v2"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/nais/jwker/pkg/config"
	jwkermetrics "github.com/nais/jwker/pkg/metrics"
	"github.com/nais/jwker/pkg/pods"
	"github.com/nais/jwker/pkg/secret"
	"github.com/nais/jwker/pkg/tokendings"
	"github.com/nais/jwker/utils"
)

const (
	refreshTokenRetryInterval = 10 * time.Second
	requeueInterval           = 10 * time.Second
)
const (
	JWKKeyName        = "privateJWK"
	PrivateSecretName = "jwker-private-jwk"
)

// JwkerReconciler reconciles a Jwker object
type JwkerReconciler struct {
	client.Client
	Log             logr.Logger
	Scheme          *runtime.Scheme
	Reader          client.Reader
	Recorder        record.EventRecorder
	logger          logr.Logger
	TokendingsToken *tokendings.TokenResponse
	Config          *config.Config
}

func (r *JwkerReconciler) appClientID(req ctrl.Request) tokendings.ClientId {
	return tokendings.ClientId{
		Name:      req.Name,
		Namespace: req.Namespace,
		Cluster:   r.Config.ClusterName,
	}
}

func (r *JwkerReconciler) RefreshToken() {
	jwk := r.Config.AuthProvider.ClientJwk
	clientID := r.Config.AuthProvider.ClientID
	endpoint := r.Config.Tokendings.Metadata.TokenEndpoint

	var err error

	jwt, err := tokendings.ClientAssertion(jwk, clientID, endpoint)
	if err != nil {
		r.Log.Error(err, "failed to generate client assertion")
	}
	r.TokendingsToken = &tokendings.TokenResponse{
		AccessToken: jwt,
		TokenType:   "Bearer",
		ExpiresIn:   0,
		Scope:       "",
	}
}

// delete all associated objects
// TODO: needs finalizer
func (r *JwkerReconciler) purge(ctx context.Context, req ctrl.Request) error {
	aid := r.appClientID(req)

	r.logger.Info(fmt.Sprintf("Jwker resource %s in namespace: %s has been deleted. Cleaning up resources", req.Name, req.Namespace))

	r.logger.Info(fmt.Sprintf("Deleting resource %s in namespace %s from tokendings", req.Name, req.Namespace))
	if err := tokendings.DeleteClient(ctx, r.TokendingsToken.AccessToken, r.Config.Tokendings.BaseURL, aid); err != nil {
		return fmt.Errorf("deleting resource from Tokendings: %s", err)
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
	keyset      utils.KeySet
	secretLists kubernetes.SecretLists
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
	secrets := kubernetes.ListUsedAndUnusedSecretsForPods(allSecrets, *podList)

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
		newJwk, err = utils.GenerateJWK()
		if err != nil {
			return nil, err
		}
	}

	keyset := utils.KeySetWithExisting(newJwk, existingJwks.Keys)

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
		r.Config.AuthProvider.ClientJwk,
		&tx.keyset.Public,
		app,
		tx.jwker,
	)

	if err != nil {
		return fmt.Errorf("create client registration payload: %s", err)
	}

	r.logger.Info(fmt.Sprintf("Registering app %s with tokendings", app.String()))
	err = tokendings.RegisterClient(
		*cr,
		r.TokendingsToken.AccessToken,
		r.Config.Tokendings.BaseURL,
	)

	if err != nil {
		return fmt.Errorf("failed registering client: %s", err)
	}

	r.logger.Info(fmt.Sprintf("Reconciling secrets for app %s in namespace %s", app.Name, app.Namespace))

	jwk, err := secret.FirstJWK(tx.keyset.Private)
	if err != nil {
		return fmt.Errorf("unable to get first jwk from jwks: %s", err)
	}

	secretData := secret.PodSecretData{
		ClientId:         app,
		Jwk:              *jwk,
		TokendingsConfig: r.Config.Tokendings,
	}

	if err := secret.CreateAppSecret(r.Client, tx.ctx, tx.jwker.Spec.SecretName, secretData); err != nil {
		return fmt.Errorf("reconciling secrets: %s", err)
	}

	return nil
}

// +kubebuilder:rbac:groups=nais.io,resources=jwkers,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=nais.io,resources=jwkers/status,verbs=get;update;patch

func (r *JwkerReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	hash := ""
	correlationId := uuid.New().String()
	var jwker jwkerv1.Jwker

	jwkermetrics.JwkersProcessedCount.Inc()

	if err := r.setupJwkerJwk(ctx); err != nil {
		return ctrl.Result{}, err
	}

	/*if r.TokendingsToken == nil {
		return ctrl.Result{
			RequeueAfter: requeueInterval,
		}, nil
	}*/
	r.RefreshToken()

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
	return ctrl.NewControllerManagedBy(mgr).
		For(&jwkerv1.Jwker{}).
		Complete(r)
}

func (r *JwkerReconciler) setupJwkerJwk(ctx context.Context) error {

	cfg := r.Config
	jwk, err := ensurePrivateJWKSecret(ctx, r.Client, cfg.Namespace, PrivateSecretName)
	if err != nil {
		r.logger.Error(err, "unable to read or create private jwk secret")
		return err
	}

	r.Config.AuthProvider.ClientJwk = jwk

	if err := ensurePublicSecret(ctx, r.Client, cfg.Namespace, cfg.SharedPublicSecretName, jwk); err != nil {
		r.logger.Error(err, "unable to create public jwk secret")
		return err
	}
	return nil
}

func ensurePublicSecret(ctx context.Context, c client.Client, namespace string, name string, jwk *jose.JSONWebKey) error {
	existing, err := getSecret(ctx, c, namespace, name)
	if existing != nil {
		//secret already exists
		return nil
	}
	keySet := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk.Public()}}
	b, err := json.Marshal(&keySet)
	if err != nil {
		return err
	}
	_, err = secret.CreateSecret(ctx, c, name, namespace, nil, map[string]string{"AUTH_CLIENT_JWKS": string(b)})
	return err
}

func parseJWK(json []byte) (*jose.JSONWebKey, error) {
	jwk := &jose.JSONWebKey{}
	if err := jwk.UnmarshalJSON(json); err != nil {
		return nil, err
	}

	return jwk, nil
}

func ensurePrivateJWKSecret(ctx context.Context, c client.Client, namespace, secretName string) (*jose.JSONWebKey, error) {
	privateJWKSecret, err := getSecret(ctx, c, namespace, secretName)
	if err != nil {
		return nil, err
	}

	if privateJWKSecret != nil {
		jwkJSON := privateJWKSecret.Data[JWKKeyName]
		if len(jwkJSON) == 0 {
			return nil, fmt.Errorf("no %s key in secret: %s", JWKKeyName, secretName)
		}
		return parseJWK([]byte(jwkJSON))
	}

	jwk, err := utils.GenerateJWK()
	if err != nil {
		return nil, fmt.Errorf("failed to generate JWK: %w", err)
	}

	jwkJson, err := json.Marshal(jwk)
	if err != nil {
		return nil, err
	}
	data := map[string]string{
		"privateJWK": string(jwkJson),
	}

	_, err = secret.CreateSecret(ctx, c, secretName, namespace, nil, data)

	if err != nil {
		return nil, fmt.Errorf("failed to create secret: %w", err)
	}
	return &jwk, nil
}

func getSecret(ctx context.Context, c client.Client, namespace, secretName string) (*corev1.Secret, error) {
	var existingSecret corev1.Secret
	if err := c.Get(ctx, client.ObjectKey{Namespace: namespace, Name: secretName}, &existingSecret); errors.IsNotFound(err) {
		log.Info("secret not found:", secretName)
		return nil, nil
	} else if err != nil {
		log.Info("error getting secret:", secretName, " error:", err)
		return nil, err
	} else {
		log.Info("found secret:", secretName)
		return &existingSecret, nil
	}
}
