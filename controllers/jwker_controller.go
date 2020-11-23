package controllers

import (
	"context"
	"fmt"
	"github.com/go-logr/logr"
	jwkerv1 "github.com/nais/jwker/api/v1"
	jwkermetrics "github.com/nais/jwker/pkg/metrics"
	"github.com/nais/jwker/pkg/pods"
	"github.com/nais/jwker/pkg/secret"
	"github.com/nais/jwker/pkg/tokendings"
	"github.com/nais/jwker/utils"
	log "github.com/sirupsen/logrus"
	"gopkg.in/square/go-jose.v2"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"net/url"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"time"
)

const (
	refreshTokenRetryInterval = 10 * time.Second
	requeueInterval           = 10 * time.Second
)

// JwkerReconciler reconciles a Jwker object
type JwkerReconciler struct {
	client.Client
	Log                logr.Logger
	Scheme             *runtime.Scheme
	ClusterName        string
	ClientID           string
	Endpoint           string
	TokendingsClientID string
	TokenDingsUrl      string
	logger             logr.Logger
	TokendingsToken    *tokendings.TokenResponse
	AzureCredentials   jose.JSONWebKey
}

func (r *JwkerReconciler) appClientID(req ctrl.Request) tokendings.ClientId {
	return tokendings.ClientId{
		Name:      req.Name,
		Namespace: req.Namespace,
		Cluster:   r.ClusterName,
	}
}

func (r *JwkerReconciler) RefreshToken() {
	var err error
	exp := 0 * time.Second

	scope := &url.URL{
		Scheme: "api",
		Host:   r.TokendingsClientID,
		Path:   "/.default",
	}
	sc := scope.String()

	t := time.NewTimer(exp)
	for range t.C {

		// Fetching a token for communicating with tokendings
		r.TokendingsToken, err = tokendings.GetToken(&r.AzureCredentials, r.ClientID, sc, r.Endpoint)
		if err != nil {
			r.Log.Error(err, "unable to fetch token from azure. will retry in 10 secs.")
			exp = refreshTokenRetryInterval
		} else {
			secs := float64(r.TokendingsToken.ExpiresIn) / 3
			exp = time.Duration(int(secs)) * time.Second
			log.Infof("got token from Azure, next refresh in %s", exp)
		}
		t.Reset(exp)
	}
}

// delete all associated objects
// TODO: needs finalizer
func (r *JwkerReconciler) purge(ctx context.Context, req ctrl.Request) error {
	aid := r.appClientID(req)

	r.logger.Info(fmt.Sprintf("Jwker resource %s in namespace: %s has been deleted. Cleaning up resources", req.Name, req.Namespace))

	r.logger.Info(fmt.Sprintf("Deleting resource %s in namespace %s from tokendings", req.Name, req.Namespace))
	if err := tokendings.DeleteClient(ctx, r.TokendingsToken.AccessToken, r.TokenDingsUrl, aid); err != nil {
		return fmt.Errorf("deleting resource from Tokendings: %s", err)
	}

	r.logger.Info(fmt.Sprintf("Deleting application %s jwker secrets in namespace %s from cluster", req.Name, req.Namespace))
	if err := secret.DeleteClusterSecrets(r, ctx, aid, ""); err != nil {
		return fmt.Errorf("deleting secrets from cluster: %s", err)
	}
	jwkermetrics.JwkerSecretsTotal.Dec()

	return nil
}

type secretLists struct {
	Used   corev1.SecretList
	Unused corev1.SecretList
}

type transaction struct {
	ctx         context.Context
	req         ctrl.Request
	keyset      utils.KeySet
	secretLists secretLists
	jwker       jwkerv1.Jwker
}

func secretInPod(secret corev1.Secret, pod corev1.Pod) bool {
	for _, volume := range pod.Spec.Volumes {
		if volume.Secret != nil && volume.Secret.SecretName == secret.Name {
			return true
		}
	}
	return false
}

func secretInPods(secret corev1.Secret, pods corev1.PodList) bool {
	for _, pod := range pods.Items {
		if secretInPod(secret, pod) {
			return true
		}
	}
	return false
}

func podSecretLists(secrets corev1.SecretList, pods corev1.PodList) secretLists {
	lists := secretLists{
		Used: corev1.SecretList{
			Items: make([]corev1.Secret, 0),
		},
		Unused: corev1.SecretList{
			Items: make([]corev1.Secret, 0),
		},
	}

	for _, sec := range secrets.Items {
		if secretInPods(sec, pods) {
			lists.Used.Items = append(lists.Used.Items, sec)
		} else {
			lists.Unused.Items = append(lists.Unused.Items, sec)
		}
	}

	return lists
}

func (r *JwkerReconciler) prepare(ctx context.Context, req ctrl.Request) (*transaction, error) {
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
	secrets := podSecretLists(allSecrets, *podList)

	newJwk, err := utils.GenerateJWK()
	if err != nil {
		return nil, err
	}

	jwks := jose.JSONWebKeySet{}

	for _, sec := range secrets.Used.Items {
		jwk, err := secret.ExtractJWK(sec)
		if err != nil {
			return nil, err
		}
		jwks.Keys = append(jwks.Keys, *jwk)
	}

	keyset := utils.KeySetWithExisting(newJwk, jwks.Keys)

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
		&r.AzureCredentials,
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
		r.TokenDingsUrl,
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
		ClientId:               app,
		Jwk:                    *jwk,
		TokenDingsWellKnownUrl: secret.WellKnownUrl(r.TokenDingsUrl),
	}

	if err := secret.CreateSecret(r, tx.ctx, tx.jwker.Spec.SecretName, secretData); err != nil {
		return fmt.Errorf("reconciling secrets: %s", err)
	}

	return nil
}

// +kubebuilder:rbac:groups=nais.io,resources=jwkers,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=nais.io,resources=jwkers/status,verbs=get;update;patch

func (r *JwkerReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	ctx := context.Background()
	hash := ""
	var jwker jwkerv1.Jwker

	jwkermetrics.JwkersProcessedCount.Inc()

	if r.TokendingsToken == nil {
		return ctrl.Result{
			RequeueAfter: requeueInterval,
		}, nil
	}

	r.logger = r.Log.WithValues("jwker", req.NamespacedName)

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
		if jwker.Status.SynchronizationState == jwkerv1.EventFailedSynchronization || jwker.Status.SynchronizationState == jwkerv1.EventFailedPrepare {
			return
		}
		err := r.Update(ctx, &jwker)
		if err != nil {
			r.logger.Error(err, "failed writing status")
		}
	}()

	// prepare and commit
	tx, err := r.prepare(ctx, req)
	if err != nil {
		jwker.Status.SynchronizationState = jwkerv1.EventFailedPrepare
		r.reportError(err, "failed prepare jwks")
		return ctrl.Result{
			RequeueAfter: requeueInterval,
		}, nil
	}

	tx.jwker = jwker
	err = r.create(*tx)
	if err != nil {
		jwker.Status.SynchronizationState = jwkerv1.EventFailedSynchronization
		r.reportError(err, "failed synchronization")
		return ctrl.Result{
			RequeueAfter: requeueInterval,
		}, nil
	}

	jwker.Status.SynchronizationState = jwkerv1.EventRolloutComplete
	jwker.Status.SynchronizationHash = hash

	// delete unused secrets from cluster
	for _, oldSecret := range tx.secretLists.Unused.Items {
		if err := r.Delete(tx.ctx, &oldSecret); err != nil {
			r.logger.Error(err, "failed deletion")
		}
	}

	return ctrl.Result{}, nil
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
