package controllers

import (
	"context"
	"fmt"
	"net/url"
	"time"

	"github.com/go-logr/logr"
	jwkerv1 "github.com/nais/jwker/api/v1"
	"github.com/nais/jwker/pkg/deployment"
	jwkermetrics "github.com/nais/jwker/pkg/metrics"
	"github.com/nais/jwker/pkg/secret"
	"github.com/nais/jwker/pkg/tokendings"
	"github.com/nais/jwker/utils"
	"gopkg.in/square/go-jose.v2"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	refreshTokenRetryInterval = 10 * time.Second
)

// JwkerReconciler reconciles a Jwker object
type JwkerReconciler struct {
	client.Client
	Log                logr.Logger
	Scheme             *runtime.Scheme
	ClusterName        string
	ClientID           string
	TenantID           string
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
		r.TokendingsToken, err = tokendings.GetToken(&r.AzureCredentials, r.ClientID, sc, r.TenantID)
		if err != nil {
			r.logger.Error(err, "unable to fetch token from azure. will retry in 10 secs.")
			exp = refreshTokenRetryInterval
		} else {
			secs := float64(r.TokendingsToken.ExpiresIn) / 3
			exp = time.Duration(int(secs)) * time.Second
		}
		t.Reset(exp)
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

	return client.IgnoreNotFound(err)
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

func secretsInDeployment(secrets corev1.SecretList, deploy appsv1.Deployment) secretLists {
	lists := secretLists{
		Used: corev1.SecretList{
			Items: make([]corev1.Secret, 0),
		},
		Unused: corev1.SecretList{
			Items: make([]corev1.Secret, 0),
		},
	}

	for _, sec := range secrets.Items {
		used := false
		for _, volume := range deploy.Spec.Template.Spec.Volumes {
			if volume.Secret != nil && volume.Secret.SecretName == sec.Name {
				lists.Used.Items = append(lists.Used.Items, sec)
				used = true
			}
		}
		if !used {
			lists.Unused.Items = append(lists.Unused.Items, sec)
		}
	}

	return lists
}

func (r *JwkerReconciler) prepare(ctx context.Context, req ctrl.Request) (*transaction, error) {
	app := r.appClientID(req)

	// fetch deployment object for this app
	deploy, err := deployment.Deployment(ctx, app, r)
	if err != nil {
		return nil, err
	}

	// fetch all jwker managed secrets
	allSecrets, err := secret.ClusterSecrets(ctx, app, r.Client)
	if err != nil {
		return nil, err
	}

	// find intersect between secrets in use by deployment and all jwker managed secrets
	secrets := secretsInDeployment(allSecrets, *deploy)

	used := len(secrets.Used.Items)
	if used != 1 {
		return nil, fmt.Errorf("deployment has %d references to jwker secrets, expecting exactly 1", used)
	}

	newJwk, err := utils.GenerateJWK()
	if err != nil {
		return nil, err
	}

	jwks, err := secret.ExtractJWKS(secrets.Used.Items[0])
	if err != nil {
		return nil, err
	}

	if len(jwks.Keys) != 1 {
		return nil, fmt.Errorf("secret has %d keys, expecting exactly 1", used)
	}

	keyset := utils.BuildKeySet(newJwk, jwks.Keys[0])

	return &transaction{
		ctx:         ctx,
		req:         req,
		keyset:      keyset,
		secretLists: secrets,
	}, nil
}

func (r *JwkerReconciler) create(tr transaction) error {

	app := r.appClientID(tr.req)

	r.logger.Info(fmt.Sprintf("Registering app %s with tokendings", app.String()))
	err := tokendings.RegisterClient(
		&r.AzureCredentials,
		&tr.keyset.Public,
		r.TokendingsToken.AccessToken,
		r.TokenDingsUrl,
		app,
		tr.jwker,
	)

	// FIXME: tokendings doesn't work as advertised yet
	if false && err != nil {
		return fmt.Errorf("failed registering client: %s", err)
	}

	r.logger.Info(fmt.Sprintf("Reconciling secrets for app %s in namespace %s", app.Namespace, app.Name))
	if err := secret.ReconcileSecrets(r, tr.ctx, app, tr.jwker.Spec.SecretName, tr.keyset.Private); err != nil {
		return fmt.Errorf("reconciling secrets: %s", err)
	}

	err = r.Delete(tr.ctx, &tr.secretLists.Unused)
	if err != nil {
		return fmt.Errorf("delete old secrets: %s", err)
	}

	return nil
}

// +kubebuilder:rbac:groups=jwker.nais.io,resources=jwkers,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=jwker.nais.io,resources=jwkers/status,verbs=get;update;patch

func (r *JwkerReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	ctx := context.Background()
	changed := false
	hash := ""
	var j jwkerv1.Jwker
	var status jwkerv1.JwkerStatus

	// TODO: use less resources
	jwkermetrics.JwkersProcessedCount.Inc()
	if err := jwkermetrics.SetTotalJwkersMetric(r); err != nil {
		return ctrl.Result{}, err
	}
	if err := jwkermetrics.SetTotalJwkerSecrets(r); err != nil {
		return ctrl.Result{}, err
	}

	if r.TokendingsToken == nil {
		return ctrl.Result{
			RequeueAfter: time.Second * 10,
		}, nil
	}

	r.logger = r.Log.WithValues("jwker", req.NamespacedName)

	// purge other systems if resource was deleted
	err := r.Get(ctx, req.NamespacedName, &j)
	switch {
	case errors.IsNotFound(err):
		err := r.purge(ctx, req)
		if err != nil {
			r.logger.Error(err, "failed purge")
		}
		return ctrl.Result{}, client.IgnoreNotFound(err)
	case err != nil:
		return ctrl.Result{
			RequeueAfter: time.Second * 10,
		}, nil
	}

	hash, err = utils.Hash(j.Spec)
	if err != nil {
		return ctrl.Result{}, err
	}
	if j.Status.SynchronizationHash == hash && j.Status.SynchronizationState == jwkerv1.EventRolloutComplete {
		return ctrl.Result{}, nil
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
		existing.Status = status
		r.Update(ctx, &existing)

	}()

	// prepare and commit
	tx, err := r.prepare(ctx, req)
	if err != nil {
		j.Status.SynchronizationState = jwkerv1.EventFailedPrepare
		r.logger.Error(err, "failed prepare jwks")
		return ctrl.Result{
			RequeueAfter: time.Second * 10,
		}, nil
	}

	tx.jwker = j
	err = r.create(*tx)
	if err != nil {
		j.Status.SynchronizationState = jwkerv1.EventFailedSynchronization
		r.logger.Error(err, "failed synchronization")
		return ctrl.Result{
			RequeueAfter: time.Second * 10,
		}, nil
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
