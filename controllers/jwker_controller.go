package controllers

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	"gopkg.in/square/go-jose.v2"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	jwkerv1 "nais.io/navikt/jwker/api/v1"
	"nais.io/navikt/jwker/secretscreator"
	"nais.io/navikt/jwker/utils"
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
}

// +kubebuilder:rbac:groups=jwker.nais.io,resources=jwkers,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=jwker.nais.io,resources=jwkers/status,verbs=get;update;patch

func (r *JwkerReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	var j jwkerv1.Jwker
	ctx := context.Background()
	_ = r.Log.WithValues("jwker", req.NamespacedName)
	if err := r.Get(ctx, req.NamespacedName, &j); err != nil {
		r.Log.Info(fmt.Sprintf("This is when we clean up app: %s in namespace: %s", req.Name, req.Namespace))
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	jwkerClientID := utils.AppId{Name: "jwker", Namespace: "nais", Cluster: r.ClusterName}
	appClientId := utils.AppId{Name: j.Name, Namespace: j.Namespace, Cluster: r.ClusterName}

	jwkerPrivateJwk := r.JwkerPrivateJwks.Keys[0]
	tokendingsToken, err := utils.GetTokenDingsToken(&jwkerPrivateJwk, jwkerClientID, r.TokenDingsUrl)
	if err != nil {
		r.Log.Error(err, "unable to fetch token from tokendings")
		return ctrl.Result{}, err
	}

	clientJwk, err := utils.JwkKeyGenerator()
	if err != nil {
		r.Log.Error(err, "Unable to generate client JWK")
		return ctrl.Result{}, err
	}

	clientPrivateJwks, clientPublicJwks, err := utils.JwksGenerator(clientJwk)
	if err != nil {
		r.Log.Error(err, "Unable to generate client JWKS")
		return ctrl.Result{}, err
	}
	secrets, err := r.retrieveJwkerSecrets(req.Name, req.Namespace)
	if err != nil {
		r.Log.Error(err, "Unable to retrieve secrets from cluster")
	}
	for _, secret := range secrets.Items {
		if secret.Name != j.Spec.SecretName {
			r.Log.Info(fmt.Sprintf("Deleting secret %s in %s", secret.Name, secret.Namespace))
			r.Client.Delete(ctx, secret.DeepCopyObject())
		}
	}

	secretSpec, err := secretscreator.CreateSecret(req.Name, j.Spec.SecretName, req.Namespace, clientPrivateJwks)
	if err != nil {
		r.Log.Error(err, "Unable to create secretSpec object")
	}
	if err := r.Client.Get(ctx, client.ObjectKey{Namespace: j.Namespace, Name: j.Spec.SecretName}, secretSpec.DeepCopyObject()); err != nil {
		r.Log.Info(fmt.Sprintf("Creating secret %s in %s", secretSpec.Name, secretSpec.Namespace))
		if err := r.applySecret(ctx, secretSpec); err != nil {
			r.Log.Error(err, "Unable to create or update secretSpec")
		}
		r.Log.Info(fmt.Sprintf("Registering app %s:%s:%s with token-dingz", appClientId.Cluster, appClientId.Namespace, appClientId.Name))
	}

	clientRegistrationResponse, err := utils.RegisterClient(&jwkerPrivateJwk, &clientPublicJwks, tokendingsToken.AccessToken, r.TokenDingsUrl, appClientId, &j)
	if err != nil {
		r.Log.Error(err, "Unable to register client")
	}

	fmt.Printf("clientresponse: %#v\n", clientRegistrationResponse)

	return ctrl.Result{}, nil
}

func (r *JwkerReconciler) retrieveJwkerSecrets(app, namespace string) (corev1.SecretList, error) {
	var secrets corev1.SecretList
	var mLabels = client.MatchingLabels{}

	mLabels["app"] = app
	mLabels["type"] = "jwker.nais.io"
	if err := r.Client.List(context.Background(), &secrets, client.InNamespace(namespace), mLabels); err != nil {
		return secrets, err
	}
	return secrets, nil
}

func (r *JwkerReconciler) applySecret(ctx context.Context, secret v1.Secret) error {
	if err := r.Client.Create(ctx, secret.DeepCopyObject()); err != nil {
		return err
	}
	return nil
}

func (r *JwkerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&jwkerv1.Jwker{}).
		Complete(r)
}
