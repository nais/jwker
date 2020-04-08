package controllers

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	"gopkg.in/square/go-jose.v2"
	"k8s.io/apimachinery/pkg/runtime"
	jwkerv1 "nais.io/navikt/jwker/api/v1"
	"nais.io/navikt/jwker/utils"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// JwkerReconciler reconciles a Jwker object
type JwkerReconciler struct {
	client.Client
	Log           logr.Logger
	Scheme        *runtime.Scheme
	ClusterName   string
	StoragePath   string
	PrivateJwks   *jose.JSONWebKeySet
	TokenDingsUrl string
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

	jwkerPrivateJwk := r.PrivateJwks.Keys[0]
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

	_, clientPublicJwks, err := utils.JwksGenerator(clientJwk)
	if err != nil {
		r.Log.Error(err, "Unable to generate client JWKS")
		return ctrl.Result{}, err
	}

	clientRegistrationResponse, err := utils.RegisterClient(&jwkerPrivateJwk, &clientPublicJwks, tokendingsToken.AccessToken, r.TokenDingsUrl, appClientId, &j)
	fmt.Printf("clientresponse: %#v", clientRegistrationResponse)
	return ctrl.Result{}, nil
}

func (r *JwkerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&jwkerv1.Jwker{}).
		Complete(r)
}
