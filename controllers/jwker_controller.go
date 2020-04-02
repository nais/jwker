package controllers

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	jose "gopkg.in/square/go-jose.v2"
	jwkerv1 "nais.io/navikt/jwker/api/v1"
)

// JwkerReconciler reconciles a Jwker object
type JwkerReconciler struct {
	client.Client
	Log    logr.Logger
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=jwker.nais.io,resources=jwkers,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=jwker.nais.io,resources=jwkers/status,verbs=get;update;patch

type jwkerAppSet struct {
	Appid        string             `json:"appId"`
	Jwks         jose.JSONWebKeySet `json:"jwks"`
	AccessPolicy AccessPolicy       `json:"accessPolicy"`
}
type AccessPolicy struct {
	Inbound  []string `json:"inbound"`
	Outbound []string `json:"outbound"`
}

func (r *JwkerReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	var jwker jwkerv1.Jwker
	ctx := context.Background()
	_ = r.Log.WithValues("jwker", req.NamespacedName)
	if err := r.Get(ctx, req.NamespacedName, &jwker); err != nil {
		r.Log.Error(err, "Unable to fetch jwkr")
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		r.Log.Error(err, "Unable to generate private key")
	}

	jwk := jose.JSONWebKey{
		Key:          privateKey,
		Certificates: nil,
		KeyID:        fmt.Sprintf("whateverunique"),
		Use:          "sig",
	}
	var publicjwks []jose.JSONWebKey

	publicjwks = append(publicjwks, jwk.Public())

	keyset := jose.JSONWebKeySet{Keys: publicjwks}
	var inbound []string
	var outbound []string
	for _, rule := range jwker.Spec.AccessPolicy.Inbound.Rules {
		inbound = append(inbound, fmt.Sprintf("%s:%s:%s", rule.Cluster, rule.Namespace, rule.Application))
	}
	for _, rule := range jwker.Spec.AccessPolicy.Outbound.Rules {
		outbound = append(outbound, fmt.Sprintf("%s:%s:%s", rule.Cluster, rule.Namespace, rule.Application))
	}
	appkeyset := jwkerAppSet{
		Appid: "xyz",
		Jwks:  keyset,
		AccessPolicy: AccessPolicy{
			Inbound:  inbound,
			Outbound: outbound,
		},
	}
	appjson, err := json.Marshal(appkeyset)
	if err != nil {
		r.Log.Error(err, "unable to marshall object")
	}

	fmt.Printf("%#v\n", string(appjson))

	return ctrl.Result{}, nil
}

func (r *JwkerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&jwkerv1.Jwker{}).
		Complete(r)
}
