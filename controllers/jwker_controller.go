package controllers

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io/ioutil"

	"encoding/json"
	"github.com/go-logr/logr"
	"gopkg.in/square/go-jose.v2"
	"k8s.io/apimachinery/pkg/runtime"
	jwkerv1 "nais.io/navikt/jwker/api/v1"
	"nais.io/navikt/jwker/storage"
	"nais.io/navikt/jwker/utils"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// JwkerReconciler reconciles a Jwker object
type JwkerReconciler struct {
	client.Client
	Log         logr.Logger
	Scheme      *runtime.Scheme
	ClusterName string
	StoragePath string
}

// +kubebuilder:rbac:groups=jwker.nais.io,resources=jwkers,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=jwker.nais.io,resources=jwkers/status,verbs=get;update;patch

func init() {

}

func (r *JwkerReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	var jwker jwkerv1.Jwker
	ctx := context.Background()
	_ = r.Log.WithValues("jwker", req.NamespacedName)

	if err := r.Get(ctx, req.NamespacedName, &jwker); err != nil {
		r.Log.Error(err, "Unable to fetch jwkr")
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	appId := fmt.Sprintf("%s:%s:%s", r.ClusterName, jwker.Namespace, jwker.Name)
	jwkerStorage, _ := storage.New()
	appSets, err := jwkerStorage.ReadJwkerStorage(r.StoragePath)

	if err != nil {
		r.Log.Error(err, "Could not read storage")
	}
	if val, ok := appSets[appId]; !ok {
		fmt.Println("Not found")
		fmt.Println(val)

	}

	appkeyset := generateNewAppSet(r, jwker)
	appjson, err := json.MarshalIndent(appkeyset, "", " ")
	if err != nil {
		r.Log.Error(err, "unable to marshall object")
	}

	_ = ioutil.WriteFile("test.json", appjson, 0644)
	return ctrl.Result{}, nil
}

func generateNewAppSet(r *JwkerReconciler, jwker jwkerv1.Jwker) storage.JwkerAppSet {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		r.Log.Error(err, "Unable to generate private key")
	}

	keyId := utils.RandStringBytes(8)

	jwk := jose.JSONWebKey{
		Key: privateKey,
		// Certificates: nil,
		KeyID: string(keyId),
		Use:   "sig",
	}
	var publicjwks []jose.JSONWebKey

	publicjwks = append(publicjwks, jwk.Public())

	keyset := jose.JSONWebKeySet{Keys: publicjwks}
	var inbound []string
	var outbound []string
	for _, rule := range jwker.Spec.AccessPolicy.Inbound.Rules {
		cluster, namespace := parseAccessPolicy(rule, r, jwker)
		inbound = append(inbound, fmt.Sprintf("%s:%s:%s", cluster, namespace, rule.Application))
	}
	for _, rule := range jwker.Spec.AccessPolicy.Outbound.Rules {
		cluster, namespace := parseAccessPolicy(rule, r, jwker)
		outbound = append(outbound, fmt.Sprintf("%s:%s:%s", cluster, namespace, rule.Application))
	}
	appkeyset := storage.JwkerAppSet{
		Appid: fmt.Sprintf("%s:%s:%s", r.ClusterName, jwker.Namespace, jwker.Name),
		Jwks:  keyset,
		AccessPolicy: storage.AccessPolicy{
			Inbound:  inbound,
			Outbound: outbound,
		},
	}
	return appkeyset
}

func parseAccessPolicy(rule jwkerv1.AccessPolicyRule, r *JwkerReconciler, jwker jwkerv1.Jwker) (string, string) {
	var cluster string
	var namespace string
	if rule.Cluster != "" {
		cluster = rule.Cluster
	} else {
		cluster = r.ClusterName
	}
	if rule.Namespace != "" {
		namespace = rule.Namespace
	} else {
		namespace = jwker.ObjectMeta.Namespace
	}
	return cluster, namespace
}

func (r *JwkerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&jwkerv1.Jwker{}).
		Complete(r)
}
