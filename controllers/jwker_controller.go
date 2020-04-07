package controllers

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/go-logr/logr"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
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
	Log           logr.Logger
	Scheme        *runtime.Scheme
	ClusterName   string
	StoragePath   string
	PrivateJwks   *jose.JSONWebKeySet
	PrivateKey    *rsa.PrivateKey
	TokenDingsUrl string
}

// +kubebuilder:rbac:groups=jwker.nais.io,resources=jwkers,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=jwker.nais.io,resources=jwkers/status,verbs=get;update;patch

func (r *JwkerReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	var jwker jwkerv1.Jwker
	ctx := context.Background()
	_ = r.Log.WithValues("jwker", req.NamespacedName)
	if err := r.Get(ctx, req.NamespacedName, &jwker); err != nil {
		r.Log.Info(fmt.Sprintf("This is when we clean up app: %s in namespace: %s", req.Name, req.Namespace))
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	jwkerClientID := fmt.Sprintf("%s:%s:%s", r.ClusterName, "nais", "jwker")
	privateJwk := r.PrivateJwks.Keys[0]
	tokendingsToken, err := utils.GetTokenDingsToken(&privateJwk, jwkerClientID, r.TokenDingsUrl)
	if err != nil {
		r.Log.Error(err, "unable to fetch token from tokendings")
		return ctrl.Result{}, err
	}

	type ClientRegistration struct {
		ClientName        string `json:"client_name"`
		Jwks              string `json:"jwks"`
		SoftwareStatement string `json:"software_statement"`
	}

	type SoftwareStatement struct {
		AppId                string   `json:"appId"`
		AccessPolicyInbound  []string `json:"accessPolicyInbound"`
		AccessPolicyOutbound []string `json:"accessPolicyOutbound"`
	}
	key := jose.SigningKey{Algorithm: jose.RS256, Key: r.PrivateJwks.Keys[0].Key}
	var signerOpts = jose.SignerOptions{}
	signerOpts.WithType("JWT")
	signerOpts.WithHeader("kid", r.PrivateJwks.Keys[0].KeyID)

	rsaSigner, err := jose.NewSigner(key, &signerOpts)
	if err != nil {
		r.Log.Error(err, "unable to create signer")
	}
	builder := jwt.Signed(rsaSigner)

	claims := SoftwareStatement{
		AppId:                "xx",
		AccessPolicyInbound:  []string{"yy"},
		AccessPolicyOutbound: []string{"zz"},
	}
	builder = builder.Claims(claims)
	rawJWT, err := builder.CompactSerialize()
	if err != nil {
		r.Log.Error(err, "unable to build claims")
	}

	data, err := json.Marshal(ClientRegistration{
		ClientName:        "xx",
		Jwks:              "jwks in json-format",
		SoftwareStatement: rawJWT,
	})
	request, err := http.NewRequest("POST", fmt.Sprintf("%s/registration/client", r.TokenDingsUrl), bytes.NewReader(data))
	request.Header.Add("Content-Type", "application/json")
	request.Header.Add("Authorization", fmt.Sprintf("Bearer %s", tokendingsToken.AccessToken))

	client := http.Client{}
	resp, err := client.Do(request)
	if err != nil {
		r.Log.Error(err, "Unable to fetch token from tokendings")
	}
	defer resp.Body.Close()
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
	}
	bodyString := string(bodyBytes)
	fmt.Println(bodyString)

	fmt.Printf("Returned token: %#v\n", resp.Body)

	appId := fmt.Sprintf("%s:%s:%s", r.ClusterName, jwker.Namespace, jwker.Name)
	jwkerStorage, _ := storage.New()
	appSets, err := jwkerStorage.ReadJwkerStorage(r.StoragePath)

	if err != nil {
		r.Log.Error(err, "Could not read storage")
	}
	if _, ok := appSets[appId]; !ok {
		// fmt.Println(val)

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
