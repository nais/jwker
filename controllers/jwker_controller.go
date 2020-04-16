package controllers

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	"gopkg.in/square/go-jose.v2"
	corev1 "k8s.io/api/core/v1"
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
	Log              logr.Logger
	Scheme           *runtime.Scheme
	ClusterName      string
	StoragePath      string
	JwkerPrivateJwks *jose.JSONWebKeySet
	TokenDingsUrl    string
	logger           logr.Logger
	JwkerStorage     storage.JwkerStorage
}

// +kubebuilder:rbac:groups=jwker.nais.io,resources=jwkers,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=jwker.nais.io,resources=jwkers/status,verbs=get;update;patch

func (r *JwkerReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	var j jwkerv1.Jwker
	ctx := context.Background()
	r.logger = r.Log.WithValues("jwker", req.NamespacedName)

	jwkerClientID := utils.AppId{Name: "jwker", Namespace: "nais", Cluster: r.ClusterName}
	jwkerPrivateJwk := r.JwkerPrivateJwks.Keys[0]

	tokendingsToken, err := utils.GetTokenDingsToken(&jwkerPrivateJwk, jwkerClientID, r.TokenDingsUrl)
	if err != nil {
		r.logger.Error(err, "unable to fetch token from tokendings")
		return ctrl.Result{}, err
	}

	if err := r.Get(ctx, req.NamespacedName, &j); err != nil {
		r.logger.Info(fmt.Sprintf("This is when we clean up app: %s in namespace: %s", req.Name, req.Namespace))
		tmpAppClientId := utils.AppId{
			Name:      req.Name,
			Namespace: req.Namespace,
			Cluster:   r.ClusterName,
		}

		if err := utils.DeleteClient(tokendingsToken.AccessToken, r.TokenDingsUrl, tmpAppClientId); err != nil {
			return ctrl.Result{}, err
		}
		secretList, err := r.fetchClusterSecrets(req.Name, req.Namespace)
		if err != nil {
			return ctrl.Result{}, err
		}

		if err := r.deleteClusterSecrets(secretList, "", ctx); err != nil {
			return ctrl.Result{}, err
		}

		if err := r.JwkerStorage.Delete(tmpAppClientId.ToFileName()); err != nil {
			return ctrl.Result{}, err
		}

		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	appClientId := utils.AppId{Name: j.Name, Namespace: j.Namespace, Cluster: r.ClusterName}

	clientJwk, err := utils.JwkKeyGenerator()
	if err != nil {
		r.logger.Error(err, "Unable to generate client JWK")
		return ctrl.Result{}, err
	}

	clientPrivateJwks, clientPublicJwks, err := utils.JwksGenerator(clientJwk)
	if err != nil {
		r.logger.Error(err, "Unable to generate client JWKS")
		return ctrl.Result{}, err
	}

	if err := r.reconcileSecrets(req, ctx, j.Spec.SecretName, clientPrivateJwks); err != nil {
		r.logger.Error(err, "Reconciling secrets failed...")
		return ctrl.Result{}, err
	}

	r.logger.Info(fmt.Sprintf("Registering app %s:%s:%s with token-dingz", appClientId.Cluster, appClientId.Namespace, appClientId.Name))
	clientRegistrationResponse, err := utils.RegisterClient(&jwkerPrivateJwk, &clientPublicJwks, tokendingsToken.AccessToken, r.TokenDingsUrl, appClientId, &j)
	if err != nil {
		r.logger.Error(err, "Unable to register client")
	}

	if err := r.JwkerStorage.Write(appClientId.ToFileName(), clientRegistrationResponse); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

func (r *JwkerReconciler) reconcileSecrets(req ctrl.Request, ctx context.Context, secretName string, clientPrivateJwks jose.JSONWebKeySet) error {
	clusterSecrets, err := r.fetchClusterSecrets(req.Name, req.Namespace)
	if err != nil {
		return fmt.Errorf("Unable to fetch clusterSecrets from cluster: %s", err.Error())
	}

	if err := r.deleteClusterSecrets(clusterSecrets, secretName, ctx); err != nil {
		return fmt.Errorf("Unable to delete clusterSecrets from cluster: %s", err.Error())
	}

	secretSpec, err := utils.CreateSecretSpec(req.Name, secretName, req.Namespace, clientPrivateJwks)
	if err != nil {
		return fmt.Errorf("Unable to create secretSpec object: %s", err.Error())
	}

	if err := r.Client.Get(ctx, client.ObjectKey{Namespace: req.Namespace, Name: secretName}, secretSpec.DeepCopyObject()); err != nil {
		if err.Error() != fmt.Sprintf("Secret \"%s\" not found", secretName) {
			return fmt.Errorf("Unable to create secret: %s", err.Error())
		}
		r.logger.Info(fmt.Sprintf("Creating clusterSecret %s in %s", secretSpec.Name, secretSpec.Namespace))
		if err := r.Client.Create(ctx, secretSpec.DeepCopyObject()); err != nil {
			return fmt.Errorf("Unable to apply secretSpec: %s", err.Error())
		}
	}

	return nil
}

// TODO: Make exclusion optional
func (r *JwkerReconciler) deleteClusterSecrets(clusterSecrets corev1.SecretList, secretName string, ctx context.Context) error {
	for _, clusterSecret := range clusterSecrets.Items {
		if clusterSecret.Name != secretName {
			r.logger.Info(fmt.Sprintf("Deleting clusterSecret %s in %s", clusterSecret.Name, clusterSecret.Namespace))
			if err := r.Client.Delete(ctx, clusterSecret.DeepCopyObject()); err != nil {
				return fmt.Errorf("Unable to delete clusterSecret: %s", err.Error())
			}
		}
	}
	return nil
}

func (r *JwkerReconciler) fetchClusterSecrets(app, namespace string) (corev1.SecretList, error) {
	var secrets corev1.SecretList
	var mLabels = client.MatchingLabels{}

	mLabels["app"] = app
	mLabels["type"] = "jwker.nais.io"
	if err := r.Client.List(context.Background(), &secrets, client.InNamespace(namespace), mLabels); err != nil {
		return secrets, err
	}
	return secrets, nil
}

func (r *JwkerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&jwkerv1.Jwker{}).
		Complete(r)
}
