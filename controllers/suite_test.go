package controllers_test

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	jwkerv1 "github.com/nais/jwker/api/v1"
	"github.com/nais/jwker/controllers"
	"github.com/nais/jwker/pkg/secret"
	"github.com/nais/jwker/pkg/tokendings"
	"github.com/nais/jwker/utils"
	"github.com/stretchr/testify/assert"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	_ "k8s.io/client-go/plugin/pkg/client/auth" // for side effects only
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	// +kubebuilder:scaffold:imports
)

var cfg *rest.Config
var cli client.Client
var testEnv *envtest.Environment

const secretName = "app1-secret-foobar"
const namespace = "default"

type handler struct{}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusCreated)
}

func fixtures(t *testing.T, cli client.Client) {
	ctx := context.Background()

	assert.NoError(t, cli.Create(
		ctx,
		&jwkerv1.Jwker{
			TypeMeta: v1.TypeMeta{
				Kind:       "Jwker",
				APIVersion: "v1",
			},
			ObjectMeta: v1.ObjectMeta{
				Name:      "app1",
				Namespace: namespace,
			},
			Spec: jwkerv1.JwkerSpec{
				SecretName: secretName,
				AccessPolicy: &jwkerv1.AccessPolicy{
					Inbound: &jwkerv1.AccessPolicyInbound{},
				},
			},
		},
	))

	assert.NoError(t, cli.Create(
		ctx,
		&appsv1.Deployment{
			TypeMeta: v1.TypeMeta{
				Kind:       "Jwker",
				APIVersion: "v1",
			},
			ObjectMeta: v1.ObjectMeta{
				Name:      "app1",
				Namespace: namespace,
			},
			Spec: appsv1.DeploymentSpec{
				Selector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"app": "app1"},
				},
				Template: corev1.PodTemplateSpec{
					ObjectMeta: v1.ObjectMeta{
						Labels: map[string]string{"app": "app1"},
					},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{
							{
								Name:  "main",
								Image: "foo",
							},
						},
						Volumes: []corev1.Volume{
							{
								Name: "foo",
								VolumeSource: corev1.VolumeSource{
									Secret: &corev1.SecretVolumeSource{
										SecretName: secretName,
									},
								},
							},
						},
					},
				},
			},
		},
	))
}

func TestReconciler(t *testing.T) {
	ctx := context.Background()

	testEnv = &envtest.Environment{
		CRDDirectoryPaths: []string{filepath.Join("..", "config", "crd", "bases")},
	}

	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	assert.NoError(t, err)
	assert.NotNil(t, listener)
	h := &handler{}
	go http.Serve(listener, h)

	cfg, err = testEnv.Start()
	assert.NoError(t, err)
	assert.NotNil(t, cfg)

	// scheme   = runtime.NewScheme()
	err = jwkerv1.AddToScheme(scheme.Scheme)
	assert.NoError(t, err)

	// +kubebuilder:scaffold:scheme

	cli, err = client.New(cfg, client.Options{Scheme: scheme.Scheme})
	assert.NoError(t, err)
	assert.NotNil(t, cli)

	mgr, err := ctrl.NewManager(testEnv.Config, ctrl.Options{
		Scheme:             scheme.Scheme,
		MetricsBindAddress: "0",
	})
	assert.NoError(t, err)

	signkey, err := utils.GenerateJWK()
	assert.NoError(t, err)

	jwker := &controllers.JwkerReconciler{
		AzureCredentials: signkey,
		Client:           cli,
		ClusterName:      "local",
		Log:              ctrl.Log.WithName("controllers").WithName("Jwker"),
		Scheme:           mgr.GetScheme(),
		TokenDingsUrl:    "http://" + listener.Addr().String(),
		TokendingsToken:  &tokendings.TokenResponse{},
	}

	err = jwker.SetupWithManager(mgr)
	assert.NoError(t, err)

	go func() {
		err = mgr.Start(ctrl.SetupSignalHandler())
		if err != nil {
			panic(err)
		}
	}()

	// insert data into the cluster
	fixtures(t, cli)

	// wait for synced secret until timeout
	sec, err := getSecretWithTimeout(ctx, cli, namespace, secretName)
	assert.NoError(t, err)
	assert.NotNil(t, sec)

	// secret must have data
	assert.NotEmpty(t, sec.Data[secret.JwksSecretKey])

	err = testEnv.Stop()
	assert.NoError(t, err)
}

func getSecretWithTimeout(ctx context.Context, cli client.Client, namespace, name string) (*corev1.Secret, error) {
	key := client.ObjectKey{
		Namespace: namespace,
		Name:      name,
	}
	sec := &corev1.Secret{}
	timeout := time.NewTimer(3 * time.Second)
	ticker := time.NewTicker(250 * time.Millisecond)

	for {
		select {
		case <-timeout.C:
			return nil, fmt.Errorf("timeout while waiting for secret synchronization")
		case <-ticker.C:
			err := cli.Get(ctx, key, sec)
			if err == nil {
				return sec, nil
			}
			if !errors.IsNotFound(err) {
				return nil, err
			}
		}
	}
}
