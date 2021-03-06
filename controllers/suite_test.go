package controllers_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/nais/jwker/controllers"
	"github.com/nais/jwker/pkg/secret"
	"github.com/nais/jwker/pkg/tokendings"
	"github.com/nais/jwker/utils"
	"github.com/nais/liberator/pkg/apis/nais.io/v1"
	"github.com/nais/liberator/pkg/crd"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1"
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

const appName = "app1"
const secretName = "app1-secret-foobar"
const alreadyInUseSecret = "already-in-use"
const expiredSecret = "expired-secret"
const namespace = "default"

type handler struct{}

func (h *handler) serveRegistration(w http.ResponseWriter, r *http.Request) {
	statement := &tokendings.ClientRegistration{}
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(statement)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func (h *handler) serveDelete(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		h.serveRegistration(w, r)
	} else if r.Method == http.MethodDelete {
		h.serveDelete(w, r)
	}
}

func fixtures(cli client.Client) error {
	var err error

	ctx := context.Background()

	err = cli.Create(
		ctx,
		&nais_io_v1.Jwker{
			TypeMeta: v1.TypeMeta{
				Kind:       "Jwker",
				APIVersion: "nais.io/v1",
			},
			ObjectMeta: v1.ObjectMeta{
				Name:      appName,
				Namespace: namespace,
			},
			Spec: nais_io_v1.JwkerSpec{
				SecretName: secretName,
				AccessPolicy: &nais_io_v1.AccessPolicy{},
			},
		},
	)
	if err != nil {
		return err
	}

	err = cli.Create(
		ctx,
		&corev1.Pod{
			TypeMeta: v1.TypeMeta{
				Kind:       "Pod",
				APIVersion: "v1",
			},
			ObjectMeta: v1.ObjectMeta{
				Name:      appName,
				Namespace: namespace,
				Labels: map[string]string{
					"app": appName,
				},
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
								SecretName: alreadyInUseSecret,
							},
						},
					},
				},
			},
		},
	)
	if err != nil {
		return err
	}

	key, err := utils.GenerateJWK()
	if err != nil {
		return err
	}

	keyBytes, err := key.MarshalJSON()
	if err != nil {
		return err
	}

	err = cli.Create(
		ctx,
		&corev1.Secret{
			TypeMeta: v1.TypeMeta{
				Kind:       "Secret",
				APIVersion: "v1",
			},
			ObjectMeta: v1.ObjectMeta{
				Name:      alreadyInUseSecret,
				Namespace: namespace,
				Labels: map[string]string{
					"app":                       appName,
					secret.TokenXSecretLabelKey: secret.TokenXSecretLabelType,
				},
			},
			StringData: map[string]string{
				secret.TokenXPrivateJwkKey: string(keyBytes),
			},
		},
	)
	if err != nil {
		return err
	}

	err = cli.Create(
		ctx,
		&corev1.Secret{
			TypeMeta: v1.TypeMeta{
				Kind:       "Secret",
				APIVersion: "v1",
			},
			ObjectMeta: v1.ObjectMeta{
				Name:      expiredSecret,
				Namespace: namespace,
				Labels: map[string]string{
					"app":                       appName,
					secret.TokenXSecretLabelKey: secret.TokenXSecretLabelType,
				},
			},
		},
	)

	return err
}

func TestReconciler(t *testing.T) {
	ctx := context.Background()

	crdPath := crd.YamlDirectory()

	testEnv = &envtest.Environment{
		CRDDirectoryPaths: []string{crdPath},
	}

	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	assert.NoError(t, err)
	assert.NotNil(t, listener)
	h := &handler{}
	go http.Serve(listener, h)

	cfg, err = testEnv.Start()
	assert.NoError(t, err)
	assert.NotNil(t, cfg)

	err = nais_io_v1.AddToScheme(scheme.Scheme)
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

	// insert data into the cluster
	err = fixtures(cli)
	if err != nil {
		t.Error(err)
		t.Fail()
		return
	}

	go func() {
		err = mgr.Start(ctrl.SetupSignalHandler())
		if err != nil {
			panic(err)
		}
	}()

	// wait for synced secret until timeout
	sec, err := getSecretWithTimeout(ctx, cli, namespace, secretName)
	assert.NoError(t, err)
	assert.NotNil(t, sec)

	// secret must have data
	assert.NotEmpty(t, sec.Data[secret.TokenXPrivateJwkKey])

	// existing, in-use secret should be preserved
	sec, err = getSecret(ctx, cli, namespace, alreadyInUseSecret)
	assert.NoError(t, err)
	assert.NotNil(t, sec)

	// expired secret should be deleted
	sec, err = getSecret(ctx, cli, namespace, expiredSecret)
	assert.True(t, errors.IsNotFound(err), "expired secret should be deleted")

	// retrieve the jwker resource and check that hash and status is set
	jwk := &nais_io_v1.Jwker{
		TypeMeta: v1.TypeMeta{
			Kind:       "Jwker",
			APIVersion: "v1",
		},
		ObjectMeta: v1.ObjectMeta{
			Name:      appName,
			Namespace: namespace,
		},
	}
	key := client.ObjectKey{
		Namespace: namespace,
		Name:      appName,
	}
	err = cli.Get(ctx, key, jwk)
	assert.NoError(t, err)

	hash, err := jwk.Spec.Hash()
	assert.NoError(t, err)
	assert.Equal(t, hash, jwk.Status.SynchronizationHash)
	assert.Equal(t, nais_io_v1.EventRolloutComplete, jwk.Status.SynchronizationState)

	// remove the jwker resource; usually done when naiserator syncs
	err = cli.Delete(ctx, jwk)
	assert.NoError(t, err)

	// test that deleting the jwker resource purges associated secrets
	assert.NoError(t, waitForDeletedSecret(ctx, cli, namespace, secretName))
	assert.NoError(t, waitForDeletedSecret(ctx, cli, namespace, alreadyInUseSecret))

	err = testEnv.Stop()
	assert.NoError(t, err)
}

func getSecret(ctx context.Context, cli client.Client, namespace, name string) (*corev1.Secret, error) {
	key := client.ObjectKey{
		Namespace: namespace,
		Name:      name,
	}
	sec := &corev1.Secret{}
	err := cli.Get(ctx, key, sec)
	return sec, err
}

func getSecretWithTimeout(ctx context.Context, cli client.Client, namespace, name string) (*corev1.Secret, error) {
	key := client.ObjectKey{
		Namespace: namespace,
		Name:      name,
	}
	sec := &corev1.Secret{}
	timeout := time.NewTimer(5 * time.Second)
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

func waitForDeletedSecret(ctx context.Context, cli client.Client, namespace, name string) error {
	key := client.ObjectKey{
		Namespace: namespace,
		Name:      name,
	}
	sec := &corev1.Secret{}
	timeout := time.NewTimer(5 * time.Second)
	ticker := time.NewTicker(250 * time.Millisecond)

	for {
		select {
		case <-timeout.C:
			return fmt.Errorf("secret still exists")
		case <-ticker.C:
			err := cli.Get(ctx, key, sec)
			if errors.IsNotFound(err) {
				return nil
			} else if err != nil {
				return err
			}
		}
	}
}
