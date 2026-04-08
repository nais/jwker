package controllers_test

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	naisiov1 "github.com/nais/liberator/pkg/apis/nais.io/v1"
	"github.com/nais/liberator/pkg/crd"
	"github.com/nais/liberator/pkg/events"
	"github.com/nais/liberator/pkg/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	_ "k8s.io/client-go/plugin/pkg/client/auth" // for side effects only
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	ctrlmetricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/nais/jwker/controllers"
	"github.com/nais/jwker/pkg/config"
	"github.com/nais/jwker/pkg/jwk"
	"github.com/nais/jwker/pkg/secret"
	"github.com/nais/jwker/pkg/tokendings"
	// +kubebuilder:scaffold:imports
)

var (
	cli     client.Client
	testEnv *envtest.Environment
	ctx     context.Context
	cancel  context.CancelFunc
)

const (
	appName            = "app1"
	secretName         = "app1-secret-foobar"
	alreadyInUseSecret = "already-in-use"
	expiredSecret      = "expired-secret"
	namespace          = "default"
)

type tokendingsHandler struct{}

func (h *tokendingsHandler) serveRegistration(w http.ResponseWriter, r *http.Request) {
	statement := &tokendings.ClientRegistration{}
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(statement)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func (h *tokendingsHandler) serveDelete(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}

func (h *tokendingsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		h.serveRegistration(w, r)
	} else if r.Method == http.MethodDelete {
		h.serveDelete(w, r)
	}
}

func fixtures(cli client.Client, tokendingsURL string) error {
	var err error

	ctx := context.Background()

	err = cli.Create(
		ctx,
		&naisiov1.Jwker{
			TypeMeta: metav1.TypeMeta{
				Kind:       "Jwker",
				APIVersion: "nais.io/v1",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      appName,
				Namespace: namespace,
			},
			Spec: naisiov1.JwkerSpec{
				SecretName:   secretName,
				AccessPolicy: &naisiov1.AccessPolicy{},
			},
		},
	)
	if err != nil {
		return err
	}

	err = cli.Create(
		ctx,
		&corev1.Pod{
			TypeMeta: metav1.TypeMeta{
				Kind:       "Pod",
				APIVersion: "v1",
			},
			ObjectMeta: metav1.ObjectMeta{
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
						Name: "secret-previous-in-use",
						VolumeSource: corev1.VolumeSource{
							Secret: &corev1.SecretVolumeSource{
								SecretName: alreadyInUseSecret,
							},
						},
					},
					{
						Name: "secret-to-create",
						VolumeSource: corev1.VolumeSource{
							Secret: &corev1.SecretVolumeSource{
								SecretName: secretName,
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

	key, err := jwk.Generate()
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
			TypeMeta: metav1.TypeMeta{
				Kind:       "Secret",
				APIVersion: "v1",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      alreadyInUseSecret,
				Namespace: namespace,
				Labels: map[string]string{
					"app":                       appName,
					secret.TokenXSecretLabelKey: secret.TokenXSecretLabelType,
				},
				Annotations: map[string]string{
					secret.StakaterReloaderAnnotationKey: "true",
				},
			},
			Data: map[string][]byte{
				secret.TokenXPrivateJWKKey:    keyBytes,
				secret.TokenXClientIDKey:      []byte("local:default:app1"),
				secret.TokenXWellKnownURLKey:  fmt.Appendf(nil, "%s/.well-known/oauth-authorization-server", tokendingsURL),
				secret.TokenXIssuerKey:        []byte(tokendingsURL),
				secret.TokenXJwksURIKey:       fmt.Appendf(nil, "%s/jwks", tokendingsURL),
				secret.TokenXTokenEndpointKey: fmt.Appendf(nil, "%s/token", tokendingsURL),
			},
		},
	)
	if err != nil {
		return err
	}

	err = cli.Create(
		ctx,
		&corev1.Secret{
			TypeMeta: metav1.TypeMeta{
				Kind:       "Secret",
				APIVersion: "v1",
			},
			ObjectMeta: metav1.ObjectMeta{
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
	ctrl.SetLogger(zap.New())

	testEnv = &envtest.Environment{
		CRDDirectoryPaths: []string{crd.YamlDirectory()},
	}
	// Retrieve the first found binary directory to allow running tests from IDEs
	if getFirstFoundEnvTestBinaryDir() != "" {
		testEnv.BinaryAssetsDirectory = getFirstFoundEnvTestBinaryDir()
	}

	k8scfg, err := testEnv.Start()
	require.NoError(t, err)
	require.NotNil(t, k8scfg)

	err = naisiov1.AddToScheme(scheme.Scheme)
	require.NoError(t, err)

	// +kubebuilder:scaffold:scheme

	mgr, err := ctrl.NewManager(testEnv.Config, ctrl.Options{
		Scheme: scheme.Scheme,
		Metrics: ctrlmetricsserver.Options{
			BindAddress: "0",
		},
	})
	require.NoError(t, err)

	cli = mgr.GetClient()
	require.NoError(t, err)

	tokendings := httptest.NewServer(&tokendingsHandler{})
	cfg, err := makeConfig(tokendings.URL)
	if err != nil {
		log.Fatalf("unable to create tokendings instances: %+v", err)
	}

	err = (&controllers.JwkerReconciler{
		Client:   cli,
		Recorder: mgr.GetEventRecorder("jwker"),
		Scheme:   mgr.GetScheme(),
		Config:   cfg,
	}).SetupWithManager(mgr)
	require.NoError(t, err)

	// insert data into the cluster
	err = fixtures(cli, tokendings.URL)
	if err != nil {
		t.Error(err)
		t.Fail()
		return
	}

	ctx, cancel = context.WithCancel(context.Background())

	go func() {
		err = mgr.Start(ctx)
		if err != nil {
			panic(err)
		}
	}()

	// wait for synced secret until timeout
	currentSecret, err := getSecretWithTimeout(ctx, cli, namespace, secretName)
	require.NoError(t, err)
	require.NotNil(t, currentSecret)
	ensureSecretIsValid(t, currentSecret, tokendings.URL)

	// existing, in-use secret should be preserved
	previousSecret, err := getSecret(ctx, cli, namespace, alreadyInUseSecret)
	require.NoError(t, err)
	require.NotNil(t, previousSecret)
	ensureSecretIsValid(t, previousSecret, tokendings.URL)

	// expired secret should be deleted
	_, err = getSecret(ctx, cli, namespace, expiredSecret)
	assert.True(t, errors.IsNotFound(err), "expired secret should be deleted")

	// retrieve the jwker resource and check that hash and status is set
	jwker := &naisiov1.Jwker{}
	key := client.ObjectKey{
		Namespace: namespace,
		Name:      appName,
	}
	err = cli.Get(ctx, key, jwker)
	require.NoError(t, err)

	assert.True(t, containsOwnerRef(currentSecret.GetOwnerReferences(), jwker), "secret should contain ownerReference")

	assert.Equal(t, jwker.GetGeneration(), jwker.Status.ObservedGeneration)
	assert.Equal(t, events.RolloutComplete, jwker.Status.SynchronizationState)
	assert.Equal(t, []string{
		"jwker.nais.io/finalizer",
	}, jwker.GetFinalizers())

	// update secret name in jwker spec and verify that a new secret is created
	err = cli.Get(ctx, key, jwker)
	require.NoError(t, err)
	jwker.Spec.SecretName = "new-secret-name"
	err = cli.Update(ctx, jwker)
	require.NoError(t, err)

	newSecret, err := getSecretWithTimeout(ctx, cli, namespace, "new-secret-name")
	require.NoError(t, err)
	require.NotNil(t, newSecret)
	ensureSecretIsValid(t, newSecret, tokendings.URL)

	// verify that the previous secret still exists
	previousSecret, err = getSecret(ctx, cli, namespace, secretName)
	require.NoError(t, err)
	require.NotNil(t, previousSecret)
	ensureSecretIsValid(t, previousSecret, tokendings.URL)

	// remove the jwker resource; usually done when naiserator syncs
	err = cli.Delete(ctx, jwker)
	require.NoError(t, err)
	require.NoError(t, waitForDeletedJwker(ctx, cli, namespace, jwker.Name))

	cancel()
	err = testEnv.Stop()
	require.NoError(t, err)
}

func ensureSecretIsValid(t *testing.T, sec *corev1.Secret, tokendingsURL string) {
	assert.Equal(t, map[string]string{
		secret.StakaterReloaderAnnotationKey: "true",
	}, sec.GetAnnotations())
	assert.Equal(t, map[string]string{
		"app":                       appName,
		secret.TokenXSecretLabelKey: secret.TokenXSecretLabelType,
	}, sec.GetLabels())
	assert.NotEmpty(t, sec.Data[secret.TokenXPrivateJWKKey])
	assert.Equal(t, "local:default:app1", string(sec.Data[secret.TokenXClientIDKey]))
	assert.Equal(t, fmt.Sprintf("%s/.well-known/oauth-authorization-server", tokendingsURL), string(sec.Data[secret.TokenXWellKnownURLKey]))
	assert.Equal(t, tokendingsURL, string(sec.Data[secret.TokenXIssuerKey]))
	assert.Equal(t, fmt.Sprintf("%s/jwks", tokendingsURL), string(sec.Data[secret.TokenXJwksURIKey]))
	assert.Equal(t, fmt.Sprintf("%s/token", tokendingsURL), string(sec.Data[secret.TokenXTokenEndpointKey]))
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

func waitForDeletedJwker(ctx context.Context, cli client.Client, namespace, name string) error {
	key := client.ObjectKey{
		Namespace: namespace,
		Name:      name,
	}
	jwker := &naisiov1.Jwker{}
	timeout := time.NewTimer(5 * time.Second)
	ticker := time.NewTicker(250 * time.Millisecond)

	for {
		select {
		case <-timeout.C:
			return fmt.Errorf("jwker still exists")
		case <-ticker.C:
			err := cli.Get(ctx, key, jwker)
			if errors.IsNotFound(err) {
				return nil
			} else if err != nil {
				return err
			}
		}
	}
}

func makeConfig(tokendingsURL string) (*config.Config, error) {
	jwk, err := jwk.Generate()
	if err != nil {
		return nil, err
	}

	return &config.Config{
		ClientID:    "jwker",
		ClientJwk:   &jwk,
		ClusterName: "local",
		TokendingsInstances: []tokendings.Instance{
			tokendings.NewInstance(tokendingsURL, "jwker", &jwk, &oauth.MetadataOAuth{
				Issuer:        tokendingsURL,
				JwksURI:       tokendingsURL + "/jwks",
				TokenEndpoint: tokendingsURL + "/token",
			}),
		},
	}, nil
}

func containsOwnerRef(refs []metav1.OwnerReference, owner *naisiov1.Jwker) bool {
	expected := metav1.OwnerReference{
		APIVersion: owner.APIVersion,
		Kind:       owner.Kind,
		Name:       owner.Name,
		UID:        owner.UID,
	}
	for _, ref := range refs {
		sameApiVersion := ref.APIVersion == expected.APIVersion
		sameKind := ref.Kind == expected.Kind
		sameName := ref.Name == expected.Name
		sameUID := ref.UID == expected.UID
		isBlockOwnerDeletion := ref.BlockOwnerDeletion != nil && *ref.BlockOwnerDeletion == true
		isController := ref.Controller != nil && *ref.Controller == true
		if sameApiVersion && sameKind && sameName && sameUID && isBlockOwnerDeletion && isController {
			return true
		}
	}
	return false
}

// getFirstFoundEnvTestBinaryDir locates the first binary in the specified path.
// ENVTEST-based tests depend on specific binaries, usually located in paths set by
// controller-runtime. When running tests directly (e.g., via an IDE) without using
// Makefile targets, the 'BinaryAssetsDirectory' must be explicitly configured.
//
// This function streamlines the process by finding the required binaries, similar to
// setting the 'KUBEBUILDER_ASSETS' environment variable. To ensure the binaries are
// properly set up, run 'make setup-envtest' beforehand.
func getFirstFoundEnvTestBinaryDir() string {
	basePath := filepath.Join("..", "bin", "k8s")
	entries, err := os.ReadDir(basePath)
	if err != nil {
		slog.Error("failed to read envtest binary directory; have you run 'make setup-envtest'?", "path", basePath, "error", err)
		return ""
	}
	for _, entry := range entries {
		if entry.IsDir() {
			return filepath.Join(basePath, entry.Name())
		}
	}
	return ""
}
