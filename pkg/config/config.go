package config

import (
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"path"

	"github.com/nais/liberator/pkg/oauth"
	"gopkg.in/square/go-jose.v2"
)

type Config struct {
	AuthProvider AuthProvider
	ClusterName  string
	MetricsAddr  string
	Tokendings   Tokendings
}

type Tokendings struct {
	BaseURL      string
	ClientID     string
	Metadata     *oauth.MetadataOAuth
	WellKnownURL string
}

type AuthProvider struct {
	ClientID      string
	ClientJwkFile string
	ClientJwk     *jose.JSONWebKey
	Metadata      *oauth.MetadataOpenID
	WellKnownURL  string
}

func New(ctx context.Context) (*Config, error) {
	cfg := &Config{}

	flag.StringVar(&cfg.AuthProvider.ClientJwkFile, "client-jwk-file", "/var/run/secrets/azure/jwk.json", "file with JWK credential for client at Auth Provider.")
	flag.StringVar(&cfg.AuthProvider.ClientID, "client-id", os.Getenv("JWKER_CLIENT_ID"), "Client ID of Jwker at Auth Provider.")
	flag.StringVar(&cfg.AuthProvider.WellKnownURL, "auth-provider-well-known-url", os.Getenv("AUTH_PROVIDER_WELL_KNOWN_URL"), "Well-known URL to Auth Provider.")
	flag.StringVar(&cfg.ClusterName, "cluster-name", os.Getenv("CLUSTER_NAME"), "nais cluster")
	flag.StringVar(&cfg.MetricsAddr, "metrics-addr", ":8181", "The address the metric endpoint binds to.")
	flag.StringVar(&cfg.Tokendings.BaseURL, "tokendings-base-url", os.Getenv("TOKENDINGS_URL"), "Base URL to Tokendings.")
	flag.StringVar(&cfg.Tokendings.ClientID, "tokendings-client-id", os.Getenv("TOKENDINGS_CLIENT_ID"), "Client ID of Tokendings at Auth Provider")
	flag.Parse()

	tokendingsWellKnownURL, err := url.Parse(cfg.Tokendings.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid base url for tokendings: %w", err)
	}
	tokendingsWellKnownURL.Path = path.Join(tokendingsWellKnownURL.Path, oauth.WellKnownOAuthPath)
	cfg.Tokendings.WellKnownURL = tokendingsWellKnownURL.String()

	tokendingsMetadata, err := oauth.Metadata(cfg.Tokendings.WellKnownURL).OAuth(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetching metadata from tokendings: %w", err)
	}
	cfg.Tokendings.Metadata = tokendingsMetadata

	authProviderMetadata, err := oauth.Metadata(cfg.AuthProvider.WellKnownURL).OpenID(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetching metadata from auth provider: %w", err)
	}
	cfg.AuthProvider.Metadata = authProviderMetadata

	clientJwk, err := loadCredentials(cfg.AuthProvider.ClientJwkFile)
	if err != nil {
		return nil, fmt.Errorf("loading client jwk for auth provider: %w", err)
	}
	cfg.AuthProvider.ClientJwk = clientJwk

	return cfg, nil
}

func loadCredentials(path string) (*jose.JSONWebKey, error) {
	creds, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	jwk := &jose.JSONWebKey{}
	err = jwk.UnmarshalJSON(creds)
	if err != nil {
		return nil, err
	}

	return jwk, nil
}
