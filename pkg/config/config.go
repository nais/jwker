package config

import (
	"flag"
	"fmt"
	"net/url"
	"os"
	"path"

	"github.com/nais/liberator/pkg/oauth"
	"gopkg.in/square/go-jose.v2"
)

type Config struct {
	AuthProvider           AuthProvider
	ClusterName            string
	MetricsAddr            string
	Tokendings             Tokendings
	Namespace              string
	SharedPublicSecretName string
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

func New() (*Config, error) {
	cfg := &Config{}

	flag.StringVar(&cfg.AuthProvider.ClientJwkFile, "client-jwk-file", "/var/run/secrets/azure/jwk.json", "file with JWK credential for client at Auth Provider.")
	flag.StringVar(&cfg.AuthProvider.ClientID, "client-id", os.Getenv("JWKER_CLIENT_ID"), "Client ID of Jwker at Auth Provider.")
	flag.StringVar(&cfg.AuthProvider.WellKnownURL, "auth-provider-well-known-url", os.Getenv("AUTH_PROVIDER_WELL_KNOWN_URL"), "Well-known URL to Auth Provider.")
	flag.StringVar(&cfg.Namespace, "namespace", os.Getenv("NAMESPACE"), "namespace")
	flag.StringVar(&cfg.SharedPublicSecretName, "shared-public-secret-name", os.Getenv("SHARED_PUBLIC_SECRET_NAME"), "shared public secret name")
	flag.StringVar(&cfg.ClusterName, "cluster-name", os.Getenv("CLUSTER_NAME"), "nais cluster")
	flag.StringVar(&cfg.MetricsAddr, "metrics-addr", ":8181", "The address the metric endpoint binds to.")
	flag.StringVar(&cfg.Tokendings.BaseURL, "tokendings-base-url", os.Getenv("TOKENDINGS_URL"), "Base URL to Tokendings.")
	flag.StringVar(&cfg.Tokendings.ClientID, "tokendings-client-id", os.Getenv("TOKENDINGS_CLIENT_ID"), "Client ID of Tokendings at Auth Provider")
	flag.StringVar(&cfg.Tokendings.Metadata.Issuer, "tokendings-metadata-issuer", os.Getenv("TOKENDINGS_METADATA_ISSUER"), "Tokendings metadata issuer")
	flag.StringVar(&cfg.Tokendings.Metadata.JwksURI, "tokendings-metadata-JwksURI", os.Getenv("TOKENDINGS_METADATA_JWKSURI"), "Tokendings metadata JWKS URI")
	flag.StringVar(&cfg.Tokendings.Metadata.TokenEndpoint, "tokendings-metadata-tokenendpoint", os.Getenv("TOKENDINGS_METADATA_TOKENENDPOINT"), "Tokendings metadata token endpoint")
	flag.Parse()

	tokendingsWellKnownURL, err := url.Parse(cfg.Tokendings.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid base url for tokendings: %w", err)
	}
	tokendingsWellKnownURL.Path = path.Join(tokendingsWellKnownURL.Path, oauth.WellKnownOAuthPath)
	cfg.Tokendings.WellKnownURL = tokendingsWellKnownURL.String()

	return cfg, nil
}
