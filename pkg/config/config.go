package config

import (
	"flag"
	"fmt"
	"net/url"
	"os"
	"path"

	"github.com/nais/jwker/jwkutils"
	"github.com/nais/liberator/pkg/oauth"
	"gopkg.in/square/go-jose.v2"
)

type Config struct {
	AuthProvider AuthProvider
	ClusterName  string
	LogLevel     string
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

func New() (*Config, error) {
	cfg := &Config{}
	cfg.Tokendings.Metadata = &oauth.MetadataOAuth{}
	var clientJwkJson string
	flag.StringVar(&clientJwkJson, "client-jwk-json", os.Getenv("JWKER_PRIVATE_JWK"), "json with private JWK credential")
	flag.StringVar(&cfg.AuthProvider.ClientID, "client-id", os.Getenv("JWKER_CLIENT_ID"), "Client ID of Jwker at Auth Provider.")
	flag.StringVar(&cfg.AuthProvider.WellKnownURL, "auth-provider-well-known-url", os.Getenv("AUTH_PROVIDER_WELL_KNOWN_URL"), "Well-known URL to Auth Provider.")
	flag.StringVar(&cfg.ClusterName, "cluster-name", os.Getenv("CLUSTER_NAME"), "nais cluster")
	flag.StringVar(&cfg.MetricsAddr, "metrics-addr", ":8181", "The address the metric endpoint binds to.")
	flag.StringVar(&cfg.Tokendings.BaseURL, "tokendings-base-url", os.Getenv("TOKENDINGS_URL"), "Base URL to Tokendings.")
	flag.StringVar(&cfg.Tokendings.ClientID, "tokendings-client-id", os.Getenv("TOKENDINGS_CLIENT_ID"), "Client ID of Tokendings at Auth Provider")
	flag.StringVar(&cfg.LogLevel, "log-level", "info", "Log level for jwker")
	flag.Parse()

	j, err := jwkutils.ParseJWK([]byte(clientJwkJson))
	if err != nil {
		return nil, err
	}
	cfg.AuthProvider.ClientJwk = j

	cfg.Tokendings.Metadata.Issuer = cfg.Tokendings.BaseURL
	cfg.Tokendings.Metadata.JwksURI = fmt.Sprintf("%s/jwks", cfg.Tokendings.BaseURL)
	cfg.Tokendings.Metadata.TokenEndpoint = fmt.Sprintf("%s/token", cfg.Tokendings.BaseURL)

	tokendingsWellKnownURL, err := url.Parse(cfg.Tokendings.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid base url for tokendings: %w", err)
	}
	tokendingsWellKnownURL.Path = path.Join(tokendingsWellKnownURL.Path, oauth.WellKnownOAuthPath)
	cfg.Tokendings.WellKnownURL = tokendingsWellKnownURL.String()

	return cfg, nil
}
