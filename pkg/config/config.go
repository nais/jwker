package config

import (
	"flag"
	"fmt"
	"github.com/nais/jwker/pkg/tokendings"
	"net/url"
	"os"
	"strings"

	"github.com/nais/jwker/jwkutils"
	"github.com/nais/liberator/pkg/oauth"
	"gopkg.in/square/go-jose.v2"
)

type Config struct {
	ClientID            string
	ClientJwk           *jose.JSONWebKey
	ClusterName         string
	LogLevel            string
	MetricsAddr         string
	TokendingsInstances []*tokendings.Instance
}

type Tokendings struct {
	BaseURL      string
	Metadata     *oauth.MetadataOAuth
	WellKnownURL string
}

func New() (*Config, error) {
	cfg := &Config{}
	var clientJwkJson string
	var instanceString string
	var tokendingsURL string
	flag.StringVar(&clientJwkJson, "client-jwk-json", os.Getenv("JWKER_PRIVATE_JWK"), "json with private JWK credential")
	flag.StringVar(&cfg.ClientID, "client-id", os.Getenv("JWKER_CLIENT_ID"), "Client ID of Jwker at Auth Provider.")
	flag.StringVar(&cfg.ClusterName, "cluster-name", os.Getenv("CLUSTER_NAME"), "nais cluster")
	flag.StringVar(&cfg.MetricsAddr, "metrics-addr", ":8181", "The address the metric endpoint binds to.")
	flag.StringVar(&tokendingsURL, "tokendings-base-url", os.Getenv("TOKENDINGS_URL"), "The base URL to Tokendings.")
	flag.StringVar(&instanceString, "tokendings-instances", os.Getenv("TOKENDINGS_INSTANCES"), "Comma separated list of baseUrls to Tokendings instances.")
	flag.StringVar(&cfg.LogLevel, "log-level", "info", "Log level for jwker")
	flag.Parse()

	j, err := jwkutils.ParseJWK([]byte(clientJwkJson))
	if err != nil {
		return nil, err
	}
	cfg.ClientJwk = j

	instances := make([]*tokendings.Instance, 0)
	raw := strings.TrimSpace(instanceString)
	if raw == "" {
		raw = tokendingsURL
	}
	for _, u := range strings.Split(raw, ",") {
		_, err := url.Parse(strings.TrimSpace(u))
		if err != nil {
			return nil, fmt.Errorf("invalid base url for tokendings instance: %w", err)
		}
		instances = append(instances, tokendings.NewInstance(u, cfg.ClientID, cfg.ClientJwk))
	}

	return cfg, nil
}
