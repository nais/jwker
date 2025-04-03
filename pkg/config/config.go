package config

import (
	"flag"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/go-jose/go-jose/v4"
	"github.com/nais/liberator/pkg/oauth"

	"github.com/nais/jwker/pkg/jwk"
	"github.com/nais/jwker/pkg/tokendings"
)

type Config struct {
	ClientID                string
	ClientJwk               *jose.JSONWebKey
	ClusterName             string
	LogLevel                string
	MaxConcurrentReconciles int
	MetricsAddr             string
	TokendingsInstances     []*tokendings.Instance
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
	flag.IntVar(&cfg.MaxConcurrentReconciles, "max-concurrent-reconciles", 20, "Max concurrent reconciles for controller.")
	flag.StringVar(&cfg.MetricsAddr, "metrics-addr", ":8181", "The address the metric endpoint binds to.")
	flag.StringVar(&tokendingsURL, "tokendings-base-url", os.Getenv("TOKENDINGS_URL"), "The base URL to Tokendings.")
	flag.StringVar(&instanceString, "tokendings-instances", os.Getenv("TOKENDINGS_INSTANCES"), "Comma separated list of baseUrls to Tokendings instances.")
	flag.StringVar(&cfg.LogLevel, "log-level", "info", "Log level for jwker")
	flag.Parse()

	j, err := jwk.Parse([]byte(clientJwkJson))
	if err != nil {
		return nil, err
	}
	cfg.ClientJwk = j

	maxConcurrentReconciles, ok := os.LookupEnv("JWKER_MAX_CONCURRENT_RECONCILES")
	if ok {
		if mcr, err := strconv.Atoi(maxConcurrentReconciles); err != nil {
			cfg.MaxConcurrentReconciles = mcr
		}
	}

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

	if len(instances) == 0 {
		return nil, fmt.Errorf("no tokendings instances configured")
	}
	cfg.TokendingsInstances = instances

	return cfg, nil
}
