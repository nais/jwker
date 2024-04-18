package tokendings

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	v1 "github.com/nais/liberator/pkg/apis/nais.io/v1"
	"github.com/nais/liberator/pkg/oauth"
)

type ClientId struct {
	Name      string
	Namespace string
	Cluster   string
}

func (a *ClientId) String() string {
	return fmt.Sprintf("%s:%s:%s", a.Cluster, a.Namespace, a.Name)
}

func (a *ClientId) ToFileName() string {
	return fmt.Sprintf("%s/%s/%s", a.Cluster, a.Namespace, a.Name)
}

type ClientRegistration struct {
	ClientName        string             `json:"client_name"`
	Jwks              jose.JSONWebKeySet `json:"jwks"`
	SoftwareStatement string             `json:"software_statement"`
}

type ClientRegistrationResponse struct {
	ClientRegistration
	GrantTypes              []string `json:"grant_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
}

type SoftwareStatement struct {
	AppId                string   `json:"appId"`
	AccessPolicyInbound  []string `json:"accessPolicyInbound"`
	AccessPolicyOutbound []string `json:"accessPolicyOutbound"`
}

type Instance struct {
	BaseURL      string
	ClientID     string
	ClientJwk    *jose.JSONWebKey
	Metadata     *oauth.MetadataOAuth
	WellKnownURL string
}

func NewInstance(baseURL, clientID string, clientJwk *jose.JSONWebKey) *Instance {
	i := &Instance{
		BaseURL:   baseURL,
		ClientID:  clientID,
		ClientJwk: clientJwk,
	}

	i.Metadata = &oauth.MetadataOAuth{}
	i.Metadata.Issuer = i.BaseURL
	i.Metadata.JwksURI = fmt.Sprintf("%s/jwks", i.BaseURL)
	i.Metadata.TokenEndpoint = fmt.Sprintf("%s/token", i.BaseURL)
	i.WellKnownURL = fmt.Sprintf("%s%s", strings.TrimSuffix(i.BaseURL, "/"), oauth.WellKnownOAuthPath)
	return i
}

func (t *Instance) DeleteClient(ctx context.Context, appClientId ClientId) error {
	endpoint := fmt.Sprintf("%s/registration/client", t.BaseURL)

	request, err := http.NewRequestWithContext(ctx, "DELETE", fmt.Sprintf("%s/%s", endpoint, url.QueryEscape(appClientId.String())), nil)
	if err != nil {
		return err
	}

	accessToken, err := ClientAssertion(t.ClientJwk, t.ClientID, endpoint)
	if err != nil {
		return fmt.Errorf("unable to create token for invoking tokendings: %w", err)
	}

	request.Header.Add("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	client := http.Client{}
	resp, err := client.Do(request)
	if err != nil {
		return err
	}

	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		return nil
	}

	msg, _ := io.ReadAll(resp.Body)

	return fmt.Errorf("delete client from tokendings: %s: %s", resp.Status, msg)
}

func MakeClientRegistration(jwkerPrivateJwk *jose.JSONWebKey, clientPublicJwks *jose.JSONWebKeySet, appClientId ClientId, jwker v1.Jwker) (*ClientRegistration, error) {
	key := jose.SigningKey{Algorithm: jose.RS256, Key: jwkerPrivateJwk.Key}
	var signerOpts = jose.SignerOptions{}
	signerOpts.WithType("JWT")
	signerOpts.WithHeader("kid", jwkerPrivateJwk.KeyID)

	rsaSigner, err := jose.NewSigner(key, &signerOpts)
	if err != nil {
		return nil, err
	}
	builder := jwt.Signed(rsaSigner)

	softwareStatement, err := createSoftwareStatement(jwker, appClientId)
	if err != nil {
		return nil, err
	}
	builder = builder.Claims(softwareStatement)

	rawJWT, err := builder.Serialize()
	if err != nil {
		return nil, err
	}

	return &ClientRegistration{
		ClientName:        appClientId.String(),
		Jwks:              *clientPublicJwks,
		SoftwareStatement: rawJWT,
	}, nil
}

func (t *Instance) RegisterClient(cr ClientRegistration) error {
	endpoint := fmt.Sprintf("%s/registration/client", t.BaseURL)

	data, err := json.Marshal(cr)
	if err != nil {
		return err
	}
	request, err := http.NewRequest("POST", endpoint, bytes.NewReader(data))
	if err != nil {
		return err
	}
	request.Header.Add("Content-Type", "application/json")

	accessToken, err := ClientAssertion(t.ClientJwk, t.ClientID, endpoint)
	if err != nil {
		return fmt.Errorf("unable to create token for invoking tokendings: %w", err)
	}
	request.Header.Add("Authorization", fmt.Sprintf("Bearer %s", accessToken))

	client := http.Client{}
	resp, err := client.Do(request)
	if err != nil {
		return err
	}

	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		response, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("unable to register application with tokendings: %s: %s", resp.Status, response)
	}

	return nil
}

func createSoftwareStatement(jwker v1.Jwker, appId ClientId) (*SoftwareStatement, error) {
	inbound := make([]string, 0)
	outbound := make([]string, 0)
	if jwker.Spec.AccessPolicy == nil {
		return nil, fmt.Errorf("no access policy")
	}
	if jwker.Spec.AccessPolicy.Inbound != nil {
		for _, rule := range jwker.Spec.AccessPolicy.Inbound.Rules.GetRules() {
			ensureValidRule(&rule, appId)
			inbound = append(inbound, fmt.Sprintf("%s:%s:%s", rule.Cluster, rule.Namespace, rule.Application))
		}
	}
	if jwker.Spec.AccessPolicy.Outbound != nil {
		for _, rule := range jwker.Spec.AccessPolicy.Outbound.Rules {
			ensureValidRule(&rule, appId)
			outbound = append(outbound, fmt.Sprintf("%s:%s:%s", rule.Cluster, rule.Namespace, rule.Application))
		}
	}
	return &SoftwareStatement{
		AppId:                appId.String(),
		AccessPolicyInbound:  inbound,
		AccessPolicyOutbound: outbound,
	}, nil
}

func ensureValidRule(rule *v1.AccessPolicyRule, appId ClientId) {
	if len(rule.Namespace) == 0 {
		rule.Namespace = appId.Namespace
	}
	if len(rule.Cluster) == 0 {
		rule.Cluster = appId.Cluster
	}
}
