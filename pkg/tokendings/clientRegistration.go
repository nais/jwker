package tokendings

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"

	v1 "github.com/nais/jwker/api/v1"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
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

// TODO: sign
type SoftwareStatement struct {
	AppId                string   `json:"appId"`
	AccessPolicyInbound  []string `json:"accessPolicyInbound"`
	AccessPolicyOutbound []string `json:"accessPolicyOutbound"`
}

func DeleteClient(ctx context.Context, accessToken string, tokenDingsUrl string, appClientId ClientId) error {
	request, err := http.NewRequestWithContext(ctx, "DELETE", fmt.Sprintf("%s/registration/client/%s", tokenDingsUrl, url.QueryEscape(appClientId.String())), nil)
	if err != nil {
		return err
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

	msg, _ := ioutil.ReadAll(resp.Body)

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

	rawJWT, err := builder.CompactSerialize()
	if err != nil {
		return nil, err
	}

	return &ClientRegistration{
		ClientName:        appClientId.String(),
		Jwks:              *clientPublicJwks,
		SoftwareStatement: rawJWT,
	}, nil
}

func RegisterClient(cr ClientRegistration, accessToken string, tokenDingsUrl string) error {
	data, err := json.Marshal(cr)
	if err != nil {
		return err
	}
	request, err := http.NewRequest("POST", fmt.Sprintf("%s/registration/client", tokenDingsUrl), bytes.NewReader(data))
	if err != nil {
		return err
	}
	request.Header.Add("Content-Type", "application/json")
	request.Header.Add("Authorization", fmt.Sprintf("Bearer %s", accessToken))

	client := http.Client{}
	resp, err := client.Do(request)
	if err != nil {
		return err
	}

	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		response, _ := ioutil.ReadAll(resp.Body)
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
		for _, rule := range jwker.Spec.AccessPolicy.Inbound.Rules {
			inbound = append(inbound, fmt.Sprintf("%s:%s:%s", rule.Cluster, rule.Namespace, rule.Application))
		}
	}
	if jwker.Spec.AccessPolicy.Outbound != nil {
		for _, rule := range jwker.Spec.AccessPolicy.Outbound.Rules {
			outbound = append(outbound, fmt.Sprintf("%s:%s:%s", rule.Cluster, rule.Namespace, rule.Application))
		}
	}
	return &SoftwareStatement{
		AppId:                appId.String(),
		AccessPolicyInbound:  inbound,
		AccessPolicyOutbound: outbound,
	}, nil
}
