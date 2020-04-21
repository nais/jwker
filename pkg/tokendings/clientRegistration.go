package tokendings

import (
	"bytes"
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

type SoftwareStatement struct {
	AppId                string   `json:"appId"`
	AccessPolicyInbound  []string `json:"accessPolicyInbound"`
	AccessPolicyOutbound []string `json:"accessPolicyOutbound"`
}

func DeleteClient(accessToken string, tokenDingsUrl string, appClientId ClientId) error {
	fmt.Printf("%s/registration/client/%s\n", tokenDingsUrl, url.QueryEscape(appClientId.String()))
	request, err := http.NewRequest("DELETE", fmt.Sprintf("%s/registration/client/%s", tokenDingsUrl, url.QueryEscape(appClientId.String())), nil)
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
	if resp.StatusCode != http.StatusNoContent {
		return nil
	}

	return fmt.Errorf("Something went wrong when deleting client from tokendings")
}

func RegisterClient(jwkerPrivateJwk *jose.JSONWebKey, clientPublicJwks *jose.JSONWebKeySet, accessToken string, tokenDingsUrl string, appClientId ClientId, j *v1.Jwker) ([]byte, error) {
	key := jose.SigningKey{Algorithm: jose.RS256, Key: jwkerPrivateJwk.Key}
	var signerOpts = jose.SignerOptions{}
	signerOpts.WithType("JWT")
	signerOpts.WithHeader("kid", jwkerPrivateJwk.KeyID)

	rsaSigner, err := jose.NewSigner(key, &signerOpts)
	if err != nil {
		return nil, err
	}
	builder := jwt.Signed(rsaSigner)

	softwareStatement, err := createSoftwareStatement(j, appClientId)
	if err != nil {

		return nil, err
	}
	builder = builder.Claims(softwareStatement)

	rawJWT, err := builder.CompactSerialize()
	if err != nil {
		return nil, err
	}
	cr := ClientRegistration{
		ClientName:        appClientId.String(),
		Jwks:              *clientPublicJwks,
		SoftwareStatement: rawJWT,
	}
	data, err := json.Marshal(cr)
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequest("POST", fmt.Sprintf("%s/registration/client", tokenDingsUrl), bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	request.Header.Add("Content-Type", "application/json")
	request.Header.Add("Authorization", fmt.Sprintf("Bearer %s", accessToken))

	client := http.Client{}
	resp, err := client.Do(request)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("Unable to register application with tokendings. StatusCode: %d", resp.StatusCode)
	}
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return bodyBytes, nil
}

func createSoftwareStatement(jwker *v1.Jwker, appId ClientId) (SoftwareStatement, error) {
	var inbound []string
	var outbound []string
	for _, rule := range jwker.Spec.AccessPolicy.Inbound.Rules {
		cluster, namespace := parseAccessPolicy(rule, appId)
		inbound = append(inbound, fmt.Sprintf("%s:%s:%s", cluster, namespace, rule.Application))
	}
	for _, rule := range jwker.Spec.AccessPolicy.Outbound.Rules {
		cluster, namespace := parseAccessPolicy(rule, appId)
		outbound = append(outbound, fmt.Sprintf("%s:%s:%s", cluster, namespace, rule.Application))
	}
	return SoftwareStatement{
		AppId:                appId.String(),
		AccessPolicyInbound:  inbound,
		AccessPolicyOutbound: outbound,
	}, nil
}

func parseAccessPolicy(rule v1.AccessPolicyRule, appId ClientId) (string, string) {
	cluster := rule.Cluster
	namespace := rule.Namespace
	if cluster == "" {
		cluster = appId.Cluster
	}
	if namespace == "" {
		namespace = appId.Namespace
	}
	return cluster, namespace
}
