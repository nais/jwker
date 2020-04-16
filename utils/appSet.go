package utils

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"

	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
	v1 "nais.io/navikt/jwker/api/v1"
	ctrl "sigs.k8s.io/controller-runtime"
)

type AppId struct {
	Name      string
	Namespace string
	Cluster   string
}

func (a *AppId) String() string {
	return fmt.Sprintf("%s:%s:%s", a.Cluster, a.Namespace, a.Name)
}

func (a *AppId) ToFileName() string {
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

// TODO: We need to handle response from token-dingz once endpoint is ready
func DeleteClient(accessToken string, tokenDingsUrl string, appClientId AppId) error {
	fmt.Printf("%s/registration/client/%s\n", tokenDingsUrl, url.QueryEscape(appClientId.String()))
	request, err := http.NewRequest("DELETE", fmt.Sprintf("%s/registration/client/%s", tokenDingsUrl, url.QueryEscape(appClientId.String())), nil)
	if err != nil {
		return err
	}
	//request.Header.Add("Content-Type", "application/json")
	request.Header.Add("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	client := http.Client{}
	resp, err := client.Do(request)
	if err != nil {
		return err
	}

	defer resp.Body.Close()
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	fmt.Println(bodyBytes)
	if err != nil {
		return err
	}
	return nil
}

func RegisterClient(jwkerPrivateJwk *jose.JSONWebKey, clientPublicJwks *jose.JSONWebKeySet, accessToken string, tokenDingsUrl string, appClientId AppId, j *v1.Jwker) ([]byte, error) {
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

	data, err := json.Marshal(ClientRegistration{
		ClientName:        appClientId.String(),
		Jwks:              *clientPublicJwks,
		SoftwareStatement: rawJWT,
	})
	if err != nil {
		ctrl.Log.Error(err, "Unable to marshal data")
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
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	//var clientRegistrationResponse ClientRegistrationResponse
	return bodyBytes, nil

	/*	appId := fmt.Sprintf("%s:%s:%s", r.ClusterName, jwker.Namespace, jwker.Name)
		jwkerStorage, _ := storage.New()
		appSets, err := jwkerStorage.ReadJwkerStorage(r.StoragePath)

		if err != nil {
			r.Log.Error(err, "Could not read storage")
		}
		if _, ok := appSets[appId]; !ok {
			// fmt.Println(val)

		}

		appkeyset := generateNewAppSet(r, jwker)
		appjson, err := json.MarshalIndent(appkeyset, "", " ")
		if err != nil {
			r.Log.Error(err, "unable to marshall object")
		}

		_ = ioutil.WriteFile("test.json", appjson, 0644)
	*/
}
