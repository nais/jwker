package tokendings

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/nais/jwker/utils"
	"golang.org/x/oauth2/microsoft"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

type TokenResponse struct {
	AccessToken     string `json:"access_token"`
	IssuedTokenType string `json:"issued_token_type"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int64  `json:"expires_in"`
	Scope           string `json:"scope"`
}

const (
	grantType           = "client_credentials"
	clientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
)

func Claims(clientid string, audience string) jwt.Claims {
	now := time.Now()

	return jwt.Claims{
		Issuer:    clientid,
		Subject:   clientid,
		Audience:  []string{audience},
		Expiry:    jwt.NewNumericDate(now.Add(time.Second * 50000000)),
		NotBefore: 1,
		ID:        utils.RandStringBytes(8),
	}
}

func OauthForm(scope, clientAssertion string) url.Values {
	return url.Values{
		"scope":                 []string{scope},
		"grant_type":            []string{grantType},
		"client_assertion_type": []string{clientAssertionType},
		"client_assertion":      []string{clientAssertion},
	}
}

// scope = api://tokendings.prod
func GetToken(privateJwk *jose.JSONWebKey, jwkerClientID string, scope, tenantID string) (*TokenResponse, error) {
	key := jose.SigningKey{Algorithm: jose.RS256, Key: privateJwk.Key}

	signerOpts := jose.SignerOptions{}
	signerOpts.WithType("JWT")
	signerOpts.WithHeader("kid", privateJwk.KeyID)

	rsaSigner, err := jose.NewSigner(key, &signerOpts)
	if err != nil {
		return nil, err
	}

	endpoint := microsoft.AzureADEndpoint(tenantID).TokenURL
	claims := Claims(jwkerClientID, endpoint)

	builder := jwt.Signed(rsaSigner).Claims(claims)
	rawJWT, err := builder.CompactSerialize()
	if err != nil {
		return nil, err
	}

	formData := OauthForm(scope, rawJWT)

	request, err := http.NewRequest("POST", endpoint, strings.NewReader(formData.Encode()))
	if err != nil {
		return nil, err
	}
	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	client := http.Client{}
	resp, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := ioutil.ReadAll(resp.Body)
		return nil, fmt.Errorf("%s: %s", resp.Status, string(body))
	}

	token := &TokenResponse{}
	if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
		return nil, err
	}

	return token, nil
}
