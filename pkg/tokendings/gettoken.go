package tokendings

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/nais/jwker/jwkutils"
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

type CustomClaims struct {
	Issuer    string          `json:"iss,omitempty"`
	Subject   string          `json:"sub,omitempty"`
	Expiry    jwt.NumericDate `json:"exp,omitempty"`
	NotBefore jwt.NumericDate `json:"nbf,omitempty"`
	IssuedAt  jwt.NumericDate `json:"iat,omitempty"`
	ID        string          `json:"jti,omitempty"`
	Audience  string          `json:"aud,omitempty"`
}

func Claims(clientid, audience string) CustomClaims {
	now := time.Now()
	exp := jwt.NewNumericDate(now.Add(time.Second * 50000000))

	return CustomClaims{
		Issuer:    clientid,
		Subject:   clientid,
		Expiry:    *exp,
		NotBefore: 1,
		ID:        jwkutils.RandStringBytes(8),
		Audience:  audience,
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
func GetToken(privateJwk *jose.JSONWebKey, clientID string, scope, endpoint string) (*TokenResponse, error) {
	rawJWT, err := ClientAssertion(privateJwk, clientID, endpoint)
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
		return nil, fmt.Errorf("%s", resp.Status)
	}

	token := &TokenResponse{}
	if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
		return nil, err
	}

	return token, nil
}

func ClientAssertion(privateJwk *jose.JSONWebKey, clientID string, endpoint string) (string, error) {
	key := jose.SigningKey{Algorithm: jose.RS256, Key: privateJwk.Key}

	signerOpts := jose.SignerOptions{}
	signerOpts.WithType("JWT")
	signerOpts.WithHeader("kid", privateJwk.KeyID)

	rsaSigner, err := jose.NewSigner(key, &signerOpts)
	if err != nil {
		return "", err
	}

	claims := Claims(clientID, endpoint)

	builder := jwt.Signed(rsaSigner).Claims(claims)
	rawJWT, err := builder.CompactSerialize()
	if err != nil {
		return "", err
	}
	return rawJWT, nil
}
