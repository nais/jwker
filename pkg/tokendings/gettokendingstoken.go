package tokendings

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/nais/jwker/utils"
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
	tokenDingsTokenEndpoint  = "%s/token"
	tokenDingsClientEndpoint = "%s/registration/client"
	grantType                = "client_credentials"
	clientAssertionType      = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
)

func GetToken(privateJwk *jose.JSONWebKey, jwkerClientID ClientId, tokenDingsUrl string) (*TokenResponse, error) {
	key := jose.SigningKey{Algorithm: jose.RS256, Key: privateJwk.Key}
	var signerOpts = jose.SignerOptions{}
	signerOpts.WithType("JWT")
	signerOpts.WithHeader("kid", privateJwk.KeyID)

	rsaSigner, err := jose.NewSigner(key, &signerOpts)
	if err != nil {
		return nil,err
	}

	builder := jwt.Signed(rsaSigner)

	t := fmt.Sprintf(tokenDingsTokenEndpoint, tokenDingsUrl)
	now := time.Now()
	claims := jwt.Claims{
		Issuer:    jwkerClientID.String(),
		Subject:   jwkerClientID.String(),
		Audience:  []string{t},
		Expiry:    jwt.NewNumericDate(now.Add(time.Second * 500)),
		NotBefore: jwt.NewNumericDate(now),
		IssuedAt:  jwt.NewNumericDate(now),
		ID:        utils.RandStringBytes(8),
	}
	builder = builder.Claims(claims)
	rawJWT, err := builder.CompactSerialize()
	if err != nil {
		return nil,err
	}

	client := http.Client{}

	data := url.Values{
		"scope":                 []string{fmt.Sprintf(tokenDingsClientEndpoint, tokenDingsUrl)},
		"grant_type":            []string{grantType},
		"client_assertion_type": []string{clientAssertionType},
		"client_assertion":      []string{rawJWT},
	}.Encode()
	request, err := http.NewRequest("POST", fmt.Sprintf(tokenDingsTokenEndpoint, tokenDingsUrl), strings.NewReader(data))
	if err != nil {
		return nil,err
	}
	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(request)
	if err != nil {
		return nil,err
	}
	defer resp.Body.Close()

	if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
		return nil,err
	}
	return nil,nil
}
