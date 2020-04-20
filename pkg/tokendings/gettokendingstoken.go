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

type TokenDingsToken struct {
	AccessToken     string `json:"access_token"`
	IssuedTokenType string `json:"issued_token_type"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int64  `json:"expires_in"`
	Scope           string `json:"scope"`
	Created         int64
}

var token = TokenDingsToken{}

func GetToken(privateJwk *jose.JSONWebKey, jwkerClientID ClientId, tokenDingsUrl string) (*TokenDingsToken, error) {

	now := time.Now().Unix()

	if token.AccessToken == "" || (token.Created+token.ExpiresIn) < now-30 {
		if err := fetchNewToken(privateJwk, jwkerClientID.String(), tokenDingsUrl); err != nil {
			return &TokenDingsToken{}, err
		}
	}

	return &token, nil
}

func fetchNewToken(privateJwk *jose.JSONWebKey, jwkerClientID, tokenDingsUrl string) error {

	// Todo: Retries

	key := jose.SigningKey{Algorithm: jose.RS256, Key: privateJwk.Key}
	var signerOpts = jose.SignerOptions{}
	signerOpts.WithType("JWT")
	signerOpts.WithHeader("kid", privateJwk.KeyID)

	rsaSigner, err := jose.NewSigner(key, &signerOpts)
	if err != nil {
		return err
	}

	builder := jwt.Signed(rsaSigner)

	tokenDingsTokenEndpoint := fmt.Sprintf("%s/registration/token", tokenDingsUrl)
	now := time.Now()
	claims := jwt.Claims{
		Issuer:    jwkerClientID,
		Subject:   jwkerClientID,
		Audience:  []string{tokenDingsTokenEndpoint},
		Expiry:    jwt.NewNumericDate(now.Add(time.Second * 500)),
		NotBefore: jwt.NewNumericDate(now),
		IssuedAt:  jwt.NewNumericDate(now),
		ID:        utils.RandStringBytes(8),
	}
	builder = builder.Claims(claims)
	rawJWT, err := builder.CompactSerialize()
	if err != nil {
		return err
	}
	//fmt.Printf("token to tokendings: %s\n", rawJWT)

	client := http.Client{}

	data := url.Values{
		"scope":                 []string{fmt.Sprintf("%s/registration/client", tokenDingsUrl)},
		"grant_type":            []string{"client_credentials"},
		"client_assertion_type": []string{"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		"client_assertion":      []string{rawJWT},
	}.Encode()
	request, err := http.NewRequest("POST", fmt.Sprintf("%s/registration/token", tokenDingsUrl), strings.NewReader(data))
	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(request)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if json.NewDecoder(resp.Body).Decode(&token); err != nil {
		return err
	}
	token.Created = time.Now().Unix()
	return nil
}
