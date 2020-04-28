package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/nais/jwker/pkg/tokendings"
	"github.com/nais/jwker/utils"
	flag "github.com/spf13/pflag"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

var cfg config

type config struct {
	jwks     string
	clientid string
	audience string
	url      string
}

func main() {
	var err error

	flag.StringVar(&cfg.jwks, "jwks", "", "")
	flag.StringVar(&cfg.clientid, "clientid", "clientid", "")
	flag.StringVar(&cfg.audience, "audience", "audience", "")
	flag.StringVar(&cfg.url, "url", "http://localhost:8080", "")
	flag.Parse()

	jwks := &jose.JSONWebKeySet{}
	file, err := os.Open(cfg.jwks)
	if err != nil {
		panic(err)
	}
	bdec := base64.NewDecoder(base64.StdEncoding, file)
	jdec := json.NewDecoder(bdec)
	err = jdec.Decode(jwks)

	if err != nil {
		panic(err)
	}

	if len(jwks.Keys) == 0 {
		panic("no keys")
	}

	mockToken, err := mocktoken(cfg.clientid)
	if err != nil {
		panic(err)
	}

	params := newTokenParams{
		privateJwk:    &jwks.Keys[0],
		jwkerClientID: cfg.clientid,
		oauthTokenURL: cfg.url,
		audience:      cfg.audience,
		subjectToken:  mockToken.AccessToken,
	}
	token, err := applicationToken(params)
	if err != nil {
		panic(err)
	}

	fmt.Println(token.AccessToken)
}

const (
	tokenDingsTokenEndpoint  = "%s/token"
	mockGrantType            = "client_credentials"
	clientAssertionType      = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
	grantType                = "urn:ietf:params:oauth:grant-type:token-exchange"
	subjectTokenType         = "urn:ietf:params:oauth:token-type:jwt"
)

func mocktoken(clientid string) (*tokendings.TokenResponse, error) {
	values := url.Values{
		"grant_type":    []string{mockGrantType},
		"client_id":     []string{clientid},
		"client_secret": []string{"verysecret"},
		"scope":         []string{"veryscope"},
	}
	resp, err := http.PostForm("http://localhost:1111/mock1/token", values)
	if err != nil {
		return nil, err
	}

	token := &tokendings.TokenResponse{}
	err = json.NewDecoder(resp.Body).Decode(token)
	if err != nil {
		return nil, err
	}

	return token, nil
}

type newTokenParams struct {
	privateJwk    *jose.JSONWebKey
	jwkerClientID string
	oauthTokenURL string
	audience      string
	subjectToken  string
}

func applicationToken(params newTokenParams) (*tokendings.TokenResponse, error) {
	token := &tokendings.TokenResponse{}
	key := jose.SigningKey{Algorithm: jose.RS256, Key: params.privateJwk.Key}
	var signerOpts = jose.SignerOptions{}
	signerOpts.WithType("JWT")
	signerOpts.WithHeader("kid", params.privateJwk.KeyID)

	rsaSigner, err := jose.NewSigner(key, &signerOpts)
	if err != nil {
		return nil, err
	}

	builder := jwt.Signed(rsaSigner)

	t := fmt.Sprintf(tokenDingsTokenEndpoint, params.oauthTokenURL)
	now := time.Now()
	claims := jwt.Claims{
		Issuer:    params.jwkerClientID,
		Subject:   params.jwkerClientID,
		Audience:  []string{t},
		Expiry:    jwt.NewNumericDate(now.Add(time.Second * 500)),
		NotBefore: jwt.NewNumericDate(now),
		IssuedAt:  jwt.NewNumericDate(now),
		ID:        utils.RandStringBytes(8),
	}
	builder = builder.Claims(claims)
	rawJWT, err := builder.CompactSerialize()
	if err != nil {
		return nil, err
	}

	client := http.Client{}

	data := url.Values{
		"audience":              []string{params.audience},
		"grant_type":            []string{grantType},
		"client_assertion_type": []string{clientAssertionType},
		"client_assertion":      []string{rawJWT},
		"subject_token":         []string{params.subjectToken},
		"subject_token_type":    []string{subjectTokenType},
	}.Encode()

	request, err := http.NewRequest("POST", fmt.Sprintf(tokenDingsTokenEndpoint, params.oauthTokenURL), strings.NewReader(data))
	if err != nil {
		return nil, err
	}
	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
		return nil, err
	}

	token.Created = time.Now().Unix()

	return token, nil
}
