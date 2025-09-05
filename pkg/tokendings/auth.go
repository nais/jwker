package tokendings

import (
	cryptorand "crypto/rand"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
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
		ID:        cryptorand.Text(),
		Audience:  audience,
	}
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
	rawJWT, err := builder.Serialize()
	if err != nil {
		return "", err
	}
	return rawJWT, nil
}
