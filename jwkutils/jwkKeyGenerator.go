package jwkutils

import (
	cryptorand "crypto/rand"
	"crypto/rsa"
	"math/rand"

	"github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
)

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

type KeySet struct {
	Private jose.JSONWebKeySet
	Public  jose.JSONWebKeySet
}

func RandStringBytes(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}

func ParseJWK(json []byte) (*jose.JSONWebKey, error) {
	jwk := &jose.JSONWebKey{}
	if err := jwk.UnmarshalJSON(json); err != nil {
		return nil, err
	}

	return jwk, nil
}

func GenerateJWK() (jose.JSONWebKey, error) {
	privateKey, err := rsa.GenerateKey(cryptorand.Reader, 2048)
	if err != nil {
		return jose.JSONWebKey{}, err
	}

	keyId := uuid.New().String()

	jwk := jose.JSONWebKey{
		Key:       privateKey,
		KeyID:     keyId,
		Use:       "sig",
		Algorithm: "RS256",
	}
	return jwk, nil
}

func KeySetWithExisting(newjwk jose.JSONWebKey, existingjwks []jose.JSONWebKey) KeySet {
	return KeySet{
		Private: jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{
				newjwk,
			},
		},
		Public: jose.JSONWebKeySet{
			Keys: publicKeys(append(existingjwks, newjwk)...),
		},
	}
}

func publicKeys(keys ...jose.JSONWebKey) []jose.JSONWebKey {
	publics := make([]jose.JSONWebKey, len(keys))
	for i := range keys {
		publics[i] = keys[i].Public()
	}
	return publics
}
