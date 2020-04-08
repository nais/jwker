package utils

import (
	"crypto/rand"
	"crypto/rsa"

	"github.com/google/uuid"

	"gopkg.in/square/go-jose.v2"
)

func JwkKeyGenerator() (jose.JSONWebKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return jose.JSONWebKey{}, err
	}

	keyId := uuid.New().String()

	jwk := jose.JSONWebKey{
		Key:   privateKey,
		KeyID: keyId,
		Use:   "sig",
	}
	return jwk, nil
}
func JwksGenerator(jwk jose.JSONWebKey) (jose.JSONWebKeySet, jose.JSONWebKeySet, error) {

	var privateJwks []jose.JSONWebKey
	var publicJwks []jose.JSONWebKey

	privateJwks = append(privateJwks, jwk)
	publicJwks = append(publicJwks, jwk.Public())
	privateKeyset := jose.JSONWebKeySet{Keys: privateJwks}
	publicKeyset := jose.JSONWebKeySet{Keys: publicJwks}

	return privateKeyset, publicKeyset, nil
}
