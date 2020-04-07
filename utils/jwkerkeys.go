package utils

import (
	"crypto/rand"
	"crypto/rsa"

	"gopkg.in/square/go-jose.v2"
)

func GenerateJwkerKeys() (jose.JSONWebKeySet, jose.JSONWebKeySet, *rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return jose.JSONWebKeySet{}, jose.JSONWebKeySet{}, privateKey, err
	}

	keyId := RandStringBytes(8)
	jwk := jose.JSONWebKey{
		Key:   privateKey,
		KeyID: keyId,
	}

	var privateJwks []jose.JSONWebKey
	var publicJwks []jose.JSONWebKey

	privateJwks = append(privateJwks, jwk)
	publicJwks = append(publicJwks, jwk.Public())
	privateKeyset := jose.JSONWebKeySet{Keys: privateJwks}
	publicKeyset := jose.JSONWebKeySet{Keys: publicJwks}

	return privateKeyset, publicKeyset, privateKey, nil
}
