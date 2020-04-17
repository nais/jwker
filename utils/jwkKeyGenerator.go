package utils

import (
	cryptorand "crypto/rand"
	"crypto/rsa"
	"math/rand"

	"github.com/google/uuid"

	"gopkg.in/square/go-jose.v2"
)

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func RandStringBytes(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}

func GenerateJwkerKeys() (jose.JSONWebKeySet, jose.JSONWebKeySet, error) {
	jwk, err := JwkKeyGenerator()
	if err != nil {
		return jose.JSONWebKeySet{}, jose.JSONWebKeySet{}, err
	}
	return JwksGenerator(jwk)
}

func JwkKeyGenerator() (jose.JSONWebKey, error) {
	privateKey, err := rsa.GenerateKey(cryptorand.Reader, 2048)
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
