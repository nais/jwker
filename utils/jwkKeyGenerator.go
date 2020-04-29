package utils

import (
	cryptorand "crypto/rand"
	"crypto/rsa"
	"math/rand"

	"github.com/google/uuid"

	"gopkg.in/square/go-jose.v2"
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

func GenerateJWK() (jose.JSONWebKey, error) {
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

func BuildKeySet(newjwk jose.JSONWebKey, existingjwk jose.JSONWebKey) KeySet {
	return KeySet{
		Private: jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{
				newjwk,
			},
		},
		Public: jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{
				newjwk.Public(),
				existingjwk.Public(),
			},
		},
	}
}
