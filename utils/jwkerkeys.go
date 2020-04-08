package utils

import (
	"gopkg.in/square/go-jose.v2"
)

func GenerateJwkerKeys() (jose.JSONWebKeySet, jose.JSONWebKeySet, error) {
	jwk, err := JwkKeyGenerator()
	if err != nil {
		return jose.JSONWebKeySet{}, jose.JSONWebKeySet{}, err
	}
	return JwksGenerator(jwk)
}
