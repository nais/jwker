package utils

import (
	"encoding/json"
	"fmt"
	hash "github.com/mitchellh/hashstructure"

	jwkerv1 "github.com/nais/jwker/api/v1"
)

func Hash(spec jwkerv1.JwkerSpec) (string, error) {
	marshalled, err := json.Marshal(spec)
	if err != nil {
		return "", err
	}
	h, err := hash.Hash(marshalled, nil)
	return fmt.Sprintf("%x", h), err

}
