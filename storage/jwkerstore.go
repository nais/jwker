package storage

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"

	"gopkg.in/square/go-jose.v2"
	ctrl "sigs.k8s.io/controller-runtime"
)

var (
	storageLog              = ctrl.Log.WithName("storage")
	_          JwkerStorage = &jwkerStorage{}
)

type JwkerStorage interface {
	ReadJwkerStorage(string) (map[string]JwkerAppSet, error)
}

type jwkerStorage struct{}

type JwkerAppSet struct {
	Appid        string             `json:"appId"`
	Jwks         jose.JSONWebKeySet `json:"jwks"`
	AccessPolicy AccessPolicy       `json:"accessPolicy"`
}

type AccessPolicy struct {
	Inbound  []string `json:"inbound"`
	Outbound []string `json:"outbound"`
}

func New() (JwkerStorage, error) {
	return &jwkerStorage{}, nil
}

func (j *jwkerStorage) ReadJwkerStorage(storagePath string) (map[string]JwkerAppSet, error) {
	var storage map[string]JwkerAppSet

	file, err := ioutil.ReadFile(storagePath)
	if err != nil {
		storageLog.Error(err, "Unable to read storage")
		os.Exit(1)
	}
	if err := json.Unmarshal([]byte(file), &storage); err != nil {
		storageLog.Error(err, "Unable to unmarshal storage")
		os.Exit(1)
	}

	for k, v := range storage {
		if v.Appid == "" {
			return nil, fmt.Errorf("Empty app id.")
		}
		if len(v.Jwks.Keys) < 1 {
			return nil, fmt.Errorf("No keys present. AppId: [%s]", k)
		}
		if len(v.AccessPolicy.Inbound) < 1 {
			return nil, fmt.Errorf("No inbound access policies. AppId: [%s]", k)
		}
		if len(v.AccessPolicy.Outbound) < 1 {
			return nil, fmt.Errorf("No output id access policies. AppId: [%s]", k)
		}
	}

	return storage, err
}
