package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"

	"cloud.google.com/go/storage"
	"github.com/nais/jwker/pkg/tokendings"
	"google.golang.org/api/option"
	"gopkg.in/square/go-jose.v2"
)

var (
	_ JwkerStorage = &jwkerStorage{}
)

type JwkerStorage interface {
	// Read(string) (map[string]JwkerAppSet, error)
	Write(fileName string, data []byte, keys map[string]int64) error
	Delete(fileName string) error
	Read(fileName string) (jose.JSONWebKey, map[string]int64, error)
}

type jwkerStorage struct {
	credentialsPath string
	bucketName      string
	client          *storage.Client
}

type StorageObject struct {
	Keys map[string]int64                      `json:"keys"`
	Data tokendings.ClientRegistrationResponse `json:"data"`
}

func (s *StorageObject) getYoungest() jose.JSONWebKey {
	var youngest int64
	var youngestKey jose.JSONWebKey
	for keyID, creationTime := range s.Keys {
		if creationTime > youngest {
			youngest = creationTime
			youngestKey = s.getKeyById(keyID)
		}
	}
	return youngestKey
}

func (s *StorageObject) getKeyById(keyId string) jose.JSONWebKey {
	return s.Data.Jwks.Key(keyId)[0]
}

func New(credentialsPath, bucketName string) (JwkerStorage, error) {
	client, err := storage.NewClient(context.Background(), option.WithCredentialsFile(credentialsPath))
	if err != nil {
		return nil, err
	}
	return &jwkerStorage{
		credentialsPath: credentialsPath,
		bucketName:      bucketName,
		client:          client,
	}, nil
}

func (j *jwkerStorage) Delete(bucketObjectName string) error {
	if err := j.client.Bucket(j.bucketName).Object(bucketObjectName).Delete(context.Background()); err != nil {
		return err
	}
	return nil
}

func (j *jwkerStorage) Read(bucketObjectName string) (jose.JSONWebKey, map[string]int64, error) {
	reader, err := j.client.Bucket(j.bucketName).Object(bucketObjectName).NewReader(context.Background())
	if err != nil {
		fmt.Printf("Unable to find key in bucket %s\n", err)
		return jose.JSONWebKey{}, nil, err
	}
	defer reader.Close()
	data, err := ioutil.ReadAll(reader)
	if err != nil {
		fmt.Printf("Failed to read from bucket %s\n", err)
		return jose.JSONWebKey{}, nil, err
	}
	var storageObject = StorageObject{}

	if err := json.Unmarshal(data, &storageObject); err != nil {
		fmt.Printf("Failed to unmarshall %s\n", err)
		return jose.JSONWebKey{}, nil, err
	}

	return storageObject.getYoungest(), storageObject.Keys, nil

}

func (j *jwkerStorage) Write(bucketObjectName string, data []byte, keys map[string]int64) error {
	var clientResponse = tokendings.ClientRegistrationResponse{}

	if err := json.Unmarshal(data, &clientResponse); err != nil {
		return err
	}

	storageOject := StorageObject{
		Keys: keys,
		Data: clientResponse,
	}
	storageJson, err := json.MarshalIndent(storageOject, "", " ")
	if err != nil {
		return err
	}

	writer := j.client.Bucket(j.bucketName).Object(bucketObjectName).NewWriter(context.Background())

	_, err = writer.Write(storageJson)
	if err != nil {
		return err
	}
	if err := writer.Close(); err != nil {
		return err
	}
	return nil
}
