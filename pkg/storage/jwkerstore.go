package storage

import (
	"context"
	"encoding/json"
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
	Write(fileName string, data []byte) error
	Delete(fileName string) error
	Read(fileName string) (jose.JSONWebKeySet, error)
}

type jwkerStorage struct {
	credentialsPath string
	bucketName      string
	client          *storage.Client
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

func (j *jwkerStorage) Read(bucketObjectName string) (jose.JSONWebKeySet, error) {
	reader, err := j.client.Bucket(j.bucketName).Object(bucketObjectName).NewReader(context.Background())
	if err != nil {
		return jose.JSONWebKeySet{}, err
	}
	defer reader.Close()
	data, err := ioutil.ReadAll(reader)
	if err != nil {
		return jose.JSONWebKeySet{}, err
	}
	var clientResponse tokendings.ClientRegistrationResponse

	if err := json.Unmarshal(data, &clientResponse); err != nil {
		return jose.JSONWebKeySet{}, err
	}
	return clientResponse.Jwks, nil

}
func (j *jwkerStorage) Delete(bucketObjectName string) error {
	if err := j.client.Bucket(j.bucketName).Object(bucketObjectName).Delete(context.Background()); err != nil {
		return err
	}
	return nil
}

func (j *jwkerStorage) Write(bucketObjectName string, data []byte) error {
	writer := j.client.Bucket(j.bucketName).Object(bucketObjectName).NewWriter(context.Background())
	_, err := writer.Write(data)

	if err != nil {
		return err
	}
	if err := writer.Close(); err != nil {
		return err
	}
	return nil
}
