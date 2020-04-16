package storage

import (
	"context"

	"cloud.google.com/go/storage"
	"google.golang.org/api/option"
)

var (
	_ JwkerStorage = &jwkerStorage{}
)

type JwkerStorage interface {
	// Read(string) (map[string]JwkerAppSet, error)
	Write(fileName string, data []byte) error
	Delete(fileName string) error
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

/*
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
*/
