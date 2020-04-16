package storage

import (
	"context"

	"cloud.google.com/go/storage"
	ctrl "sigs.k8s.io/controller-runtime"
)

var (
	storageLog              = ctrl.Log.WithName("storage")
	_          JwkerStorage = &jwkerStorage{}
)

type JwkerStorage interface {
	//Read(string) (map[string]JwkerAppSet, error)
	Write(bucketObjectName string, data []byte) error
}

type jwkerStorage struct{
	bucketName string
}

func New(bucketName string) (JwkerStorage, error) {
	return &jwkerStorage{bucketName: bucketName}, nil
}

func (j *jwkerStorage) Write(bucketObjectName string, data []byte) error {
	client, err := storage.NewClient(context.Background())
	if err != nil {
		storageLog.Error(err, "error creating storage client")
	}

	writer := client.Bucket(j.bucketName).Object(bucketObjectName).NewWriter(context.Background())
	_, err = writer.Write(data)

	if err != nil {
		storageLog.Error(err, "unable to write to bucket")
		return err
	}
	if err := writer.Close(); err != nil {
		storageLog.Error(err, "unable to close bucket writer")
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
