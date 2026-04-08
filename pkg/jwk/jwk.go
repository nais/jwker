package jwk

import (
	cryptorand "crypto/rand"
	"crypto/rsa"

	"github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
)

type KeySet struct {
	PrivateKey jose.JSONWebKey
	PublicKeys jose.JSONWebKeySet
}

func (k KeySet) KeyIDs() []string {
	keyIDs := make([]string, len(k.PublicKeys.Keys))
	for i, key := range k.PublicKeys.Keys {
		keyIDs[i] = key.KeyID
	}
	return keyIDs
}

func Parse(json []byte) (*jose.JSONWebKey, error) {
	jwk := &jose.JSONWebKey{}
	if err := jwk.UnmarshalJSON(json); err != nil {
		return nil, err
	}

	return jwk, nil
}

func Generate() (jose.JSONWebKey, error) {
	privateKey, err := rsa.GenerateKey(cryptorand.Reader, 2048)
	if err != nil {
		return jose.JSONWebKey{}, err
	}

	keyId := uuid.New().String()

	jwk := jose.JSONWebKey{
		Key:       privateKey,
		KeyID:     keyId,
		Use:       "sig",
		Algorithm: "RS256",
	}
	return jwk, nil
}

// NewRotatedKeySet creates a KeySet where privateKey is the active signing key.
// The public keys include privateKey's public component plus all keys from
// previousKeys, deduplicated by KeyID.
func NewRotatedKeySet(privateKey jose.JSONWebKey, previousKeys jose.JSONWebKeySet) KeySet {
	merged := mergeKeys(privateKey, previousKeys.Keys)

	return KeySet{
		PrivateKey: privateKey,
		PublicKeys: jose.JSONWebKeySet{
			Keys: publicKeys(merged...),
		},
	}
}

// EnsureKeyInSet appends key to the set if a key with the same KeyID is not already present.
func EnsureKeyInSet(set *jose.JSONWebKeySet, key jose.JSONWebKey) {
	for _, existing := range set.Keys {
		if existing.KeyID == key.KeyID {
			return
		}
	}
	set.Keys = append(set.Keys, key)
}

// mergeKeys returns a slice starting with key, followed by all keys
// from others that do not share key's KeyID.
func mergeKeys(key jose.JSONWebKey, others []jose.JSONWebKey) []jose.JSONWebKey {
	merged := []jose.JSONWebKey{key}
	for _, k := range others {
		if k.KeyID != key.KeyID {
			merged = append(merged, k)
		}
	}
	return merged
}

func publicKeys(keys ...jose.JSONWebKey) []jose.JSONWebKey {
	publics := make([]jose.JSONWebKey, len(keys))
	for i := range keys {
		publics[i] = keys[i].Public()
	}
	return publics
}
