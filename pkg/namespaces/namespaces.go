package namespaces

import (
	"context"
	"fmt"
	"strconv"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var (
	namespaceCache = make(map[string]corev1.Namespace)
)

const (
	sharedNamespaceLabelKey = "shared"
)

type Validator struct {
	Reader   client.Reader
	Logger   logr.Logger
}

func NewValidator(reader client.Reader, logger logr.Logger) *Validator {
	return &Validator{Reader: reader, Logger: logger}
}

func (v *Validator) InSharedNamespace(ctx context.Context, namespaceName string) (bool, error) {
	namespace, err := v.getNamespace(ctx, namespaceName)
	if err != nil {
		return true, fmt.Errorf("fetching namespace: %w", err)
	}

	inSharedNamespace, err := v.isSharedNamespace(namespace)
	if err != nil {
		return inSharedNamespace, err
	}

	if !inSharedNamespace {
		return false, nil
	}

	return inSharedNamespace, nil
}

func (v *Validator) getNamespace(ctx context.Context, namespaceName string) (corev1.Namespace, error) {
	var namespace corev1.Namespace
	namespace, found := namespaceCache[namespaceName]

	if found {
		return namespace, nil
	}

	err := v.Reader.Get(ctx, client.ObjectKey{
		Name: namespaceName,
	}, &namespace)
	if err != nil {
		return namespace, err
	}

	namespaceCache[namespaceName] = namespace
	return namespace, nil
}

func (v *Validator) isSharedNamespace(namespace corev1.Namespace) (bool, error) {
	stringValue, found := namespace.GetLabels()[sharedNamespaceLabelKey]
	if !found {
		return false, nil
	}

	shared, err := strconv.ParseBool(stringValue)
	if err != nil {
		return false, err
	}

	return shared, nil
}
