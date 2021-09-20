// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// +build secrets

package providers

import (
	"fmt"
	"time"

	s "github.com/DataDog/datadog-agent/pkg/secrets"
	"github.com/DataDog/datadog-agent/pkg/util/kubernetes/apiserver"
)

// SecretsProvider is responsible for fetching the value of a secret.
type SecretsProvider interface {
	// Get Fetches a secret
	// Note that secretID has a different format on each secret provider. In the
	// file provider, it's a path, whereas in the kubernetes secret one it has
	// the following format: "namespace/name/key".
	Get(secretID string) s.Secret
}

// Prefix identifies a secrets provider.
type Prefix string

const (
	file      Prefix = "file"
	k8sSecret Prefix = "k8s_secret"
)

// IsValid returns whether a prefix is valid.
func (prefix Prefix) IsValid() bool {
	return prefix == file || prefix == k8sSecret
}

// Selector chooses the appropriate secrets provider based on prefixes.
type Selector struct {
	File      *FileProvider
	K8sSecret *K8sSecretProvider
}

// GetProvider returns the SecretsProvider associated with the given prefix.
func (selector *Selector) GetProvider(prefix Prefix) (SecretsProvider, error) {
	// Lazy instantiate provider. We don't need to wait for the creation of a
	// kubernetes client until we need it, for example.
	switch prefix {
	case file:
		if selector.File == nil {
			// Assumes that / is always the root path if using the file provider.
			fileProvider := NewFileProvider("/")
			selector.File = &fileProvider
		}

		return selector.File, nil
	case k8sSecret:
		if selector.K8sSecret == nil {
			kubeClient, err := apiserver.GetKubeClient(10 * time.Second)
			if err != nil {
				return nil, err
			}

			selector.K8sSecret = &K8sSecretProvider{k8sClient: kubeClient}
		}

		return selector.K8sSecret, nil
	default:
		return nil, fmt.Errorf("provider not supported: %s", prefix)
	}
}
