// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// +build secrets

package providers

import (
	"context"
	"fmt"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	s "github.com/DataDog/datadog-agent/pkg/secrets"
)

// K8sSecretProvider fetches secrets from Kubernetes.
type K8sSecretProvider struct {
	k8sClient kubernetes.Interface
}

// NewK8sSecretProvider creates a new K8sSecretProvider.
func NewK8sSecretProvider(k8sClient kubernetes.Interface) K8sSecretProvider {
	return K8sSecretProvider{k8sClient: k8sClient}
}

// Get fetches a secret.
func (ksb *K8sSecretProvider) Get(secretID string) s.Secret {
	return readKubernetesSecret(ksb.k8sClient, secretID)
}

func readKubernetesSecret(kubeClient kubernetes.Interface, path string) s.Secret {
	splitName := strings.Split(path, "/")

	if len(splitName) != 3 {
		return s.Secret{ErrorMsg: fmt.Sprintf("invalid format. Use: \"namespace/name/key\"")}
	}

	namespace, name, key := splitName[0], splitName[1], splitName[2]

	secret, err := kubeClient.CoreV1().Secrets(namespace).Get(context.TODO(), name, metav1.GetOptions{})
	if err != nil {
		return s.Secret{ErrorMsg: err.Error()}
	}

	value, ok := secret.Data[key]
	if !ok {
		return s.Secret{ErrorMsg: fmt.Sprintf("key %s not found in secret %s/%s", key, namespace, name)}
	}

	return s.Secret{Value: string(value)}
}
