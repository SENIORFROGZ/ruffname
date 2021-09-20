// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// +build secrets

package secrets

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/DataDog/datadog-agent/cmd/secrets/providers"
)

func TestReadSecrets(t *testing.T) {
	fileProvider := providers.NewFileProvider("./testdata")

	k8sClientWithSecret := fake.NewSimpleClientset(&v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "some_name",
			Namespace: "some_namespace",
		},
		Data: map[string][]byte{"some_key": []byte("some_value")},
	})
	k8sProvider := providers.NewK8sSecretProvider(k8sClientWithSecret)

	tests := []struct {
		name        string
		in          string
		out         string
		usePrefixes bool
		selector    providers.Selector
		err         string
	}{
		{
			name: "invalid input",
			in:   "invalid",
			out:  "",
			err:  "failed to unmarshal json input",
		},
		{
			name: "invalid version",
			in: `
			{
				"version": "2.0"
			}
			`,
			out: "",
			err: `incompatible protocol version "2.0"`,
		},
		{
			name: "no secrets",
			in: `
			{
				"version": "1.0"
			}
			`,
			out: "",
			err: `no secrets listed in input`,
		},
		{
			name: "valid input, reading from file",
			in: `
			{
				"version": "1.0",
				"secrets": [
					"secret1",
					"secret2"
				]
			}
			`,
			out: `
			{
				"secret1": {
					"value": "secret1-value"
				},
				"secret2": {
					"error": "secret does not exist"
				}
			}
			`,
		},
		{
			name: "valid input, reading from file and k8s providers",
			in: `
			{
				"version": "1.0",
				"secrets": [
					"file/read-secrets/secret1",
					"k8s_secret/some_namespace/some_name/some_key",
					"file/read-secrets/secret2",
					"k8s_secret/another_namespace/another_name/another_key"
				]
			}
			`,
			out: `
			{
				"file/read-secrets/secret1": {
					"value": "secret1-value"
				},
				"k8s_secret/some_namespace/some_name/some_key": {
					"value": "some_value"
				},
				"file/read-secrets/secret2": {
					"error": "secret does not exist"
				},
				"k8s_secret/another_namespace/another_name/another_key": {
					"error": "secrets \"another_name\" not found"
				}
			}
			`,
			usePrefixes: true,
			selector: providers.Selector{
				File:      &fileProvider,
				K8sSecret: &k8sProvider,
			},
		},
	}

	path := filepath.Join("testdata", "read-secrets")
	testdata, _ := filepath.Abs("testdata")
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var w bytes.Buffer
			err := readSecrets(strings.NewReader(test.in), &w, path, test.usePrefixes, &test.selector)
			out := string(w.Bytes())

			if test.out != "" {
				assert.JSONEq(t, strings.ReplaceAll(test.out, "$TESTDATA", testdata), out)
			} else {
				assert.Empty(t, out)
			}

			if test.err != "" {
				assert.EqualError(t, err, test.err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
