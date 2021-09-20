// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// +build secrets

package secrets

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/DataDog/datadog-agent/cmd/secrets/providers"
	s "github.com/DataDog/datadog-agent/pkg/secrets"
)

// This executable provides a "read" command to fetch secrets. It can be used in
// 2 different ways:
//
// 1) With the "--with-provider-prefixes" option enabled. Each input secret
// should follow this format: "providerPrefix/some/path". The provider prefix
// indicates where to fetch the secrets from. At the moment, we support "file"
// and "k8s_secret". The path can mean different things depending on the
// provider. In "file" it's a file system path. In "k8s_secret", it follows this
// format: "namespace/name/key".
//
// 2) Without the "--with-provider-prefixes" option. The program expects a root
// path in the arguments and input secrets are just paths relative to the root
// one. So for example, if the secret is "my_secret" and the root path is
// "/some/path", the fetched value of the secret will be the contents of
// "/some/path/my_secret". This option was offered before introducing
// "--with-provider-prefixes" and is kept to avoid breaking compatibility.

const (
	providerPrefixesFlag    = "with-provider-prefixes"
	providerPrefixSeparator = "/"
)

func init() {
	cmd := readSecretCmd
	cmd.Flags().Bool(providerPrefixesFlag, false, "Use prefixes to select the secrets provider (file, k8s_secret)")
	SecretHelperCmd.AddCommand(cmd)
}

// SecretHelperCmd implements secrets provider helper commands
var SecretHelperCmd = &cobra.Command{
	Use:   "secret-helper",
	Short: "Secret management provider helper",
	Long:  ``,
}

var readSecretCmd = &cobra.Command{
	Use:   "read",
	Short: "Read secrets",
	Long:  ``,
	Args:  cobra.MaximumNArgs(1), // 0 when using the provider prefixes option, 1 when reading a file
	RunE: func(cmd *cobra.Command, args []string) error {
		usePrefixes, err := cmd.Flags().GetBool(providerPrefixesFlag)
		if err != nil {
			return err
		}

		dir := ""
		if len(args) == 1 {
			dir = args[0]
		}

		return readSecrets(os.Stdin, os.Stdout, dir, usePrefixes, &providers.Selector{})
	},
}

type secretsRequest struct {
	Version string   `json:"version"`
	Secrets []string `json:"secrets"`
}

func readSecrets(r io.Reader, w io.Writer, dir string, usePrefixes bool, selector *providers.Selector) error {
	inputSecrets, err := parseInputSecrets(r)
	if err != nil {
		return err
	}

	if usePrefixes {
		return writeFetchedSecrets(w, readSecretsUsingPrefixes(inputSecrets, selector))
	}

	return writeFetchedSecrets(w, readSecretsFromFile(inputSecrets, dir))
}

func parseInputSecrets(r io.Reader) ([]string, error) {
	in, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}

	var request secretsRequest
	err = json.Unmarshal(in, &request)
	if err != nil {
		return nil, errors.New("failed to unmarshal json input")
	}

	version := splitVersion(request.Version)
	compatVersion := splitVersion(s.PayloadVersion)
	if version[0] != compatVersion[0] {
		return nil, fmt.Errorf("incompatible protocol version %q", request.Version)
	}

	if len(request.Secrets) == 0 {
		return nil, errors.New("no secrets listed in input")
	}

	return request.Secrets, nil
}

func writeFetchedSecrets(w io.Writer, fetchedSecrets map[string]s.Secret) error {
	out, err := json.Marshal(fetchedSecrets)
	if err != nil {
		return err
	}

	_, err = w.Write(out)
	return err
}

func readSecretsFromFile(secrets []string, dir string) map[string]s.Secret {
	res := make(map[string]s.Secret)

	secretsProvider := providers.NewFileProvider(dir)
	for _, secretID := range secrets {
		res[secretID] = secretsProvider.Get(secretID)
	}

	return res
}

func readSecretsUsingPrefixes(secrets []string, selector *providers.Selector) map[string]s.Secret {
	res := make(map[string]s.Secret)

	for _, secretID := range secrets {
		prefix, id, err := parseSecretWithPrefix(secretID)
		if err != nil {
			res[secretID] = s.Secret{Value: "", ErrorMsg: err.Error()}
			continue
		}

		secretsProvider, err := selector.GetProvider(prefix)
		if err != nil {
			res[secretID] = s.Secret{Value: "", ErrorMsg: err.Error()}
			continue
		}

		res[secretID] = secretsProvider.Get(id)
	}

	return res
}

func parseSecretWithPrefix(secretID string) (prefix providers.Prefix, id string, err error) {
	split := strings.SplitN(secretID, providerPrefixSeparator, 2)
	if len(split) < 2 {
		return "", "", errors.New("invalid secret format")
	}

	prefix = providers.Prefix(split[0])
	if !prefix.IsValid() {
		return "", "", fmt.Errorf("provider not supported")
	}

	id = split[1]
	return prefix, id, nil
}

func splitVersion(ver string) []string {
	return strings.SplitN(ver, ".", 2)
}
