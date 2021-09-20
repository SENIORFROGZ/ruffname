// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2018 Datadog, Inc.

package security

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"

	"fmt"
	"net"
	"time"

	"github.com/DataDog/datadog-agent/pkg/config"
	log "github.com/cihub/seelog"
)

const (
	authTokenName = "auth_token"
	authTokenLen  = 32
)

// GenerateKeyPair create a public/private keypair
func GenerateKeyPair(bits int) (*rsa.PrivateKey, error) {
	privKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, fmt.Errorf("generating random key: %v", err)
	}

	return privKey, nil
}

// CertTemplate create x509 certificate template
func CertTemplate() (*x509.Certificate, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %s", err)
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(10 * 365 * 24 * time.Hour)
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Datadoc, Inc."},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		BasicConstraintsValid: true,
	}

	return &template, nil
}

// GenerateRootCert generates a root certificate
func GenerateRootCert(hosts []string, bits int) (
	cert *x509.Certificate, certPEM []byte, rootKey *rsa.PrivateKey, err error) {

	rootCertTmpl, err := CertTemplate()
	if err != nil {
		return
	}

	rootKey, err = GenerateKeyPair(bits)
	if err != nil {
		return
	}

	// describe what the certificate will be used for
	rootCertTmpl.IsCA = true
	rootCertTmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature
	rootCertTmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}

	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			rootCertTmpl.IPAddresses = append(rootCertTmpl.IPAddresses, ip)
		} else {
			rootCertTmpl.DNSNames = append(rootCertTmpl.DNSNames, h)
		}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, rootCertTmpl, rootCertTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		return
	}
	// parse the resulting certificate so we can use it again
	cert, err = x509.ParseCertificate(certDER)
	if err != nil {
		return
	}
	// PEM encode the certificate (this is a standard TLS encoding)
	b := pem.Block{Type: "CERTIFICATE", Bytes: certDER}
	certPEM = pem.EncodeToMemory(&b)
	return
}

// FetchAuthToken gets the authentication token from:
// - configuration (datadog.yaml or environment variable)
// - the auth token file & creates one if it doesn't exist
// Requires that the config has been set up before calling
func FetchAuthToken() (string, error) {
	authTokenFile := filepath.Join(filepath.Dir(config.Datadog.ConfigFileUsed()), authTokenName)
	_, err := os.Stat(authTokenFile)
	var isAuthTokenFile bool
	if err == nil {
		isAuthTokenFile = true
	}

	authTokenEnv := config.Datadog.GetString("auth_token")

	if authTokenEnv != "" {
		if isAuthTokenFile {
			log.Infof("Authentication token configured via \"auth_token\", ignoring existing token file: %q", authTokenFile)
		}
		err := authTokenValidation(authTokenEnv)
		if err != nil {
			return "", err
		}
		return authTokenEnv, nil
	}

	// Create a new token if it doesn't exist
	if isAuthTokenFile == false {
		key := make([]byte, authTokenLen)
		_, err = rand.Read(key)
		if err != nil {
			return "", fmt.Errorf("error creating authentication token: %s", err)
		}

		// Write the auth token to the auth token file (platform-specific)
		err = saveAuthToken(hex.EncodeToString(key), authTokenFile)
		if err != nil {
			return "", fmt.Errorf("error creating authentication token: %s", err)
		}
		log.Infof("Saved a new authentication token to %s", authTokenFile)
	}

	// Read the token
	authTokenRaw, err := ioutil.ReadFile(authTokenFile)
	if err != nil {
		return "", fmt.Errorf("unable to access authentication token: %s", err)
	}

	authToken := string(authTokenRaw)

	// Do some basic validation
	err = authTokenValidation(authToken)
	if err != nil {
		return "", err
	}
	return authToken, nil
}

func authTokenValidation(authToken string) error {
	tokenLen := len(authToken)
	if tokenLen < authTokenLen {
		return fmt.Errorf("invalid authentication token, length is %d: must be at least %d characters", tokenLen, authTokenLen)
	}
	return nil
}
