// Copyright 2026 The Agent Substrate Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package tlsclient builds client TLS configs whose trust bundle and client
// credential bundle reload on rotation without a restart. It follows
// substrate's internal/ateapiauth, which this module cannot import.
package tlsclient

import (
	"crypto/tls"
	"crypto/x509"
	"errors"

	"plugins.go.ate.dev/credprovider-openbao/internal/credbundle"
)

// Config names the files and server identity a client connection uses.
type Config struct {
	// CAFile is the trust bundle the server's certificate must chain to.
	CAFile string
	// ServerName is the DNS name the server's certificate must carry.
	ServerName string
	// ClientCredBundle, if set, is the credential bundle (PKCS#8 key and
	// chain) presented as the client certificate.
	ClientCredBundle string
}

// New returns a TLS 1.3 client config for cfg. It fails if CAFile or
// ServerName is empty or a bundle is unreadable, so a missing projection fails
// startup rather than every request.
func New(cfg Config) (*tls.Config, error) {
	switch {
	case cfg.CAFile == "":
		return nil, errors.New("a server trust bundle is required")
	case cfg.ServerName == "":
		// An empty name would skip hostname verification below.
		return nil, errors.New("a server name is required")
	}
	loadRoots := credbundle.PoolLoader(cfg.CAFile)
	if _, err := loadRoots(); err != nil {
		return nil, err
	}
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
		ServerName: cfg.ServerName,
		// Chain verification happens in VerifyConnection against the
		// reloadable pool, so a CA rotation applies without a redial.
		InsecureSkipVerify: true, //nolint:gosec // verified in VerifyConnection
		VerifyConnection: func(cs tls.ConnectionState) error {
			roots, err := loadRoots()
			if err != nil {
				return err
			}
			if len(cs.PeerCertificates) == 0 {
				return errors.New("server presented no certificate")
			}
			inter := x509.NewCertPool()
			for _, c := range cs.PeerCertificates[1:] {
				inter.AddCert(c)
			}
			_, err = cs.PeerCertificates[0].Verify(x509.VerifyOptions{
				Roots:         roots,
				Intermediates: inter,
				DNSName:       cfg.ServerName,
			})
			return err
		},
	}
	if cfg.ClientCredBundle != "" {
		load := credbundle.Loader(cfg.ClientCredBundle)
		if _, err := load(nil); err != nil {
			return nil, err
		}
		tlsCfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return load(nil)
		}
	}
	return tlsCfg, nil
}
