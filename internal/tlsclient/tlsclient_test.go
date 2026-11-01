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

package tlsclient

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"plugins.go.ate.dev/credprovider-openbao/internal/testpki"
)

func TestNewRequiresConfig(t *testing.T) {
	ca := testpki.NewCA(t, "ca")
	caFile := testpki.WriteTrustBundle(t, ca)
	for name, cfg := range map[string]Config{
		"no CA":            {ServerName: "s"},
		"no server name":   {CAFile: caFile},
		"missing CA file":  {CAFile: caFile + ".missing", ServerName: "s"},
		"missing client":   {CAFile: caFile, ServerName: "s", ClientCredBundle: caFile + ".missing"},
		"client is CA PEM": {CAFile: caFile, ServerName: "s", ClientCredBundle: caFile},
	} {
		if _, err := New(cfg); err == nil {
			t.Errorf("%s: New succeeded, want error", name)
		}
	}
}

// server starts a TLS server presenting a leaf for name from ca, requesting
// (but not requiring) a client certificate, and reports what it saw.
func server(t *testing.T, ca *testpki.CA, name string) (*httptest.Server, chan []*x509.Certificate) {
	t.Helper()
	seen := make(chan []*x509.Certificate, 1)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.TLS.PeerCertificates
	}))
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{ca.Issue(t, testpki.Opts{DNSNames: []string{name}}).TLSCertificate()},
		ClientAuth:   tls.RequestClientCert,
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv, seen
}

func get(t *testing.T, cfg *tls.Config, url string) error {
	t.Helper()
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}, Timeout: 5 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

func TestVerifiesChainAndName(t *testing.T) {
	ca := testpki.NewCA(t, "ca")
	other := testpki.NewCA(t, "other")
	srv, _ := server(t, ca, "openbao.openbao.svc")

	ok, err := New(Config{CAFile: testpki.WriteTrustBundle(t, ca), ServerName: "openbao.openbao.svc"})
	if err != nil {
		t.Fatal(err)
	}
	if err := get(t, ok, srv.URL); err != nil {
		t.Errorf("trusted CA and matching name: %v", err)
	}

	wrongName, _ := New(Config{CAFile: testpki.WriteTrustBundle(t, ca), ServerName: "impostor.svc"})
	if err := get(t, wrongName, srv.URL); err == nil {
		t.Error("mismatched server name: request succeeded, want verification failure")
	}

	wrongCA, _ := New(Config{CAFile: testpki.WriteTrustBundle(t, other), ServerName: "openbao.openbao.svc"})
	if err := get(t, wrongCA, srv.URL); err == nil {
		t.Error("untrusted CA: request succeeded, want verification failure")
	}
}

func TestReloadsTrustBundle(t *testing.T) {
	oldCA := testpki.NewCA(t, "old")
	newCA := testpki.NewCA(t, "new")
	srv, _ := server(t, newCA, "api.ate-system.svc")

	caFile := testpki.WriteTrustBundle(t, oldCA)
	cfg, err := New(Config{CAFile: caFile, ServerName: "api.ate-system.svc"})
	if err != nil {
		t.Fatal(err)
	}
	if err := get(t, cfg, srv.URL); err == nil {
		t.Fatal("server signed by a CA not yet trusted: request succeeded")
	}
	// Rotate in place with a distinct mtime, as a projected volume update does.
	if err := os.WriteFile(caFile, newCA.CertPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	later := time.Now().Add(time.Minute)
	if err := os.Chtimes(caFile, later, later); err != nil {
		t.Fatal(err)
	}
	if err := get(t, cfg, srv.URL); err != nil {
		t.Errorf("after rotating the trust bundle: %v", err)
	}
}

func TestPresentsClientCertificate(t *testing.T) {
	ca := testpki.NewCA(t, "ca")
	srv, seen := server(t, ca, "api.ate-system.svc")
	const id = "spiffe://cluster.local/ns/credprovider-openbao/sa/openbao-credential-provider"
	cfg, err := New(Config{
		CAFile:           testpki.WriteTrustBundle(t, ca),
		ServerName:       "api.ate-system.svc",
		ClientCredBundle: testpki.WriteCredBundle(t, ca.Issue(t, testpki.Opts{URIs: []string{id}})),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := get(t, cfg, srv.URL); err != nil {
		t.Fatal(err)
	}
	certs := <-seen
	if len(certs) == 0 || len(certs[0].URIs) != 1 || certs[0].URIs[0].String() != id {
		t.Errorf("server saw client certificates %v, want one with URI SAN %s", certs, id)
	}
}
