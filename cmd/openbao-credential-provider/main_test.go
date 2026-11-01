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

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"go.ate.dev/substrate/api/ateapi/v1"
	"go.ate.dev/substrate/api/credprovider/v1"

	"plugins.go.ate.dev/credprovider-openbao/internal/testpki"
)

const (
	gatewayID  = "spiffe://cluster.local/ns/ate-system/sa/atenet-egress"
	providerID = "spiffe://cluster.local/ns/credprovider-openbao/sa/openbao-credential-provider"
	// providerDNS is the name the gateway expects on the provider's certificate.
	providerDNS = "openbao-credential-provider.credprovider-openbao.svc"
)

func TestHealthHandler(t *testing.T) {
	var ready atomic.Bool
	h := healthHandler(&ready)
	get := func(path string) int {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		return rec.Code
	}
	if get("/healthz") != http.StatusOK || get("/readyz") != http.StatusServiceUnavailable {
		t.Error("before ready: want /healthz 200 and /readyz 503")
	}
	ready.Store(true)
	if get("/readyz") != http.StatusOK {
		t.Error("ready: want /readyz 200")
	}
}

func requiredFlags() []string {
	return []string{
		"--server-cred-bundle=s", "--client-ca-file=c", "--injector-identity=" + gatewayID,
		"--ateapi-ca-file=a", "--ateapi-client-cert=b", "--openbao-address=https://openbao:8200",
	}
}

func TestParseFlagsRequiresFlags(t *testing.T) {
	if _, err := parseFlags(flag.NewFlagSet("t", flag.ContinueOnError), requiredFlags()); err != nil {
		t.Fatalf("all required flags: %v", err)
	}
	for i, f := range requiredFlags() {
		args := append(append([]string{}, requiredFlags()[:i]...), requiredFlags()[i+1:]...)
		if _, err := parseFlags(flag.NewFlagSet("t", flag.ContinueOnError), args); err == nil {
			t.Errorf("without %s: parseFlags succeeded", strings.SplitN(f, "=", 2)[0])
		}
	}
}

// fakeAteapi serves Control.MintActorJwt, recording the caller's SPIFFE ID.
type fakeAteapi struct {
	ateapi.UnimplementedControlServer
	mu      sync.Mutex
	callers []string
}

func (f *fakeAteapi) MintActorJwt(ctx context.Context, req *ateapi.MintActorJwtRequest) (*ateapi.MintActorJwtResponse, error) {
	p, _ := peer.FromContext(ctx)
	var caller string
	if ti, ok := p.AuthInfo.(credentials.TLSInfo); ok && len(ti.State.PeerCertificates) > 0 && len(ti.State.PeerCertificates[0].URIs) > 0 {
		caller = ti.State.PeerCertificates[0].URIs[0].String()
	}
	f.mu.Lock()
	f.callers = append(f.callers, caller)
	f.mu.Unlock()
	if caller != providerID {
		return nil, status.Error(codes.PermissionDenied, "not egress_gateway")
	}
	return &ateapi.MintActorJwtResponse{ActorJwt: "jwt-for-" + req.GetActor().GetAtespace() + "/" + req.GetActor().GetName()}, nil
}

// harness wires the provider to a TLS fake ateapi and a TLS fake OpenBao, as
// it runs in a cluster: servicedns certificates for every server, podidentity
// certificates for every client.
type harness struct {
	servicedns, podidentity *testpki.CA
	addr                    string
	ateapi                  *fakeAteapi
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	h := &harness{
		servicedns:  testpki.NewCA(t, "servicedns"),
		podidentity: testpki.NewCA(t, "podidentity"),
		ateapi:      &fakeAteapi{},
	}
	loopback := []net.IP{net.IPv4(127, 0, 0, 1)}

	// ateapi: servicedns serving cert, verifies podidentity clients.
	clientCAs := x509.NewCertPool()
	clientCAs.AddCert(h.podidentity.Cert)
	ateapiSrv := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{h.servicedns.Issue(t, testpki.Opts{DNSNames: []string{"api.ate-system.svc"}}).TLSCertificate()},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAs,
	})))
	ateapi.RegisterControlServer(ateapiSrv, h.ateapi)
	ateapiLis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = ateapiSrv.Serve(ateapiLis) }()
	t.Cleanup(ateapiSrv.Stop)

	// OpenBao: team-a's JWT may read team-a's secret and nothing else.
	bao := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/auth/jwt/login":
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["role"] != "substrate-actor" || !strings.HasPrefix(body["jwt"], "jwt-for-") {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = io.WriteString(w, `{"errors":["bad login"]}`)
				return
			}
			_, _ = io.WriteString(w, `{"auth":{"client_token":"tok-`+strings.TrimPrefix(body["jwt"], "jwt-for-")+`","lease_duration":300}}`)
		case r.Method == http.MethodGet && r.URL.Path == "/v1/secret/data/atespaces/team-a/example-api":
			if r.Header.Get("X-Vault-Token") != "tok-team-a/alpha" {
				w.WriteHeader(http.StatusForbidden)
				_, _ = io.WriteString(w, `{"errors":["permission denied"]}`)
				return
			}
			_, _ = io.WriteString(w, `{"data":{"data":{"token":"team-a-secret"}}}`)
		default:
			w.WriteHeader(http.StatusForbidden)
		}
	}))
	bao.TLS = &tls.Config{Certificates: []tls.Certificate{h.servicedns.Issue(t, testpki.Opts{DNSNames: []string{"localhost"}, IPs: loopback}).TLSCertificate()}}
	bao.StartTLS()
	t.Cleanup(bao.Close)
	baoAddr := strings.Replace(bao.URL, "127.0.0.1", "localhost", 1)

	cfg, err := parseFlags(flag.NewFlagSet("t", flag.ContinueOnError), []string{
		"--server-cred-bundle=" + testpki.WriteCredBundle(t, h.servicedns.Issue(t, testpki.Opts{DNSNames: []string{providerDNS}})),
		"--client-ca-file=" + testpki.WriteTrustBundle(t, h.podidentity),
		"--injector-identity=" + gatewayID,
		"--ateapi-address=dns:///" + ateapiLis.Addr().String(),
		"--ateapi-ca-file=" + testpki.WriteTrustBundle(t, h.servicedns),
		"--ateapi-client-cert=" + testpki.WriteCredBundle(t, h.podidentity.Issue(t, testpki.Opts{URIs: []string{providerID}})),
		"--openbao-address=" + baoAddr,
		"--openbao-ca-file=" + testpki.WriteTrustBundle(t, h.servicedns),
	})
	if err != nil {
		t.Fatal(err)
	}
	srv, conn, err := newServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	h.addr = lis.Addr().String()
	return h
}

// dialAs connects to the provider as a client presenting a podidentity
// certificate for id, verifying the provider as the gateway does.
func (h *harness) dialAs(t *testing.T, id string) credprovider.CredentialProviderClient {
	t.Helper()
	roots := x509.NewCertPool()
	roots.AddCert(h.servicedns.Cert)
	leaf := h.podidentity.Issue(t, testpki.Opts{URIs: []string{id}}).TLSCertificate()
	conn, err := grpc.NewClient("dns:///"+h.addr, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
		MinVersion:   tls.VersionTLS13,
		RootCAs:      roots,
		ServerName:   providerDNS,
		Certificates: []tls.Certificate{leaf},
	})))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return credprovider.NewCredentialProviderClient(conn)
}

func fetchAs(c credprovider.CredentialProviderClient, actor string) (*credprovider.FetchSecretResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return c.FetchSecret(ctx, &credprovider.FetchSecretRequest{
		Uri:           "ate-secret://openbao/kv/secret/atespaces/team-a/example-api/token",
		ActorSpiffeId: "spiffe://substrate-actor.local/actor/" + actor,
	})
}

func TestServesThroughAteapiAndOpenBao(t *testing.T) {
	h := newHarness(t)
	gateway := h.dialAs(t, gatewayID)

	resp, err := fetchAs(gateway, "team-a/alpha")
	if err != nil {
		t.Fatalf("team-a actor: %v", err)
	}
	if string(resp.GetOpaqueBytes()) != "team-a-secret" {
		t.Errorf("value = %q, want team-a-secret", resp.GetOpaqueBytes())
	}
	h.ateapi.mu.Lock()
	callers := append([]string{}, h.ateapi.callers...)
	h.ateapi.mu.Unlock()
	if len(callers) != 1 || callers[0] != providerID {
		t.Errorf("ateapi saw callers %v, want the provider's pod identity %s", callers, providerID)
	}

	// OpenBao refuses team-b's token for team-a's path.
	if _, err := fetchAs(gateway, "team-b/bravo"); status.Code(err) != codes.PermissionDenied {
		t.Errorf("team-b actor: err = %v, want PermissionDenied", err)
	}
}

func TestRejectsCallersOtherThanTheGateway(t *testing.T) {
	h := newHarness(t)
	impostor := h.dialAs(t, "spiffe://cluster.local/ns/ate-system/sa/atelet")
	if _, err := fetchAs(impostor, "team-a/alpha"); status.Code(err) != codes.Unavailable {
		t.Errorf("impostor: err = %v, want the handshake to fail (Unavailable)", err)
	}
	h.ateapi.mu.Lock()
	defer h.ateapi.mu.Unlock()
	if len(h.ateapi.callers) != 0 {
		t.Errorf("an impostor's request reached ateapi: %v", h.ateapi.callers)
	}
}

func TestNewServerRejectsInsecureOpenBao(t *testing.T) {
	ca := testpki.NewCA(t, "ca")
	base := []string{
		"--server-cred-bundle=" + testpki.WriteCredBundle(t, ca.Issue(t, testpki.Opts{DNSNames: []string{providerDNS}})),
		"--client-ca-file=" + testpki.WriteTrustBundle(t, ca),
		"--injector-identity=" + gatewayID,
		"--ateapi-ca-file=" + testpki.WriteTrustBundle(t, ca),
		"--ateapi-client-cert=" + testpki.WriteCredBundle(t, ca.Issue(t, testpki.Opts{URIs: []string{providerID}})),
	}
	for _, tt := range []struct {
		extra []string
		ok    bool
	}{
		{[]string{"--openbao-address=http://openbao.openbao.svc:8200"}, false},
		{[]string{"--openbao-address=http://openbao.openbao.svc:8200", "--openbao-allow-insecure-http"}, true},
		{[]string{"--openbao-address=https://openbao.openbao.svc:8200"}, false},
		{[]string{"--openbao-address=https://openbao.openbao.svc:8200", "--openbao-ca-file=" + testpki.WriteTrustBundle(t, ca)}, true},
	} {
		cfg, err := parseFlags(flag.NewFlagSet("t", flag.ContinueOnError), append(append([]string{}, base...), tt.extra...))
		if err != nil {
			t.Fatal(err)
		}
		srv, conn, err := newServer(cfg)
		if (err == nil) != tt.ok {
			t.Errorf("%v: newServer error = %v, want ok=%v", tt.extra, err, tt.ok)
		}
		if err == nil {
			srv.Stop()
			conn.Close()
		}
	}
}
