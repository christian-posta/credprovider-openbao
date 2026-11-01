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

package provider

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"go.ate.dev/substrate/api/ateapi/v1"
	"go.ate.dev/substrate/api/credprovider/v1"

	"plugins.go.ate.dev/credprovider-openbao/internal/openbao"
)

const (
	alphaID  = "spiffe://substrate-actor.local/actor/team-a/alpha"
	alphaURI = "ate-secret://openbao/kv/secret/atespaces/team-a/example-api/token"
)

var testConfig = Config{
	ProviderName: "openbao",
	JWTMount:     "jwt",
	Role:         "substrate-actor",
	Audience:     "openbao",
	JWTLifetime:  300 * time.Second,
	FetchTimeout: 2 * time.Second,
}

// fakeMinter mints "jwt-<atespace>/<name>-<n>", or fails with err.
type fakeMinter struct {
	mu    sync.Mutex
	err   error
	calls []*ateapi.MintActorJwtRequest
	// block, if set, is waited on before minting.
	block chan struct{}
}

func (m *fakeMinter) MintActorJwt(ctx context.Context, in *ateapi.MintActorJwtRequest, _ ...grpc.CallOption) (*ateapi.MintActorJwtResponse, error) {
	if m.block != nil {
		select {
		case <-m.block:
		case <-ctx.Done():
			return nil, status.FromContextError(ctx.Err()).Err()
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, in)
	if m.err != nil {
		return nil, m.err
	}
	return &ateapi.MintActorJwtResponse{ActorJwt: fmt.Sprintf("jwt-%s/%s-%d", in.GetActor().GetAtespace(), in.GetActor().GetName(), len(m.calls))}, nil
}

func (m *fakeMinter) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.calls)
}

// fakeStore issues token "tok-<jwt>" for a login and serves reads from data,
// unless loginErr or readErr is set. Tokens in revoked are refused with 403.
type fakeStore struct {
	mu       sync.Mutex
	ttl      time.Duration
	loginErr error
	readErr  error
	data     map[string]any
	revoked  map[string]bool
	logins   []string
	reads    []string
	// readHook, if set, runs before each read.
	readHook func(ctx context.Context) error
}

func (s *fakeStore) LoginJWT(_ context.Context, mount, role, jwt string) (openbao.Token, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.logins = append(s.logins, mount+"|"+role+"|"+jwt)
	if s.loginErr != nil {
		return openbao.Token{}, s.loginErr
	}
	return openbao.Token{Value: "tok-" + jwt, TTL: s.ttl}, nil
}

func (s *fakeStore) ReadKV2(ctx context.Context, token, mount string, path []string) (map[string]any, error) {
	if s.readHook != nil {
		if err := s.readHook(ctx); err != nil {
			return nil, err
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reads = append(s.reads, token+"|"+mount+"/"+strings.Join(path, "/"))
	if s.revoked[token] {
		return nil, &openbao.StatusError{Op: "read", Code: http.StatusForbidden}
	}
	if s.readErr != nil {
		return nil, s.readErr
	}
	return s.data, nil
}

func newStore() *fakeStore {
	return &fakeStore{ttl: 300 * time.Second, data: map[string]any{"token": "hunter2"}, revoked: map[string]bool{}}
}

func newServer(t *testing.T, m Minter, s Store) *Server {
	t.Helper()
	srv, err := NewServer(testConfig, m, s)
	if err != nil {
		t.Fatal(err)
	}
	return srv
}

func fetch(srv *Server, uri, actor string) (*credprovider.FetchSecretResponse, error) {
	return srv.FetchSecret(context.Background(), &credprovider.FetchSecretRequest{Uri: uri, ActorSpiffeId: actor})
}

func TestNewServerValidatesConfig(t *testing.T) {
	for name, mutate := range map[string]func(*Config){
		"no provider name": func(c *Config) { c.ProviderName = "" },
		"no mount":         func(c *Config) { c.JWTMount = "" },
		"no role":          func(c *Config) { c.Role = "" },
		"no audience":      func(c *Config) { c.Audience = "" },
		"short lifetime":   func(c *Config) { c.JWTLifetime = 299 * time.Second },
		"long lifetime":    func(c *Config) { c.JWTLifetime = 3601 * time.Second },
		"fractional":       func(c *Config) { c.JWTLifetime = 300*time.Second + time.Millisecond },
		"no fetch timeout": func(c *Config) { c.FetchTimeout = 0 },
	} {
		cfg := testConfig
		mutate(&cfg)
		if _, err := NewServer(cfg, &fakeMinter{}, newStore()); err == nil {
			t.Errorf("%s: NewServer succeeded", name)
		}
	}
}

func TestFetchSecret(t *testing.T) {
	m, s := &fakeMinter{}, newStore()
	srv := newServer(t, m, s)
	resp, err := fetch(srv, alphaURI, alphaID)
	if err != nil {
		t.Fatal(err)
	}
	if string(resp.GetOpaqueBytes()) != "hunter2" {
		t.Errorf("value = %q, want hunter2", resp.GetOpaqueBytes())
	}
	if m.count() != 1 {
		t.Fatalf("mints = %d, want 1", m.count())
	}
	req := m.calls[0]
	if req.GetActor().GetAtespace() != "team-a" || req.GetActor().GetName() != "alpha" ||
		len(req.GetAudiences()) != 1 || req.GetAudiences()[0] != "openbao" || req.GetExpirationSeconds() != 300 {
		t.Errorf("mint request = %v", req)
	}
	if want := []string{"jwt|substrate-actor|jwt-team-a/alpha-1"}; fmt.Sprint(s.logins) != fmt.Sprint(want) {
		t.Errorf("logins = %v, want %v", s.logins, want)
	}
	if want := []string{"tok-jwt-team-a/alpha-1|secret/atespaces/team-a/example-api"}; fmt.Sprint(s.reads) != fmt.Sprint(want) {
		t.Errorf("reads = %v, want %v", s.reads, want)
	}
}

func TestTokenReusedPerActor(t *testing.T) {
	m, s := &fakeMinter{}, newStore()
	srv := newServer(t, m, s)
	for range 3 {
		if _, err := fetch(srv, alphaURI, alphaID); err != nil {
			t.Fatal(err)
		}
	}
	if m.count() != 1 || len(s.logins) != 1 || len(s.reads) != 3 {
		t.Errorf("mints=%d logins=%d reads=%d, want 1, 1, 3", m.count(), len(s.logins), len(s.reads))
	}
	// Another actor gets its own token.
	if _, err := fetch(srv, alphaURI, "spiffe://substrate-actor.local/actor/team-a/bravo"); err != nil {
		t.Fatal(err)
	}
	if m.count() != 2 || s.reads[3] != "tok-jwt-team-a/bravo-2|secret/atespaces/team-a/example-api" {
		t.Errorf("second actor: mints=%d last read=%s", m.count(), s.reads[3])
	}
}

func TestTokenRefreshedWhenAThirdOfItsLifetimeRemains(t *testing.T) {
	m, s := &fakeMinter{}, newStore()
	srv := newServer(t, m, s)
	now := time.Unix(1_800_000_000, 0)
	srv.tokens.now = func() time.Time { return now }

	if _, err := fetch(srv, alphaURI, alphaID); err != nil {
		t.Fatal(err)
	}
	now = now.Add(199 * time.Second) // 101s of 300s left: reuse
	if _, err := fetch(srv, alphaURI, alphaID); err != nil {
		t.Fatal(err)
	}
	if len(s.logins) != 1 {
		t.Fatalf("logins = %d before the refresh point, want 1", len(s.logins))
	}
	now = now.Add(1 * time.Second) // 100s left: refresh
	if _, err := fetch(srv, alphaURI, alphaID); err != nil {
		t.Fatal(err)
	}
	if len(s.logins) != 2 {
		t.Errorf("logins = %d at the refresh point, want 2", len(s.logins))
	}
}

func TestTokenWithoutTTLIsNotCached(t *testing.T) {
	m, s := &fakeMinter{}, newStore()
	s.ttl = 0
	srv := newServer(t, m, s)
	for range 2 {
		if _, err := fetch(srv, alphaURI, alphaID); err != nil {
			t.Fatal(err)
		}
	}
	if len(s.logins) != 2 {
		t.Errorf("logins = %d, want 2", len(s.logins))
	}
}

func TestStaleCachedTokenRetriedOnce(t *testing.T) {
	m, s := &fakeMinter{}, newStore()
	srv := newServer(t, m, s)
	if _, err := fetch(srv, alphaURI, alphaID); err != nil {
		t.Fatal(err)
	}
	s.revoked["tok-jwt-team-a/alpha-1"] = true
	resp, err := fetch(srv, alphaURI, alphaID)
	if err != nil {
		t.Fatalf("after revoking the cached token: %v", err)
	}
	if string(resp.GetOpaqueBytes()) != "hunter2" || len(s.logins) != 2 {
		t.Errorf("value=%q logins=%d, want hunter2 and a second login", resp.GetOpaqueBytes(), len(s.logins))
	}
	// The fresh token is cached in place of the revoked one.
	if _, err := fetch(srv, alphaURI, alphaID); err != nil || len(s.logins) != 2 {
		t.Errorf("third fetch: err=%v logins=%d, want reuse of the fresh token", err, len(s.logins))
	}
}

func TestFreshTokenRefusedIsNotRetried(t *testing.T) {
	m, s := &fakeMinter{}, newStore()
	s.readErr = &openbao.StatusError{Op: "read", Code: http.StatusForbidden}
	srv := newServer(t, m, s)
	if _, err := fetch(srv, alphaURI, alphaID); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("err = %v, want PermissionDenied", err)
	}
	if len(s.logins) != 1 || len(s.reads) != 1 {
		t.Errorf("logins=%d reads=%d, want 1 and 1", len(s.logins), len(s.reads))
	}
	// The refused token itself was valid, so it stays cached: the next read
	// reuses it without a login.
	s.readErr = nil
	if _, err := fetch(srv, alphaURI, alphaID); err != nil {
		t.Fatal(err)
	}
	if len(s.logins) != 1 {
		t.Fatalf("logins = %d, want the token kept after a policy denial", len(s.logins))
	}
	// A cached token refused, then its replacement refused too: exactly one
	// retry login, then a denial.
	s.readErr = &openbao.StatusError{Op: "read", Code: http.StatusForbidden}
	if _, err := fetch(srv, alphaURI, alphaID); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("err = %v, want PermissionDenied", err)
	}
	if len(s.logins) != 2 {
		t.Errorf("logins = %d, want exactly one retry login", len(s.logins))
	}
}

func TestDenialsAreIndistinguishable(t *testing.T) {
	cases := map[string]func(*fakeMinter, *fakeStore){
		"OpenBao refuses the path": func(_ *fakeMinter, s *fakeStore) {
			s.readErr = &openbao.StatusError{Op: "read", Code: http.StatusForbidden}
		},
		"secret does not exist": func(_ *fakeMinter, s *fakeStore) {
			s.readErr = &openbao.StatusError{Op: "read", Code: http.StatusNotFound}
		},
		"field missing":    func(_ *fakeMinter, s *fakeStore) { s.data = map[string]any{"other": "x"} },
		"field not string": func(_ *fakeMinter, s *fakeStore) { s.data = map[string]any{"token": 42} },
		"field null":       func(_ *fakeMinter, s *fakeStore) { s.data = map[string]any{"token": nil} },
		"actor not found":  func(m *fakeMinter, _ *fakeStore) { m.err = status.Error(codes.NotFound, "actor not found") },
		"login refused 400": func(_ *fakeMinter, s *fakeStore) {
			s.loginErr = &openbao.StatusError{Op: "login", Code: http.StatusBadRequest, Errors: []string{"claim mismatch"}}
		},
		"login refused 403": func(_ *fakeMinter, s *fakeStore) {
			s.loginErr = &openbao.StatusError{Op: "login", Code: http.StatusForbidden}
		},
	}
	var first string
	for name, setup := range cases {
		m, s := &fakeMinter{}, newStore()
		setup(m, s)
		_, err := fetch(newServer(t, m, s), alphaURI, alphaID)
		if status.Code(err) != codes.PermissionDenied {
			t.Errorf("%s: err = %v, want PermissionDenied", name, err)
			continue
		}
		msg := status.Convert(err).Message()
		if first == "" {
			first = msg
		} else if msg != first {
			t.Errorf("%s: message %q differs from %q", name, msg, first)
		}
		if strings.Contains(msg, "hunter2") || strings.Contains(msg, "claim mismatch") {
			t.Errorf("%s: message %q leaks detail", name, msg)
		}
	}
}

func TestErrorCodes(t *testing.T) {
	transport := errors.New("dial tcp: connection refused")
	for _, tt := range []struct {
		name  string
		setup func(*fakeMinter, *fakeStore)
		want  codes.Code
	}{
		{"ateapi unavailable", func(m *fakeMinter, _ *fakeStore) { m.err = status.Error(codes.Unavailable, "down") }, codes.Unavailable},
		{"ateapi deadline", func(m *fakeMinter, _ *fakeStore) { m.err = status.Error(codes.DeadlineExceeded, "slow") }, codes.Unavailable},
		{"provider not granted egress_gateway", func(m *fakeMinter, _ *fakeStore) { m.err = status.Error(codes.PermissionDenied, "nope") }, codes.Internal},
		{"provider unauthenticated", func(m *fakeMinter, _ *fakeStore) { m.err = status.Error(codes.Unauthenticated, "who") }, codes.Internal},
		{"ateapi invalid argument", func(m *fakeMinter, _ *fakeStore) { m.err = status.Error(codes.InvalidArgument, "bad") }, codes.Internal},
		{"login transport", func(_ *fakeMinter, s *fakeStore) { s.loginErr = transport }, codes.Unavailable},
		{"login sealed", func(_ *fakeMinter, s *fakeStore) {
			s.loginErr = &openbao.StatusError{Op: "login", Code: http.StatusServiceUnavailable}
		}, codes.Unavailable},
		{"login rate limited", func(_ *fakeMinter, s *fakeStore) {
			s.loginErr = &openbao.StatusError{Op: "login", Code: http.StatusTooManyRequests}
		}, codes.Unavailable},
		{"login mount missing", func(_ *fakeMinter, s *fakeStore) {
			s.loginErr = &openbao.StatusError{Op: "login", Code: http.StatusNotFound}
		}, codes.Internal},
		{"read transport", func(_ *fakeMinter, s *fakeStore) { s.readErr = transport }, codes.Unavailable},
		{"read 500", func(_ *fakeMinter, s *fakeStore) {
			s.readErr = &openbao.StatusError{Op: "read", Code: http.StatusInternalServerError}
		}, codes.Unavailable},
		{"read 405", func(_ *fakeMinter, s *fakeStore) {
			s.readErr = &openbao.StatusError{Op: "read", Code: http.StatusMethodNotAllowed}
		}, codes.Internal},
	} {
		m, s := &fakeMinter{}, newStore()
		tt.setup(m, s)
		_, err := fetch(newServer(t, m, s), alphaURI, alphaID)
		if got := status.Code(err); got != tt.want {
			t.Errorf("%s: code = %v, want %v (err %v)", tt.name, got, tt.want, err)
		}
	}
}

func TestBadRequests(t *testing.T) {
	m, s := &fakeMinter{}, newStore()
	srv := newServer(t, m, s)
	if _, err := fetch(srv, "ate-secret://k8s.io/default/ns/secret/key", alphaID); status.Code(err) != codes.InvalidArgument {
		t.Errorf("other provider's URI: err = %v, want InvalidArgument", err)
	}
	for _, id := range []string{"", "spiffe://cluster.local/ns/x/sa/y", "spiffe://substrate-actor.local/worker-for-actor/team-a/alpha"} {
		if _, err := fetch(srv, alphaURI, id); status.Code(err) != codes.PermissionDenied {
			t.Errorf("actor %q: err = %v, want PermissionDenied", id, err)
		}
	}
	if m.count() != 0 || len(s.reads) != 0 {
		t.Errorf("bad requests reached ateapi or OpenBao: mints=%d reads=%d", m.count(), len(s.reads))
	}
}

func TestConcurrentRequestsShareOneLogin(t *testing.T) {
	m, s := &fakeMinter{block: make(chan struct{})}, newStore()
	srv := newServer(t, m, s)
	const n = 20
	var wg sync.WaitGroup
	var failed atomic.Int32
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := fetch(srv, alphaURI, alphaID); err != nil {
				failed.Add(1)
			}
		}()
	}
	// Let every request reach the shared login before it completes.
	time.Sleep(100 * time.Millisecond)
	close(m.block)
	wg.Wait()
	if failed.Load() != 0 || m.count() != 1 || len(s.logins) != 1 || len(s.reads) != n {
		t.Errorf("failed=%d mints=%d logins=%d reads=%d, want 0, 1, 1, %d", failed.Load(), m.count(), len(s.logins), len(s.reads), n)
	}
}

func TestCallerLeavingDoesNotFailSharedLogin(t *testing.T) {
	m, s := &fakeMinter{block: make(chan struct{})}, newStore()
	srv := newServer(t, m, s)
	leaver, leave := context.WithCancel(context.Background())
	leaverErr := make(chan error, 1)
	go func() {
		_, err := srv.FetchSecret(leaver, &credprovider.FetchSecretRequest{Uri: alphaURI, ActorSpiffeId: alphaID})
		leaverErr <- err
	}()
	stayerResp := make(chan error, 1)
	go func() {
		time.Sleep(20 * time.Millisecond)
		_, err := fetch(srv, alphaURI, alphaID)
		stayerResp <- err
	}()
	time.Sleep(50 * time.Millisecond)
	leave()
	if err := <-leaverErr; status.Code(err) != codes.Unavailable {
		t.Errorf("departed caller: err = %v, want Unavailable", err)
	}
	close(m.block)
	if err := <-stayerResp; err != nil {
		t.Errorf("remaining caller: %v", err)
	}
	if m.count() != 1 {
		t.Errorf("mints = %d, want 1", m.count())
	}
}

func TestFetchTimeout(t *testing.T) {
	m, s := &fakeMinter{}, newStore()
	s.readHook = func(ctx context.Context) error {
		<-ctx.Done()
		return fmt.Errorf("read: %w", ctx.Err())
	}
	cfg := testConfig
	cfg.FetchTimeout = 50 * time.Millisecond
	srv, err := NewServer(cfg, m, s)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	_, err = fetch(srv, alphaURI, alphaID)
	if status.Code(err) != codes.Unavailable {
		t.Errorf("err = %v, want Unavailable", err)
	}
	if d := time.Since(start); d > time.Second {
		t.Errorf("fetch took %v, want about the 50ms timeout", d)
	}
}
