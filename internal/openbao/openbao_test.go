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

package openbao

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func newClient(t *testing.T, h http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	c, err := New(Options{Address: srv.URL, AllowInsecureHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestNewValidatesAddress(t *testing.T) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS13}
	for _, tt := range []struct {
		opts Options
		ok   bool
	}{
		{Options{Address: "https://openbao.openbao.svc:8200", TLS: tlsCfg}, true},
		{Options{Address: "https://openbao.openbao.svc:8200/", TLS: tlsCfg}, true},
		{Options{Address: "http://127.0.0.1:8200", AllowInsecureHTTP: true}, true},
		{Options{Address: "http://127.0.0.1:8200"}, false},
		{Options{Address: "https://openbao.openbao.svc:8200"}, false},
		{Options{Address: "https://openbao.openbao.svc:8200/v1", TLS: tlsCfg}, false},
		{Options{Address: "https://user:pw@openbao.openbao.svc", TLS: tlsCfg}, false},
		{Options{Address: "https://openbao.openbao.svc?x=1", TLS: tlsCfg}, false},
		{Options{Address: "ftp://openbao", TLS: tlsCfg}, false},
		{Options{Address: "openbao:8200", TLS: tlsCfg}, false},
	} {
		_, err := New(tt.opts)
		if (err == nil) != tt.ok {
			t.Errorf("New(%+v) error = %v, want ok=%v", tt.opts.Address, err, tt.ok)
		}
	}
}

func TestLoginJWT(t *testing.T) {
	c := newClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/auth/jwt/login" {
			t.Errorf("got %s %s, want POST /v1/auth/jwt/login", r.Method, r.URL.Path)
		}
		if r.Header.Get("X-Vault-Token") != "" {
			t.Error("login sent a token")
		}
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body["role"] != "substrate-actor" || body["jwt"] != "the.actor.jwt" {
			t.Errorf("login body = %v", body)
		}
		_, _ = io.WriteString(w, `{"auth":{"client_token":"s.tok","lease_duration":300}}`)
	})
	tok, err := c.LoginJWT(context.Background(), "jwt", "substrate-actor", "the.actor.jwt")
	if err != nil {
		t.Fatal(err)
	}
	if tok.Value != "s.tok" || tok.TTL != 300*time.Second {
		t.Errorf("token = %+v", tok)
	}
}

func TestLoginJWTErrors(t *testing.T) {
	for _, tt := range []struct {
		status   int
		body     string
		wantCode int
	}{
		{http.StatusBadRequest, `{"errors":["error validating token: invalid audience (aud) claim"]}`, http.StatusBadRequest},
		{http.StatusForbidden, `{"errors":["permission denied"]}`, http.StatusForbidden},
		{http.StatusServiceUnavailable, `{"errors":["Vault is sealed"]}`, http.StatusServiceUnavailable},
		{http.StatusOK, `{"auth":null}`, 0},
		{http.StatusOK, `not json`, 0},
	} {
		c := newClient(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(tt.status)
			_, _ = io.WriteString(w, tt.body)
		})
		_, err := c.LoginJWT(context.Background(), "jwt", "r", "j")
		if err == nil {
			t.Errorf("HTTP %d %s: login succeeded", tt.status, tt.body)
			continue
		}
		if got := StatusCode(err); got != tt.wantCode {
			t.Errorf("HTTP %d %s: StatusCode = %d, want %d (err %v)", tt.status, tt.body, got, tt.wantCode, err)
		}
	}
}

func TestReadKV2(t *testing.T) {
	c := newClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/secret/data/atespaces/team-a/example-api" {
			t.Errorf("got %s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("X-Vault-Token"); got != "s.tok" {
			t.Errorf("token header = %q", got)
		}
		_, _ = io.WriteString(w, `{"data":{"data":{"token":"hunter2","n":1},"metadata":{"version":3}}}`)
	})
	data, err := c.ReadKV2(context.Background(), "s.tok", "secret", []string{"atespaces", "team-a", "example-api"})
	if err != nil {
		t.Fatal(err)
	}
	if data["token"] != "hunter2" {
		t.Errorf("data = %v", data)
	}
}

func TestReadKV2Errors(t *testing.T) {
	for _, tt := range []struct {
		status   int
		body     string
		wantCode int
	}{
		{http.StatusForbidden, `{"errors":["1 error occurred:\n\t* permission denied\n\n"]}`, http.StatusForbidden},
		{http.StatusNotFound, `{"errors":[]}`, http.StatusNotFound},
		// A deleted version: 200 with null data in some versions.
		{http.StatusOK, `{"data":{"data":null,"metadata":{"deletion_time":"2026-11-01T00:00:00Z"}}}`, http.StatusNotFound},
		{http.StatusInternalServerError, ``, http.StatusInternalServerError},
	} {
		c := newClient(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(tt.status)
			_, _ = io.WriteString(w, tt.body)
		})
		_, err := c.ReadKV2(context.Background(), "t", "secret", []string{"p"})
		if got := StatusCode(err); got != tt.wantCode {
			t.Errorf("HTTP %d %q: StatusCode = %d, want %d (err %v)", tt.status, tt.body, got, tt.wantCode, err)
		}
	}
}

func TestDecodeErrorDoesNotQuoteBody(t *testing.T) {
	c := newClient(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"data":{"data":"hunter2-not-an-object"}}`)
	})
	_, err := c.ReadKV2(context.Background(), "t", "secret", []string{"p"})
	if err == nil || strings.Contains(err.Error(), "hunter2") {
		t.Errorf("err = %v, want a decode error that does not quote the body", err)
	}
}

func TestDoesNotFollowRedirects(t *testing.T) {
	leaked := make(chan string, 1)
	elsewhere := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		leaked <- r.Header.Get("X-Vault-Token")
	}))
	defer elsewhere.Close()
	c := newClient(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL+"/steal", http.StatusTemporaryRedirect)
	})
	if _, err := c.ReadKV2(context.Background(), "s.tok", "secret", []string{"p"}); StatusCode(err) != http.StatusTemporaryRedirect {
		t.Errorf("err = %v, want the redirect reported as a status error", err)
	}
	select {
	case tok := <-leaked:
		t.Errorf("redirect target received token %q", tok)
	default:
	}
}

func TestContextTimeout(t *testing.T) {
	c := newClient(t, func(_ http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	})
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := c.ReadKV2(ctx, "t", "secret", []string{"p"}); err == nil || StatusCode(err) != 0 {
		t.Errorf("err = %v, want a transport error", err)
	}
}
