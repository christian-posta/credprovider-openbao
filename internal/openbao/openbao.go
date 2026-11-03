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

// Package openbao is a minimal client for the two OpenBao HTTP API calls the
// provider makes: a login to the JWT or Kubernetes auth method and a KV
// version 2 read. It uses net/http
// rather than the OpenBao SDK to keep the dependency tree small.
package openbao

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// maxResponseBytes bounds how much of a response body is read.
const maxResponseBytes = 1 << 20

// ActorHeader carries the actor a read is made for, as actor/<atespace>/<name>.
// OpenBao does not interpret it; an audit device logs it once
// sys/config/auditing/request-headers lists it.
const ActorHeader = "X-Substrate-Actor"

// Options configure a Client.
type Options struct {
	// Address is the OpenBao base URL, e.g. https://openbao.openbao.svc:8200.
	Address string
	// TLS is the client TLS config for an https Address. Required for https.
	TLS *tls.Config
	// AllowInsecureHTTP permits an http Address. Tokens and secrets then cross
	// the network in cleartext, so it is for local development only.
	AllowInsecureHTTP bool
}

// Client calls the OpenBao HTTP API.
type Client struct {
	base *url.URL
	hc   *http.Client
}

// New returns a Client for opts.
func New(opts Options) (*Client, error) {
	u, err := url.Parse(opts.Address)
	if err != nil {
		return nil, fmt.Errorf("parsing OpenBao address %q: %w", opts.Address, err)
	}
	if u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("OpenBao address %q must be scheme://host[:port] with no path, query or credentials", opts.Address)
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	switch u.Scheme {
	case "https":
		if opts.TLS == nil {
			return nil, errors.New("an https OpenBao address requires a TLS config")
		}
		transport.TLSClientConfig = opts.TLS
	case "http":
		if !opts.AllowInsecureHTTP {
			return nil, fmt.Errorf("OpenBao address %q is plain http; allow it explicitly for local development only", opts.Address)
		}
	default:
		return nil, fmt.Errorf("OpenBao address %q must use https", opts.Address)
	}
	// Ignore proxy settings: tokens and secrets must go straight to OpenBao.
	transport.Proxy = nil
	return &Client{
		base: &url.URL{Scheme: u.Scheme, Host: u.Host},
		hc: &http.Client{
			Transport: transport,
			// A redirect could carry the token to another host.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

// StatusError is a non-2xx response from OpenBao.
type StatusError struct {
	// Op names the call, e.g. "login" or "read".
	Op string
	// Code is the HTTP status code.
	Code int
	// Errors are the messages in OpenBao's error response, if any.
	Errors []string
}

func (e *StatusError) Error() string {
	if len(e.Errors) == 0 {
		return fmt.Sprintf("OpenBao %s: HTTP %d", e.Op, e.Code)
	}
	return fmt.Sprintf("OpenBao %s: HTTP %d: %s", e.Op, e.Code, strings.Join(e.Errors, "; "))
}

// StatusCode returns the HTTP status of err if it is a StatusError, else 0.
func StatusCode(err error) int {
	var se *StatusError
	if errors.As(err, &se) {
		return se.Code
	}
	return 0
}

// Token is an OpenBao client token.
type Token struct {
	// Value is the token itself.
	Value string
	// TTL is how long the token is valid from issuance. Zero means OpenBao
	// reported no expiry.
	TTL time.Duration
}

// Login logs in to the auth method mounted at mount as role, presenting jwt,
// and returns the issued token. The JWT and Kubernetes auth methods share this
// request shape.
func (c *Client) Login(ctx context.Context, mount, role, jwt string) (Token, error) {
	body, err := json.Marshal(map[string]string{"role": role, "jwt": jwt})
	if err != nil {
		return Token{}, err
	}
	var resp struct {
		Auth *struct {
			ClientToken   string `json:"client_token"`
			LeaseDuration int64  `json:"lease_duration"`
		} `json:"auth"`
	}
	if err := c.do(ctx, "login", http.MethodPost, c.base.JoinPath("v1", "auth", mount, "login"), "", "", body, &resp); err != nil {
		return Token{}, err
	}
	if resp.Auth == nil || resp.Auth.ClientToken == "" {
		return Token{}, errors.New("OpenBao login: response carries no client token")
	}
	return Token{Value: resp.Auth.ClientToken, TTL: time.Duration(resp.Auth.LeaseDuration) * time.Second}, nil
}

// ReadKV2 reads the latest version of the KV version 2 secret at path in the
// engine mounted at mount for actor, and returns its data. actor is sent in
// ActorHeader.
func (c *Client) ReadKV2(ctx context.Context, token, actor, mount string, path []string) (map[string]any, error) {
	elems := append([]string{"v1", mount, "data"}, path...)
	var resp struct {
		Data *struct {
			Data map[string]any `json:"data"`
		} `json:"data"`
	}
	if err := c.do(ctx, "read", http.MethodGet, c.base.JoinPath(elems...), token, actor, nil, &resp); err != nil {
		return nil, err
	}
	if resp.Data == nil || resp.Data.Data == nil {
		// A deleted or destroyed version reads as null data.
		return nil, &StatusError{Op: "read", Code: http.StatusNotFound}
	}
	return resp.Data.Data, nil
}

func (c *Client) do(ctx context.Context, op, method string, u *url.URL, token, actor string, body []byte, out any) error {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), rd)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("X-Vault-Token", token)
	}
	if actor != "" {
		req.Header.Set(ActorHeader, actor)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("OpenBao %s: %w", op, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return fmt.Errorf("OpenBao %s: reading response: %w", op, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		var e struct {
			Errors []string `json:"errors"`
		}
		_ = json.Unmarshal(data, &e)
		return &StatusError{Op: op, Code: resp.StatusCode, Errors: e.Errors}
	}
	if err := json.Unmarshal(data, out); err != nil {
		// The decoder's message can quote the body, which may hold a secret.
		return fmt.Errorf("OpenBao %s: response is not the expected JSON", op)
	}
	return nil
}
