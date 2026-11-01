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

// Package provider implements substrate's CredentialProvider API over OpenBao.
// For each actor it mints a substrate actor JWT, logs in to OpenBao's JWT auth
// method with it, and reads the secret with the actor's own OpenBao token, so
// OpenBao's policies decide what each actor may read and its audit log names
// the actor.
package provider

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"golang.org/x/sync/singleflight"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"go.ate.dev/substrate/api/ateapi/v1"
	"go.ate.dev/substrate/api/credprovider/v1"

	"plugins.go.ate.dev/credprovider-openbao/internal/actorid"
	"plugins.go.ate.dev/credprovider-openbao/internal/openbao"
)

// Minter mints actor JWTs. ateapi.ControlClient satisfies it.
type Minter interface {
	MintActorJwt(ctx context.Context, in *ateapi.MintActorJwtRequest, opts ...grpc.CallOption) (*ateapi.MintActorJwtResponse, error)
}

// Store is the OpenBao API the server uses. *openbao.Client satisfies it.
type Store interface {
	LoginJWT(ctx context.Context, mount, role, jwt string) (openbao.Token, error)
	ReadKV2(ctx context.Context, token, mount string, path []string) (map[string]any, error)
}

// Config configures a Server.
type Config struct {
	// ProviderName is the ate-secret:// URI host this provider serves.
	ProviderName string
	// JWTMount is the path the OpenBao JWT auth method is mounted at.
	JWTMount string
	// Role is the OpenBao JWT auth role actors log in as.
	Role string
	// Audience is the audience of the minted actor JWTs. The role must bind it.
	Audience string
	// JWTLifetime is the lifetime of the minted actor JWTs, 300s to 3600s.
	// Only the login uses one, so the minimum serves.
	JWTLifetime time.Duration
	// FetchTimeout bounds each FetchSecret, which must answer within the
	// egress gateway's provider budget.
	FetchTimeout time.Duration
}

func (c Config) validate() error {
	switch {
	case c.ProviderName == "":
		return errors.New("a provider name is required")
	case c.JWTMount == "":
		return errors.New("an OpenBao JWT auth mount is required")
	case c.Role == "":
		return errors.New("an OpenBao JWT auth role is required")
	case c.Audience == "":
		return errors.New("an actor JWT audience is required")
	case c.JWTLifetime < 300*time.Second || c.JWTLifetime > 3600*time.Second || c.JWTLifetime%time.Second != 0:
		return fmt.Errorf("the actor JWT lifetime must be whole seconds from 300s to 3600s, got %v", c.JWTLifetime)
	case c.FetchTimeout <= 0:
		return fmt.Errorf("the fetch timeout must be positive, got %v", c.FetchTimeout)
	}
	return nil
}

// errDenied marks a failure the caller must not be able to tell apart from
// any other denial. FetchSecret turns it into one PermissionDenied message.
var errDenied = errors.New("denied")

// Server implements credprovider.CredentialProviderServer over OpenBao.
type Server struct {
	credprovider.UnimplementedCredentialProviderServer
	cfg     Config
	minter  Minter
	store   Store
	tokens  *tokenCache
	flights singleflight.Group
}

// NewServer returns a Server that mints actor JWTs with minter and reads
// secrets from store.
func NewServer(cfg Config, minter Minter, store Store) (*Server, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &Server{cfg: cfg, minter: minter, store: store, tokens: newTokenCache(time.Now)}, nil
}

// FetchSecret resolves a credential URI to the string value of its field,
// read with the asserted actor's own OpenBao token.
func (s *Server) FetchSecret(ctx context.Context, req *credprovider.FetchSecretRequest) (*credprovider.FetchSecretResponse, error) {
	ref, err := parseURI(req.GetUri(), s.cfg.ProviderName)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	actor, err := actorid.Parse(req.GetActorSpiffeId())
	if err != nil {
		slog.WarnContext(ctx, "credential request denied: unusable actor identity", slog.Any("err", err))
		return nil, status.Errorf(codes.PermissionDenied, "actor identity is required and must be a valid actor SPIFFE URI: %v", err)
	}
	slog.InfoContext(ctx, "resolving credential",
		slog.String("actor", actor.String()),
		slog.String("mount", ref.Mount),
		slog.String("secret", ref.String()),
	)
	ctx, cancel := context.WithTimeout(ctx, s.cfg.FetchTimeout)
	defer cancel()

	value, err := s.fetch(ctx, actor, ref)
	if errors.Is(err, errDenied) {
		// One message for a refused, missing or malformed secret, so an actor
		// cannot probe what exists outside what it may read.
		return nil, status.Errorf(codes.PermissionDenied, "actor %s is not permitted to read %s", actor, ref)
	}
	if err != nil {
		return nil, err
	}
	return &credprovider.FetchSecretResponse{OpaqueBytes: value}, nil
}

func (s *Server) fetch(ctx context.Context, actor actorid.Ref, ref secretRef) ([]byte, error) {
	token, fresh, err := s.token(ctx, actor)
	if err != nil {
		return nil, err
	}
	data, err := s.store.ReadKV2(ctx, token, ref.Mount, ref.Path)
	if !fresh && openbao.StatusCode(err) == http.StatusForbidden {
		// A cached token can be revoked or expire early. Log in once more; a
		// fresh token that is refused too is a real denial.
		s.tokens.forget(actor, token)
		if token, _, err = s.token(ctx, actor); err != nil {
			return nil, err
		}
		data, err = s.store.ReadKV2(ctx, token, ref.Mount, ref.Path)
	}
	if err != nil {
		return nil, s.readError(ctx, actor, ref, err)
	}
	value, ok := data[ref.Field].(string)
	if !ok {
		slog.WarnContext(ctx, "credential request denied: field missing or not a string",
			slog.String("actor", actor.String()), slog.String("secret", ref.String()))
		return nil, errDenied
	}
	return []byte(value), nil
}

// token returns an OpenBao token for the actor, and whether it was just issued
// rather than taken from the cache. Concurrent requests for one actor share a
// single login.
func (s *Server) token(ctx context.Context, actor actorid.Ref) (string, bool, error) {
	if tok, ok := s.tokens.get(actor); ok {
		return tok, false, nil
	}
	ch := s.flights.DoChan(actor.String(), func() (any, error) {
		if tok, ok := s.tokens.get(actor); ok {
			return tok, nil
		}
		// Other requests may be waiting on this login, so one caller going
		// away must not cancel it.
		lctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), s.cfg.FetchTimeout)
		defer cancel()
		return s.login(lctx, actor)
	})
	select {
	case <-ctx.Done():
		return "", false, status.Errorf(codes.Unavailable, "logging in to OpenBao as actor %s: %v", actor, ctx.Err())
	case r := <-ch:
		if r.Err != nil {
			return "", false, r.Err
		}
		return r.Val.(string), true, nil
	}
}

// login mints an actor JWT and exchanges it for an OpenBao token, which it
// caches.
func (s *Server) login(ctx context.Context, actor actorid.Ref) (string, error) {
	resp, err := s.minter.MintActorJwt(ctx, &ateapi.MintActorJwtRequest{
		Actor:             &ateapi.ObjectRef{Atespace: actor.Atespace, Name: actor.Name},
		Audiences:         []string{s.cfg.Audience},
		ExpirationSeconds: int64(s.cfg.JWTLifetime / time.Second),
	})
	if err != nil {
		return "", s.mintError(ctx, actor, err)
	}
	tok, err := s.store.LoginJWT(ctx, s.cfg.JWTMount, s.cfg.Role, resp.GetActorJwt())
	if err != nil {
		return "", s.loginError(ctx, actor, err)
	}
	s.tokens.put(actor, tok.Value, tok.TTL)
	return tok.Value, nil
}

// The error mappings below target the egress gateway, which answers
// Unavailable and DeadlineExceeded with a retryable 503 and anything else with
// a 403 or 500.

func (s *Server) mintError(ctx context.Context, actor actorid.Ref, err error) error {
	switch code := status.Code(err); {
	case code == codes.NotFound:
		slog.WarnContext(ctx, "credential request denied: actor not found", slog.String("actor", actor.String()))
		return errDenied
	case code == codes.PermissionDenied || code == codes.Unauthenticated:
		slog.ErrorContext(ctx, "this provider may not mint actor JWTs; add its SPIFFE ID to ATE_EGRESS_GATEWAY_EXTRA_SPIFFE_IDS when installing substrate",
			slog.String("actor", actor.String()), slog.Any("err", err))
		return status.Error(codes.Internal, "credential provider is not authorized to mint actor JWTs")
	case code == codes.Unavailable || code == codes.DeadlineExceeded || code == codes.Canceled || ctx.Err() != nil:
		return status.Errorf(codes.Unavailable, "minting an actor JWT for %s: %v", actor, err)
	default:
		slog.ErrorContext(ctx, "minting an actor JWT failed", slog.String("actor", actor.String()), slog.Any("err", err))
		return status.Errorf(codes.Internal, "minting an actor JWT for %s failed", actor)
	}
}

func (s *Server) loginError(ctx context.Context, actor actorid.Ref, err error) error {
	switch code := openbao.StatusCode(err); {
	case code == http.StatusBadRequest || code == http.StatusForbidden:
		// OpenBao refused the actor's JWT, e.g. a role binding it does not meet.
		slog.WarnContext(ctx, "credential request denied: OpenBao refused the actor's login",
			slog.String("actor", actor.String()), slog.Any("err", err))
		return errDenied
	case transient(code):
		return status.Errorf(codes.Unavailable, "logging in to OpenBao as actor %s: %v", actor, err)
	default:
		slog.ErrorContext(ctx, "OpenBao login failed; check --openbao-jwt-mount and --openbao-role",
			slog.String("actor", actor.String()), slog.Any("err", err))
		return status.Errorf(codes.Internal, "logging in to OpenBao as actor %s failed", actor)
	}
}

func (s *Server) readError(ctx context.Context, actor actorid.Ref, ref secretRef, err error) error {
	switch code := openbao.StatusCode(err); {
	case code == http.StatusForbidden || code == http.StatusNotFound:
		// OpenBao answers 404 for a missing path the token may read and 403
		// for any path it may not; the caller sees the same denial for both.
		slog.WarnContext(ctx, "credential request denied by OpenBao",
			slog.String("actor", actor.String()), slog.String("secret", ref.String()), slog.Int("http_status", code))
		return errDenied
	case transient(code):
		return status.Errorf(codes.Unavailable, "reading %s from OpenBao: %v", ref, err)
	default:
		slog.ErrorContext(ctx, "OpenBao read failed",
			slog.String("actor", actor.String()), slog.String("secret", ref.String()), slog.Any("err", err))
		return status.Errorf(codes.Internal, "reading %s from OpenBao failed", ref)
	}
}

// transient reports whether an OpenBao call that failed with HTTP status code
// (0 for no response) may succeed on retry.
func transient(code int) bool {
	return code == 0 || code == http.StatusTooManyRequests || code >= 500
}
