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

// Command openbao-credential-provider serves substrate's CredentialProvider
// gRPC API from OpenBao. The egress gateway calls it to resolve ate-secret://
// URIs for credential injection. For each actor it mints a substrate actor JWT
// and logs in to OpenBao as that actor, so OpenBao's policies decide what the
// actor may read.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"runtime/debug"
	"sync/atomic"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"go.ate.dev/substrate/api/ateapi/v1"
	"go.ate.dev/substrate/api/credprovider/v1"

	"plugins.go.ate.dev/credprovider-openbao/internal/mtls"
	"plugins.go.ate.dev/credprovider-openbao/internal/openbao"
	"plugins.go.ate.dev/credprovider-openbao/internal/provider"
	"plugins.go.ate.dev/credprovider-openbao/internal/tlsclient"
)

// version is set at build time with -ldflags "-X main.version=v0.1.0".
var version string

// config is the parsed command line.
type config struct {
	listenAddr string
	healthAddr string
	logLevel   string
	drainGrace time.Duration

	serverBundle     string
	clientCAFile     string
	injectorIdentity string

	ateapiAddr       string
	ateapiCAFile     string
	ateapiClientCert string
	ateapiServerName string

	openbaoAddr              string
	openbaoCAFile            string
	openbaoAllowInsecureHTTP bool

	provider provider.Config
}

func parseFlags(fs *flag.FlagSet, args []string) (config, error) {
	var c config
	fs.StringVar(&c.listenAddr, "listen-address", ":50051", "gRPC listen address")
	fs.StringVar(&c.healthAddr, "health-address", ":9090", "HTTP listen address for /healthz and /readyz")
	fs.StringVar(&c.logLevel, "log-level", "info", "one of debug, info, warn, error")
	fs.DurationVar(&c.drainGrace, "drain-grace", 5*time.Second, "how long to wait for in-flight RPCs on shutdown before a hard stop")

	fs.StringVar(&c.serverBundle, "server-cred-bundle", "", "credential bundle (PKCS#8 key and certificate chain) presented for serving TLS (required)")
	fs.StringVar(&c.clientCAFile, "client-ca-file", "", "trust bundle the caller's client certificate must chain to (required)")
	// No default: the gateway's namespace and ServiceAccount are known only to
	// the deployment.
	fs.StringVar(&c.injectorIdentity, "injector-identity", "", "SPIFFE ID the caller's client certificate must carry: substrate's egress gateway, e.g. spiffe://cluster.local/ns/ate-system/sa/atenet-egress (required)")

	fs.StringVar(&c.ateapiAddr, "ateapi-address", "dns:///api.ate-system.svc:443", "gRPC target of substrate's ateapi, which mints actor JWTs")
	fs.StringVar(&c.ateapiCAFile, "ateapi-ca-file", "", "trust bundle ateapi's serving certificate must chain to (required)")
	fs.StringVar(&c.ateapiClientCert, "ateapi-client-cert", "", "credential bundle presented to ateapi; its SPIFFE ID must hold substrate's egress_gateway role (required)")
	fs.StringVar(&c.ateapiServerName, "ateapi-server-name", "api.ate-system.svc", "DNS name ateapi's serving certificate must carry")

	fs.StringVar(&c.openbaoAddr, "openbao-address", "", "OpenBao base URL, e.g. https://openbao.openbao.svc:8200 (required)")
	fs.StringVar(&c.openbaoCAFile, "openbao-ca-file", "", "trust bundle OpenBao's serving certificate must chain to (required for https)")
	fs.BoolVar(&c.openbaoAllowInsecureHTTP, "openbao-allow-insecure-http", false, "allow a plain http --openbao-address; actor tokens and secrets then cross the network in cleartext (local development only)")

	fs.StringVar(&c.provider.ProviderName, "provider-name", "openbao", "ate-secret:// URI host this provider serves; must match the name substrate's --credential-provider gives it")
	fs.StringVar(&c.provider.JWTMount, "openbao-jwt-mount", "jwt", "path the OpenBao JWT auth method is mounted at")
	fs.StringVar(&c.provider.Role, "openbao-role", "substrate-actor", "OpenBao JWT auth role actors log in as")
	fs.StringVar(&c.provider.Audience, "actor-jwt-audience", "openbao", "audience of the minted actor JWTs; the OpenBao role must bind it")
	fs.DurationVar(&c.provider.JWTLifetime, "actor-jwt-lifetime", 300*time.Second, "lifetime of the minted actor JWTs, 300s to 3600s; each is used once, to log in")
	// The egress gateway allows a provider about four seconds.
	fs.DurationVar(&c.provider.FetchTimeout, "fetch-timeout", 3*time.Second, "how long one FetchSecret may take, including any ateapi mint and OpenBao login; keep it under the egress gateway's provider timeout")

	if err := fs.Parse(args); err != nil {
		return config{}, err
	}
	return c, c.validate()
}

func (c config) validate() error {
	for _, f := range []struct{ name, value string }{
		{"--server-cred-bundle", c.serverBundle},
		{"--client-ca-file", c.clientCAFile},
		{"--injector-identity", c.injectorIdentity},
		{"--ateapi-ca-file", c.ateapiCAFile},
		{"--ateapi-client-cert", c.ateapiClientCert},
		{"--ateapi-server-name", c.ateapiServerName},
		{"--openbao-address", c.openbaoAddr},
	} {
		if f.value == "" {
			return fmt.Errorf("%s is required", f.name)
		}
	}
	return nil
}

func main() {
	cfg, err := parseFlags(flag.CommandLine, os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	var level slog.Level
	if err := level.UnmarshalText([]byte(cfg.logLevel)); err != nil {
		fmt.Fprintf(os.Stderr, "invalid --log-level %q: %v\n", cfg.logLevel, err)
		os.Exit(2)
	}
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: level})))

	slog.Info("starting openbao-credential-provider", slog.String("version", buildVersion()))
	if err := run(context.Background(), cfg); err != nil {
		slog.Error("openbao-credential-provider exited with error", slog.Any("err", err))
		os.Exit(1)
	}
}

// newServer builds the gRPC server and the ateapi connection it mints through.
// The caller closes the connection.
func newServer(cfg config) (*grpc.Server, *grpc.ClientConn, error) {
	creds, err := mtls.ServerCredentials(mtls.Config{
		ServerBundle:   cfg.serverBundle,
		ClientCAFile:   cfg.clientCAFile,
		CallerIdentity: cfg.injectorIdentity,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("server credentials: %w", err)
	}

	ateapiTLS, err := tlsclient.New(tlsclient.Config{
		CAFile:           cfg.ateapiCAFile,
		ServerName:       cfg.ateapiServerName,
		ClientCredBundle: cfg.ateapiClientCert,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("ateapi client TLS: %w", err)
	}
	conn, err := grpc.NewClient(cfg.ateapiAddr,
		grpc.WithTransportCredentials(credentials.NewTLS(ateapiTLS)),
		// Spread mints across every ateapi replica the resolver returns.
		grpc.WithDefaultServiceConfig(`{"loadBalancingConfig": [{"round_robin":{}}]}`),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("ateapi client: %w", err)
	}

	store, err := newOpenBaoClient(cfg)
	if err != nil {
		conn.Close()
		return nil, nil, err
	}
	p, err := provider.NewServer(cfg.provider, ateapi.NewControlClient(conn), store)
	if err != nil {
		conn.Close()
		return nil, nil, err
	}
	srv := grpc.NewServer(grpc.Creds(creds))
	credprovider.RegisterCredentialProviderServer(srv, p)
	return srv, conn, nil
}

func newOpenBaoClient(cfg config) (*openbao.Client, error) {
	opts := openbao.Options{Address: cfg.openbaoAddr, AllowInsecureHTTP: cfg.openbaoAllowInsecureHTTP}
	u, err := url.Parse(cfg.openbaoAddr)
	if err != nil {
		return nil, fmt.Errorf("parsing --openbao-address: %w", err)
	}
	if u.Scheme == "https" && cfg.openbaoCAFile == "" {
		return nil, errors.New("--openbao-ca-file is required for an https --openbao-address")
	}
	if cfg.openbaoCAFile != "" {
		opts.TLS, err = tlsclient.New(tlsclient.Config{CAFile: cfg.openbaoCAFile, ServerName: u.Hostname()})
		if err != nil {
			return nil, fmt.Errorf("OpenBao client TLS: %w", err)
		}
	}
	c, err := openbao.New(opts)
	if err != nil {
		return nil, fmt.Errorf("OpenBao client: %w", err)
	}
	return c, nil
}

func run(ctx context.Context, cfg config) error {
	srv, conn, err := newServer(cfg)
	if err != nil {
		return err
	}
	defer conn.Close()
	slog.Info("admitting callers", slog.String("client_ca", cfg.clientCAFile), slog.String("required_san", cfg.injectorIdentity))
	slog.Info("resolving secrets from OpenBao", slog.String("address", cfg.openbaoAddr),
		slog.String("jwt_mount", cfg.provider.JWTMount), slog.String("role", cfg.provider.Role),
		slog.String("ateapi", cfg.ateapiAddr))

	grpcLis, err := (&net.ListenConfig{}).Listen(ctx, "tcp", cfg.listenAddr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", cfg.listenAddr, err)
	}
	healthLis, err := (&net.ListenConfig{}).Listen(ctx, "tcp", cfg.healthAddr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", cfg.healthAddr, err)
	}
	var ready atomic.Bool
	healthSrv := &http.Server{Handler: healthHandler(&ready), ReadHeaderTimeout: 10 * time.Second}
	healthDone := make(chan error, 1)
	go func() { healthDone <- healthSrv.Serve(healthLis) }()

	shutdownCtx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	shutdownErr := make(chan error, 1)
	go func() {
		var err error
		select {
		case <-shutdownCtx.Done():
			slog.Info("shutting down")
		case err = <-healthDone:
			err = fmt.Errorf("health server: %w", err)
		}
		ready.Store(false)
		gracefulStop(srv, cfg.drainGrace)
		_ = healthSrv.Close()
		shutdownErr <- err
	}()

	ready.Store(true)
	slog.Info("openbao-credential-provider listening", slog.String("address", grpcLis.Addr().String()), slog.String("health_address", healthLis.Addr().String()))
	// ErrServerStopped means shutdown began before Serve started: not a failure.
	if err := srv.Serve(grpcLis); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
		return fmt.Errorf("serving: %w", err)
	}
	return <-shutdownErr
}

// gracefulStop lets in-flight RPCs finish for up to grace, then forces the
// server down.
func gracefulStop(srv *grpc.Server, grace time.Duration) {
	done := make(chan struct{})
	go func() {
		srv.GracefulStop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(grace):
		slog.Warn("graceful shutdown timed out; forcing stop", slog.Duration("grace", grace))
		srv.Stop()
	}
}

// healthHandler serves /healthz, which always succeeds so a draining pod is not
// restarted, and /readyz, which succeeds only while ready is set.
func healthHandler(ready *atomic.Bool) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		if !ready.Load() {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("ok"))
	})
	return mux
}

// buildVersion returns the release or module version, else "dev", plus the VCS
// revision when the build recorded one.
func buildVersion() string {
	v := version
	info, ok := debug.ReadBuildInfo()
	if !ok {
		if v == "" {
			return "dev"
		}
		return v
	}
	if v == "" && info.Main.Version != "" && info.Main.Version != "(devel)" {
		v = info.Main.Version
	}
	if v == "" {
		v = "dev"
	}
	var revision, modified string
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			revision = s.Value
		case "vcs.modified":
			modified = s.Value
		}
	}
	if revision == "" {
		return v
	}
	if modified == "true" {
		revision += "-dirty"
	}
	return v + " commit=" + revision
}
