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

// Command probe is the actor the end-to-end test runs. POST / with
// {"url": "...", "headers": {"Name": "value"}} makes one GET of url carrying
// those headers and answers {"statusCode": ..., "body": "..."}. The egress
// gateway replaces only a header the request already carries, so the test
// sends a placeholder for the header it expects to be injected.
package main

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"time"
)

type request struct {
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers,omitempty"`
}

type response struct {
	StatusCode int    `json:"statusCode,omitempty"`
	Body       string `json:"body,omitempty"`
	Error      string `json:"error,omitempty"`
}

func main() {
	client := &http.Client{
		Timeout: 15 * time.Second,
		// Egress is intercepted transparently; never use a proxy from the
		// environment.
		Transport: &http.Transport{Proxy: nil},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	})
	mux.HandleFunc("POST /", func(w http.ResponseWriter, r *http.Request) {
		var req request
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil || req.URL == "" {
			http.Error(w, `want {"url": "...", "headers": {...}}`, http.StatusBadRequest)
			return
		}
		out := fetch(client, r, req)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	})
	slog.Info("probe listening", "address", ":80")
	srv := &http.Server{Addr: ":80", Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	if err := srv.ListenAndServe(); err != nil {
		slog.Error("probe exited", "err", err)
	}
}

func fetch(client *http.Client, in *http.Request, req request) response {
	out, err := http.NewRequestWithContext(in.Context(), http.MethodGet, req.URL, nil)
	if err != nil {
		return response{Error: err.Error()}
	}
	for k, v := range req.Headers {
		out.Header.Set(k, v)
	}
	resp, err := client.Do(out)
	if err != nil {
		return response{Error: err.Error()}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	return response{StatusCode: resp.StatusCode, Body: string(body)}
}
