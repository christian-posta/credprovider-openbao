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
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// uriScheme is the only scheme a credential URI may carry.
const uriScheme = "ate-secret"

// kvEngine is the leading path segment selecting a KV version 2 read. Other
// secrets engines can be added under their own leading segment.
const kvEngine = "kv"

// segment is the character set a mount, path segment or field may use. It
// leaves out everything that would need percent-encoding in an OpenBao path.
var segment = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,255}$`)

// secretRef is a parsed credential URI:
//
//	ate-secret://<provider>/kv/<mount>/<path>.../<field>
//
// It names the string value of field in the latest version of the KV version
// 2 secret at path in the engine mounted at mount.
type secretRef struct {
	Mount string
	Path  []string
	Field string
}

func (r secretRef) String() string {
	return r.Mount + "/" + strings.Join(r.Path, "/") + "#" + r.Field
}

// parseURI parses a credential URI for provider, rejecting any other scheme or
// provider and any malformed path.
func parseURI(raw, provider string) (secretRef, error) {
	const want = "ate-secret://<provider>/kv/<mount>/<path>.../<field>"
	u, err := url.Parse(raw)
	if err != nil {
		return secretRef{}, fmt.Errorf("parsing credential URI %q: %w", raw, err)
	}
	if u.Scheme != uriScheme {
		return secretRef{}, fmt.Errorf("malformed credential URI %q: scheme is %q, want %q", raw, u.Scheme, uriScheme)
	}
	if u.Host != provider {
		return secretRef{}, fmt.Errorf("credential URI %q: provider is %q, this provider serves %q", raw, u.Host, provider)
	}
	// Reject, rather than ignore, components the grammar does not define.
	if u.User != nil {
		return secretRef{}, fmt.Errorf("credential URI %q: user information is not allowed", raw)
	}
	if u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return secretRef{}, fmt.Errorf("credential URI %q: query and fragment components are not allowed", raw)
	}
	if u.EscapedPath() != u.Path {
		return secretRef{}, fmt.Errorf("credential URI %q: path must not contain percent-encoding", raw)
	}
	// Split without trimming, so an extra slash becomes an empty segment.
	if !strings.HasPrefix(u.Path, "/") {
		return secretRef{}, fmt.Errorf("credential URI %q: want %s", raw, want)
	}
	segments := strings.Split(u.Path[1:], "/")
	for i, s := range segments {
		if s == "." || s == ".." || !segment.MatchString(s) {
			return secretRef{}, fmt.Errorf("credential URI %q: path segment %d (%q) must be 1-255 letters, digits, '_', '-' or '.', and not a dot segment", raw, i, s)
		}
	}
	if len(segments) < 4 || segments[0] != kvEngine {
		return secretRef{}, fmt.Errorf("credential URI %q: want %s", raw, want)
	}
	n := len(segments)
	return secretRef{
		Mount: segments[1],
		Path:  segments[2 : n-1],
		Field: segments[n-1],
	}, nil
}
