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
	"reflect"
	"strings"
	"testing"
)

func TestParseURI(t *testing.T) {
	tests := []struct {
		uri     string
		want    secretRef
		wantErr bool
	}{
		{
			uri:  "ate-secret://openbao/kv/secret/atespaces/team-a/example-api/token",
			want: secretRef{Mount: "secret", Path: []string{"atespaces", "team-a", "example-api"}, Field: "token"},
		},
		{
			uri:  "ate-secret://openbao/kv/kv-v2/api/key",
			want: secretRef{Mount: "kv-v2", Path: []string{"api"}, Field: "key"},
		},
		{
			uri:  "ate-secret://openbao/kv/m/a.b_c-D/f.1",
			want: secretRef{Mount: "m", Path: []string{"a.b_c-D"}, Field: "f.1"},
		},
		{uri: "ate-secret://openbao/kv/secret/token", wantErr: true},         // no path
		{uri: "ate-secret://openbao/kv/secret", wantErr: true},               // no path or field
		{uri: "ate-secret://openbao/dyn/aws/creds/role/key", wantErr: true},  // unsupported engine
		{uri: "ate-secret://k8s.io/kv/secret/p/f", wantErr: true},            // other provider
		{uri: "https://openbao/kv/secret/p/f", wantErr: true},                // scheme
		{uri: "ate-secret://openbao/kv/secret/../p/f", wantErr: true},        // traversal
		{uri: "ate-secret://openbao/kv/secret/./p/f", wantErr: true},         // dot segment
		{uri: "ate-secret://openbao/kv/secret//p/f", wantErr: true},          // empty segment
		{uri: "ate-secret://openbao/kv/secret/p/f/", wantErr: true},          // trailing slash
		{uri: "ate-secret://openbao/kv/secret/p%2Fq/f", wantErr: true},       // percent-encoding
		{uri: "ate-secret://openbao/kv/secret/p q/f", wantErr: true},         // space
		{uri: "ate-secret://openbao/kv/secret/p/f?version=1", wantErr: true}, // query
		{uri: "ate-secret://openbao/kv/secret/p/f?", wantErr: true},          // empty query
		{uri: "ate-secret://openbao/kv/secret/p/f#x", wantErr: true},         // fragment
		{uri: "ate-secret://u@openbao/kv/secret/p/f", wantErr: true},         // userinfo
		{uri: "ate-secret://openbao/kv/secret/p/" + strings.Repeat("f", 256), wantErr: true},
		{uri: "", wantErr: true},
	}
	for _, tt := range tests {
		got, err := parseURI(tt.uri, "openbao")
		if tt.wantErr {
			if err == nil {
				t.Errorf("parseURI(%q) = %+v, want error", tt.uri, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseURI(%q) error: %v", tt.uri, err)
			continue
		}
		if !reflect.DeepEqual(got, tt.want) {
			t.Errorf("parseURI(%q) = %+v, want %+v", tt.uri, got, tt.want)
		}
	}
}
