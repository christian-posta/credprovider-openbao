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

package actorid

import (
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	tests := []struct {
		id      string
		want    Ref
		wantErr bool
	}{
		{id: "spiffe://substrate-actor.local/actor/team-a/alpha", want: Ref{Atespace: "team-a", Name: "alpha"}},
		{id: "spiffe://substrate-actor.local/actor/a/" + strings.Repeat("b", 63), want: Ref{Atespace: "a", Name: strings.Repeat("b", 63)}},
		{id: "", wantErr: true},
		{id: "spiffe://cluster.local/actor/team-a/alpha", wantErr: true},
		{id: "https://substrate-actor.local/actor/team-a/alpha", wantErr: true},
		{id: "spiffe://substrate-actor.local/worker-for-actor/team-a/alpha", wantErr: true},
		{id: "spiffe://substrate-actor.local/actor/team-a", wantErr: true},
		{id: "spiffe://substrate-actor.local/actor/team-a/alpha/extra", wantErr: true},
		{id: "spiffe://substrate-actor.local/actor/Team-A/alpha", wantErr: true},
		{id: "spiffe://substrate-actor.local/actor/team-a/..", wantErr: true},
		{id: "spiffe://substrate-actor.local/actor/team-a/" + strings.Repeat("b", 64), wantErr: true},
		{id: "spiffe://substrate-actor.local/actor/team-a/alpha?x=1", wantErr: true},
		{id: "spiffe://substrate-actor.local/actor/team-a/alpha?", wantErr: true},
		{id: "spiffe://substrate-actor.local/actor/team-a/alpha#frag", wantErr: true},
		{id: "spiffe://user@substrate-actor.local/actor/team-a/alpha", wantErr: true},
	}
	for _, tt := range tests {
		got, err := Parse(tt.id)
		if tt.wantErr {
			if err == nil {
				t.Errorf("Parse(%q) = %+v, want error", tt.id, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("Parse(%q) error: %v", tt.id, err)
			continue
		}
		if got != tt.want {
			t.Errorf("Parse(%q) = %+v, want %+v", tt.id, got, tt.want)
		}
	}
}
