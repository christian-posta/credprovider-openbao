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
	"testing"
	"time"

	"plugins.go.ate.dev/credprovider-openbao/internal/actorid"
)

func TestTokenCacheForgetOnlyMatchingToken(t *testing.T) {
	c := newTokenCache(time.Now)
	a := actorid.Ref{Atespace: "team-a", Name: "alpha"}
	c.put(a, "new", time.Minute)
	c.forget(a, "old")
	if tok, ok := c.get(a); !ok || tok != "new" {
		t.Errorf("get = %q, %v after forgetting a different token; want new, true", tok, ok)
	}
	c.forget(a, "new")
	if _, ok := c.get(a); ok {
		t.Error("token still cached after forget")
	}
}

func TestTokenCacheSweepsExpiredEntries(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	c := newTokenCache(func() time.Time { return now })
	for i := range sweepThreshold {
		c.put(actorid.Ref{Atespace: "a", Name: fmt.Sprintf("n%d", i)}, "t", 3*time.Second)
	}
	now = now.Add(3 * time.Second)
	live := actorid.Ref{Atespace: "a", Name: "live"}
	c.put(live, "t", time.Minute)
	if len(c.entries) != 1 {
		t.Errorf("entries = %d after a sweep, want only the live one", len(c.entries))
	}
}
