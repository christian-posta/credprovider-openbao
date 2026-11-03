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
	"sync"
	"time"
)

// sweepThreshold is the cache size above which an insert first drops expired
// entries, so keys that stop being used do not accumulate.
const sweepThreshold = 1024

// tokenCache holds OpenBao tokens by key until their reuse deadline.
type tokenCache struct {
	now func() time.Time

	mu      sync.Mutex
	entries map[string]cachedToken
}

type cachedToken struct {
	value      string
	reuseUntil time.Time
}

func newTokenCache(now func() time.Time) *tokenCache {
	return &tokenCache{now: now, entries: map[string]cachedToken{}}
}

// get returns key's token if one is cached and still reusable.
func (c *tokenCache) get(key string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	if !ok || !c.now().Before(e.reuseUntil) {
		return "", false
	}
	return e.value, true
}

// put caches token for key until a third of ttl remains, so a cached
// token always has that long left when it is used. A token with no TTL is not
// cached.
func (c *tokenCache) put(key, token string, ttl time.Duration) {
	if ttl <= 0 {
		return
	}
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) >= sweepThreshold {
		for k, e := range c.entries {
			if !now.Before(e.reuseUntil) {
				delete(c.entries, k)
			}
		}
	}
	c.entries[key] = cachedToken{value: token, reuseUntil: now.Add(ttl - ttl/3)}
}

// forget drops key's token if it is still token, so a token found to be
// unusable is not served again while a fresh one may already be cached.
func (c *tokenCache) forget(key, token string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.entries[key]; ok && e.value == token {
		delete(c.entries, key)
	}
}
