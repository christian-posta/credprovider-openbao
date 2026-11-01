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

// Package actorid parses the actor SPIFFE ID the egress gateway asserts on
// each FetchSecret request.
package actorid

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// TrustDomain is the SPIFFE trust domain of actor IDs.
const TrustDomain = "substrate-actor.local"

const format = "spiffe://" + TrustDomain + "/actor/<atespace>/<name>"

// dns1123Label is the rule substrate applies to atespace and actor names.
var dns1123Label = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)

// Ref names one actor.
type Ref struct {
	Atespace string
	Name     string
}

// String returns the actor as <atespace>/<name>.
func (r Ref) String() string { return r.Atespace + "/" + r.Name }

// Parse parses spiffe://substrate-actor.local/actor/<atespace>/<name>. It
// follows substrate's internal/resources.ActorRefFromActorSPIFFEURL, which
// this module cannot import.
func Parse(id string) (Ref, error) {
	u, err := url.Parse(id)
	if err != nil {
		return Ref{}, fmt.Errorf("invalid actor SPIFFE ID %q: %w", id, err)
	}
	if u.Scheme != "spiffe" || u.Host != TrustDomain || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return Ref{}, fmt.Errorf("%q does not have format %s", id, format)
	}
	segments := strings.Split(strings.TrimPrefix(u.Path, "/"), "/")
	if len(segments) != 3 || segments[0] != "actor" {
		return Ref{}, fmt.Errorf("%q does not have format %s", id, format)
	}
	atespace, name := segments[1], segments[2]
	if !dns1123Label.MatchString(atespace) {
		return Ref{}, fmt.Errorf("%q is not a valid atespace", atespace)
	}
	if !dns1123Label.MatchString(name) {
		return Ref{}, fmt.Errorf("%q is not a valid actor name", name)
	}
	return Ref{Atespace: atespace, Name: name}, nil
}
